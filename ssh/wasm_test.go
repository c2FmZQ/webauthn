// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//go:build js && wasm

package ssh

import (
	"bytes"
	"crypto/rand"
	"syscall/js"
	"testing"

	"github.com/c2FmZQ/webauthn"
)

func setupMockWASM(t *testing.T, auth *webauthn.FakeAuthenticator, hostname, origin string) {
	t.Helper()
	global := js.Global()
	objCtor := global.Get("Object")
	arrCtor := global.Get("Array")
	u8Ctor := global.Get("Uint8Array")

	newObj := func(m map[string]any) js.Value {
		o := objCtor.New()
		for k, v := range m {
			o.Set(k, v)
		}
		return o
	}
	toJSBytes := func(b []byte) js.Value {
		u := u8Ctor.New(len(b))
		js.CopyBytesToJS(u, b)
		return u
	}
	fromJSBytes := func(v js.Value) []byte {
		b := make([]byte, v.Length())
		js.CopyBytesToGo(b, v)
		return b
	}

	origDoc := global.Get("document")
	origNav := global.Get("navigator")

	setGlobal := func(name string, val js.Value) {
		objCtor.Call("defineProperty", global, name, newObj(map[string]any{
			"value":        val,
			"configurable": true,
			"writable":     true,
		}))
	}

	setGlobal("document", newObj(map[string]any{
		"location": newObj(map[string]any{
			"hostname": hostname,
			"origin":   origin,
		}),
	}))

	createFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		promiseCtor := global.Get("Promise")
		var execFn js.Func
		execFn = js.FuncOf(func(this js.Value, pArgs []js.Value) any {
			defer execFn.Release()
			resolve := pArgs[0]
			reject := pArgs[1]
			pk := args[0].Get("publicKey")
			ao := &webauthn.AttestationOptions{
				Challenge:   fromJSBytes(pk.Get("challenge")),
				Attestation: pk.Get("attestation").String(),
			}
			rp := pk.Get("rp")
			ao.RelyingParty.Name = rp.Get("name").String()
			ao.RelyingParty.ID = ao.RelyingParty.Name
			user := pk.Get("user")
			ao.User.ID = fromJSBytes(user.Get("id"))
			ao.User.Name = user.Get("name").String()
			ao.User.DisplayName = user.Get("displayName").String()
			if sel := pk.Get("authenticatorSelection"); sel.Truthy() {
				if rk := sel.Get("residentKey"); rk.Type() == js.TypeString {
					ao.AuthenticatorSelection.ResidentKey = rk.String()
				}
			}
			params := pk.Get("pubKeyCredParams")
			for i := 0; i < params.Length(); i++ {
				p := params.Index(i)
				ao.PubKeyCredParams = append(ao.PubKeyCredParams, webauthn.PubKeyCredParam{
					Type: p.Get("type").String(),
					Alg:  p.Get("alg").Int(),
				})
			}
			cd, attObj, err := auth.Create(ao)
			if err != nil {
				reject.Invoke(err.Error())
				return nil
			}
			parsedAtt, err := webauthn.ParseAttestationObject(attObj)
			if err != nil {
				reject.Invoke(err.Error())
				return nil
			}
			credID := parsedAtt.AuthData.AttestedCredentials.ID
			resolve.Invoke(newObj(map[string]any{
				"id":    credID.String(),
				"rawId": toJSBytes(credID),
				"type":  "public-key",
				"response": newObj(map[string]any{
					"clientDataJSON":    toJSBytes(cd),
					"attestationObject": toJSBytes(attObj),
				}),
			}))
			return nil
		})
		return promiseCtor.New(execFn)
	})

	getFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		promiseCtor := global.Get("Promise")
		var execFn js.Func
		execFn = js.FuncOf(func(this js.Value, pArgs []js.Value) any {
			defer execFn.Release()
			resolve := pArgs[0]
			reject := pArgs[1]
			pk := args[0].Get("publicKey")
			aso := &webauthn.AssertionOptions{
				Challenge: fromJSBytes(pk.Get("challenge")),
			}
			if allow := pk.Get("allowCredentials"); allow.Truthy() {
				for i := 0; i < allow.Length(); i++ {
					c := allow.Index(i)
					aso.AllowCredentials = append(aso.AllowCredentials, webauthn.CredentialID{
						Type: c.Get("type").String(),
						ID:   fromJSBytes(c.Get("id")),
					})
				}
			}
			id, cd, ad, sig, uh, err := auth.Get(aso)
			if err != nil {
				reject.Invoke(err.Error())
				return nil
			}
			respMap := map[string]any{
				"clientDataJSON":    toJSBytes(cd),
				"authenticatorData": toJSBytes(ad),
				"signature":         toJSBytes(sig),
			}
			if len(uh) > 0 {
				respMap["userHandle"] = toJSBytes(uh)
			}
			_ = arrCtor
			resolve.Invoke(newObj(map[string]any{
				"id":       webauthn.Bytes(id).String(),
				"rawId":    toJSBytes(id),
				"type":     "public-key",
				"response": newObj(respMap),
			}))
			return nil
		})
		return promiseCtor.New(execFn)
	})

	setGlobal("navigator", newObj(map[string]any{
		"credentials": newObj(map[string]any{
			"create": createFn,
			"get":    getFn,
		}),
	}))

	t.Cleanup(func() {
		setGlobal("document", origDoc)
		setGlobal("navigator", origNav)
		createFn.Release()
		getFn.Release()
	})
}

func TestWASMSSHCreateDiscoverAndSign(t *testing.T) {
	auth, err := webauthn.NewFakeAuthenticator()
	if err != nil {
		t.Fatalf("NewFakeAuthenticator: %v", err)
	}
	auth.SetOrigin("https://example.com")
	setupMockWASM(t, auth, "example.com", "https://example.com")

	key, err := Create("my-rk-key", true)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var prompts int
	discKey, discName, err := Discover(func(string) { prompts++ })
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if prompts != 2 {
		t.Errorf("Discover prompts = %d, want 2", prompts)
	}
	if discName != "my-rk-key" {
		t.Errorf("Discover name = %q, want my-rk-key", discName)
	}
	if !bytes.Equal(discKey.Marshal(), key.Marshal()) {
		t.Errorf("discovered public key does not match created key")
	}

	data := []byte("ssh-handshake-payload")
	sig, err := discKey.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := key.Verify(data, sig); err != nil {
		t.Errorf("Verify(Sign): %v", err)
	}
	if _, err := (*Key)(nil).Sign(rand.Reader, data); err == nil {
		t.Error("(*Key)(nil).Sign succeeded, want error")
	}
}
