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

package webauthn

import (
	"bytes"
	"syscall/js"
	"testing"
)

// lastCreateOptions and lastGetOptions are the publicKey options most recently
// passed to the mock navigator.credentials.create() and get().
var lastCreateOptions, lastGetOptions js.Value

func setupMockBrowser(t *testing.T, auth *FakeAuthenticator, hostname, origin string) {
	t.Helper()
	global := js.Global()

	origDoc := global.Get("document")
	origNav := global.Get("navigator")

	doc := jsNewObject(map[string]any{
		"location": jsNewObject(map[string]any{
			"hostname": hostname,
			"origin":   origin,
		}),
	})
	setGlobal := func(name string, val js.Value) {
		jsObject.Call("defineProperty", global, name, jsNewObject(map[string]any{
			"value":        val,
			"configurable": true,
			"writable":     true,
		}))
	}
	setGlobal("document", doc)

	createFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		promiseCtor := global.Get("Promise")
		var execFn js.Func
		execFn = js.FuncOf(func(this js.Value, pArgs []js.Value) any {
			defer execFn.Release()
			resolve := pArgs[0]
			reject := pArgs[1]
			pk := args[0].Get("publicKey")
			lastCreateOptions = pk
			ao := &AttestationOptions{
				Challenge:   uint8ArrayToBytes(pk.Get("challenge")),
				Attestation: pk.Get("attestation").String(),
			}
			if formats := pk.Get("attestationFormats"); formats.Truthy() {
				for i := 0; i < formats.Length(); i++ {
					ao.AttestationFormats = append(ao.AttestationFormats, formats.Index(i).String())
				}
			}
			rp := pk.Get("rp")
			ao.RelyingParty.Name = rp.Get("name").String()
			if id := rp.Get("id"); id.Type() == js.TypeString {
				ao.RelyingParty.ID = id.String()
			} else {
				ao.RelyingParty.ID = ao.RelyingParty.Name
			}
			user := pk.Get("user")
			ao.User.ID = uint8ArrayToBytes(user.Get("id"))
			ao.User.Name = user.Get("name").String()
			ao.User.DisplayName = user.Get("displayName").String()
			if sel := pk.Get("authenticatorSelection"); sel.Truthy() {
				if rk := sel.Get("residentKey"); rk.Type() == js.TypeString {
					ao.AuthenticatorSelection.ResidentKey = rk.String()
				}
				if rrk := sel.Get("requireResidentKey"); rrk.Type() == js.TypeBoolean {
					ao.AuthenticatorSelection.RequireResidentKey = rrk.Bool()
				}
				if uv := sel.Get("userVerification"); uv.Type() == js.TypeString {
					ao.AuthenticatorSelection.UserVerification = uv.String()
				}
			}
			params := pk.Get("pubKeyCredParams")
			for i := 0; i < params.Length(); i++ {
				p := params.Index(i)
				ao.PubKeyCredParams = append(ao.PubKeyCredParams, PubKeyCredParam{
					Type: p.Get("type").String(),
					Alg:  p.Get("alg").Int(),
				})
			}
			cd, attObj, err := auth.Create(ao)
			if err != nil {
				reject.Invoke(err.Error())
				return nil
			}
			parsedAtt, err := ParseAttestationObject(attObj)
			if err != nil {
				reject.Invoke(err.Error())
				return nil
			}
			credID := parsedAtt.AuthData.AttestedCredentials.ID
			getTransportsFn := js.FuncOf(func(this js.Value, args []js.Value) any {
				return jsStringArray([]string{"internal"})
			})
			t.Cleanup(getTransportsFn.Release)
			resolve.Invoke(jsNewObject(map[string]any{
				"id":                      credID.String(),
				"rawId":                   uint8ArrayFromBytes(credID),
				"type":                    "public-key",
				"authenticatorAttachment": "platform",
				"response": jsNewObject(map[string]any{
					"clientDataJSON":    uint8ArrayFromBytes(cd),
					"attestationObject": uint8ArrayFromBytes(attObj),
					"getTransports":     getTransportsFn,
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
			lastGetOptions = pk
			aso := &AssertionOptions{
				Challenge: uint8ArrayToBytes(pk.Get("challenge")),
			}
			if allow := pk.Get("allowCredentials"); allow.Truthy() {
				for i := 0; i < allow.Length(); i++ {
					c := allow.Index(i)
					aso.AllowCredentials = append(aso.AllowCredentials, CredentialID{
						Type: c.Get("type").String(),
						ID:   uint8ArrayToBytes(c.Get("id")),
					})
				}
			}
			id, cd, ad, sig, uh, err := auth.Get(aso)
			if err != nil {
				reject.Invoke(err.Error())
				return nil
			}
			respMap := map[string]any{
				"clientDataJSON":    uint8ArrayFromBytes(cd),
				"authenticatorData": uint8ArrayFromBytes(ad),
				"signature":         uint8ArrayFromBytes(sig),
			}
			if len(uh) > 0 {
				respMap["userHandle"] = uint8ArrayFromBytes(uh)
			}
			resolve.Invoke(jsNewObject(map[string]any{
				"id":                      Bytes(id).String(),
				"rawId":                   uint8ArrayFromBytes(id),
				"type":                    "public-key",
				"authenticatorAttachment": "platform",
				"response":                jsNewObject(respMap),
			}))
			return nil
		})
		return promiseCtor.New(execFn)
	})

	nav := jsNewObject(map[string]any{
		"credentials": jsNewObject(map[string]any{
			"create": createFn,
			"get":    getFn,
		}),
	})
	setGlobal("navigator", nav)

	t.Cleanup(func() {
		setGlobal("document", origDoc)
		setGlobal("navigator", origNav)
		createFn.Release()
		getFn.Release()
	})
}

func TestWASMCreateAndGet(t *testing.T) {
	auth, err := NewFakeAuthenticator()
	if err != nil {
		t.Fatalf("NewFakeAuthenticator: %v", err)
	}
	auth.SetOrigin("https://example.com")
	setupMockBrowser(t, auth, "example.com", "https://example.com")

	if got := Hostname(); got != "example.com" {
		t.Errorf("Hostname() = %q, want example.com", got)
	}
	if got := Origin(); got != "https://example.com" {
		t.Errorf("Origin() = %q, want https://example.com", got)
	}

	attOpts, err := NewAttestationOptions()
	if err != nil {
		t.Fatalf("NewAttestationOptions: %v", err)
	}
	attOpts.User.ID = Bytes("user-id-123")
	attOpts.User.Name = "alice"
	attOpts.Hints = []string{"security-key"}
	attOpts.AttestationFormats = []string{"none"}

	createResp, err := Create(attOpts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cred, err := VerifyAttestation(createResp, VerifyAttestationOptions{
		Challenge:               attOpts.Challenge,
		Origin:                  "https://example.com",
		RPID:                    "example.com",
		RequireUserVerification: true,
	})
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}

	assertOpts, err := NewAssertionOptions()
	if err != nil {
		t.Fatalf("NewAssertionOptions: %v", err)
	}
	assertOpts.AllowCredentials = []CredentialID{
		{Type: "public-key", ID: cred.ID, Transports: []string{"internal"}},
	}
	getResp, err := Get(assertOpts)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(getResp.RawID, cred.ID) {
		t.Errorf("getResp.RawID = %x, want %x", getResp.RawID, cred.ID)
	}
	if _, err := VerifyAssertion(getResp, VerifyAssertionOptions{
		Challenge:               assertOpts.Challenge,
		Origin:                  "https://example.com",
		RPID:                    "example.com",
		COSEKey:                 cred.COSEKey,
		CredentialID:            cred.ID,
		RequireUserVerification: true,
	}); err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
}

func TestExtensionsForwarded(t *testing.T) {
	auth, err := NewFakeAuthenticator()
	if err != nil {
		t.Fatalf("NewFakeAuthenticator: %v", err)
	}
	auth.SetOrigin("https://example.com")
	setupMockBrowser(t, auth, "example.com", "https://example.com")

	salt := []byte{1, 2, 3, 4}
	attOpts, err := NewAttestationOptions()
	if err != nil {
		t.Fatalf("NewAttestationOptions: %v", err)
	}
	attOpts.User.ID = Bytes("user-id-123")
	attOpts.User.Name = "alice"
	attOpts.Extensions = map[string]any{
		"credProps": true,
		"prf": map[string]any{
			"eval": map[string]any{"first": Bytes(salt)},
		},
	}
	createResp, err := Create(attOpts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ext := lastCreateOptions.Get("extensions")
	if !ext.Truthy() {
		t.Fatal("create(): extensions not forwarded")
	}
	if v := ext.Get("credProps"); v.Type() != js.TypeBoolean || !v.Bool() {
		t.Errorf("create(): extensions.credProps = %v, want true", v)
	}
	first := ext.Get("prf").Get("eval").Get("first")
	if !first.InstanceOf(jsUint8Array) {
		t.Fatalf("create(): extensions.prf.eval.first is not a Uint8Array")
	}
	if got := uint8ArrayToBytes(first); !bytes.Equal(got, salt) {
		t.Errorf("create(): extensions.prf.eval.first = %x, want %x", got, salt)
	}

	assertOpts, err := NewAssertionOptions()
	if err != nil {
		t.Fatalf("NewAssertionOptions: %v", err)
	}
	assertOpts.AllowCredentials = []CredentialID{{Type: "public-key", ID: createResp.RawID}}
	assertOpts.Extensions = map[string]any{
		"largeBlob": map[string]any{"read": true},
		"list":      []any{"a", int64(2), []byte{9}},
	}
	if _, err := Get(assertOpts); err != nil {
		t.Fatalf("Get: %v", err)
	}
	ext = lastGetOptions.Get("extensions")
	if !ext.Truthy() {
		t.Fatal("get(): extensions not forwarded")
	}
	if v := ext.Get("largeBlob").Get("read"); v.Type() != js.TypeBoolean || !v.Bool() {
		t.Errorf("get(): extensions.largeBlob.read = %v, want true", v)
	}
	if list := ext.Get("list"); list.Length() != 3 || list.Index(0).String() != "a" || list.Index(1).Int() != 2 || !list.Index(2).InstanceOf(jsUint8Array) {
		t.Errorf("get(): unexpected extensions.list %v", list)
	}

	// Without extensions, the member is not set at all.
	assertOpts.Extensions = nil
	if _, err := Get(assertOpts); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if v := lastGetOptions.Get("extensions"); !v.IsUndefined() {
		t.Errorf("get(): extensions = %v, want undefined", v)
	}

	// Values that can't be converted to JS are reported, not dropped.
	assertOpts.Extensions = map[string]any{"bad": struct{}{}}
	if _, err := Get(assertOpts); err == nil {
		t.Error("Get with unsupported extension value succeeded, want error")
	}
	attOpts.Extensions = map[string]any{"bad": make(chan int)}
	if _, err := Create(attOpts); err == nil {
		t.Error("Create with unsupported extension value succeeded, want error")
	}
}
