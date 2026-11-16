// MIT License
//
// Copyright (c) 2025-2026 TTBT Enterprises LLC
// Copyright (c) 2025-2026 Robin Thellend <rthellend@rthellend.com>
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
	"errors"
	"fmt"
	"syscall/js"
)

var (
	jsUint8Array = js.Global().Get("Uint8Array")
	jsArray      = js.Global().Get("Array")
	jsObject     = js.Global().Get("Object")
)

func jsNewObject(m map[string]any) js.Value {
	obj := jsObject.New()
	for k, v := range m {
		obj.Set(k, v)
	}
	return obj
}

func jsNewArray(a []any) js.Value {
	arr := jsArray.New()
	for _, v := range a {
		arr.Call("push", v)
	}
	return arr
}

func jsStringArray(ss []string) js.Value {
	arr := jsArray.New()
	for _, s := range ss {
		arr.Call("push", s)
	}
	return arr
}

// jsValueOf converts v, a value from an Extensions map, to a JS value. In
// addition to the types supported by js.ValueOf, []byte and Bytes are
// converted to Uint8Array, which is what extensions with binary inputs (e.g.
// prf, largeBlob) expect.
func jsValueOf(v any) (js.Value, error) {
	switch x := v.(type) {
	case nil:
		return js.Null(), nil
	case js.Value:
		return x, nil
	case Bytes:
		return uint8ArrayFromBytes(x), nil
	case []byte:
		return uint8ArrayFromBytes(x), nil
	case []string:
		return jsStringArray(x), nil
	case []any:
		arr := jsArray.New()
		for i, e := range x {
			jv, err := jsValueOf(e)
			if err != nil {
				return js.Value{}, fmt.Errorf("[%d]: %w", i, err)
			}
			arr.Call("push", jv)
		}
		return arr, nil
	case map[string]any:
		obj := jsObject.New()
		for k, e := range x {
			jv, err := jsValueOf(e)
			if err != nil {
				return js.Value{}, fmt.Errorf("%s: %w", k, err)
			}
			obj.Set(k, jv)
		}
		return obj, nil
	case bool, string, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return js.ValueOf(x), nil
	default:
		return js.Value{}, fmt.Errorf("unsupported value type %T", v)
	}
}

func jsAwait(p js.Value) (js.Value, error) {
	if p.IsUndefined() || p.IsNull() || (p.Type() != js.TypeObject && p.Type() != js.TypeFunction) {
		return p, nil
	}
	if then := p.Get("then"); then.IsUndefined() || then.Type() != js.TypeFunction {
		return p, nil
	}
	v := make(chan js.Value, 1)
	e := make(chan error, 1)
	resolveFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		var res js.Value
		if len(args) > 0 {
			res = args[0]
		}
		v <- res
		return nil
	})
	defer resolveFn.Release()
	rejectFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) == 0 {
			e <- errors.New("promise rejected")
			return nil
		}
		e <- errors.New(js.Global().Call("String", args[0]).String())
		return nil
	})
	defer rejectFn.Release()
	p.Call("then", resolveFn).
		Call("catch", rejectFn)
	select {
	case value := <-v:
		return value, nil
	case err := <-e:
		return js.Value{}, err
	}
}

func uint8ArrayFromBytes(in []byte) js.Value {
	out := jsUint8Array.New(js.ValueOf(len(in)))
	js.CopyBytesToJS(out, in)
	return out
}

func uint8ArrayToBytes(v js.Value) []byte {
	buf := make([]byte, v.Length())
	js.CopyBytesToGo(buf, v)
	return buf
}

// Hostname returns document.location.hostname in a browser WASM environment.
func Hostname() string {
	return js.Global().Get("document").Get("location").Get("hostname").String()
}

// Origin returns document.location.origin in a browser WASM environment.
func Origin() string {
	return js.Global().Get("document").Get("location").Get("origin").String()
}

// Create invokes navigator.credentials.create() in a browser WASM environment
// using the provided AttestationOptions.
func Create(opts *AttestationOptions) (*AttestationResponse, error) {
	if opts == nil {
		return nil, errors.New("nil AttestationOptions")
	}
	cc := js.Global().Get("navigator").Get("credentials")
	if !cc.Truthy() {
		return nil, errors.New("CredentialsContainer is unavailable")
	}
	// The spec requires user.id to be 1-64 bytes.
	if len(opts.User.ID) == 0 || len(opts.User.ID) > 64 {
		return nil, fmt.Errorf("invalid user ID length %d, want 1-64", len(opts.User.ID))
	}

	attestation := opts.Attestation
	if attestation == "" {
		attestation = "none"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120000
	}
	rpName := opts.RelyingParty.Name
	if rpName == "" {
		rpName = Hostname()
	}
	rpObj := map[string]any{
		"name": rpName,
	}
	if opts.RelyingParty.ID != "" {
		rpObj["id"] = opts.RelyingParty.ID
	}

	displayName := opts.User.DisplayName
	if displayName == "" {
		displayName = opts.User.Name
	}

	params := opts.PubKeyCredParams
	if len(params) == 0 {
		params = []PubKeyCredParam{
			{Type: "public-key", Alg: AlgES256},
			{Type: "public-key", Alg: AlgEdDSA},
			{Type: "public-key", Alg: AlgRS256},
		}
	}
	jsParams := make([]any, 0, len(params))
	for _, p := range params {
		typ := p.Type
		if typ == "" {
			typ = "public-key"
		}
		jsParams = append(jsParams, jsNewObject(map[string]any{
			"alg":  p.Alg,
			"type": typ,
		}))
	}

	authSel := map[string]any{}
	if opts.AuthenticatorSelection.AuthenticatorAttachment != "" {
		authSel["authenticatorAttachment"] = opts.AuthenticatorSelection.AuthenticatorAttachment
	}
	uv := opts.AuthenticatorSelection.UserVerification
	if uv == "" {
		uv = "preferred"
	}
	authSel["userVerification"] = uv
	rk := opts.AuthenticatorSelection.ResidentKey
	if rk == "" {
		if opts.AuthenticatorSelection.RequireResidentKey {
			rk = "required"
		} else {
			rk = "discouraged"
		}
	}
	authSel["residentKey"] = rk
	authSel["requireResidentKey"] = rk == "required" || opts.AuthenticatorSelection.RequireResidentKey

	pubKeyOpts := map[string]any{
		"attestation":            attestation,
		"authenticatorSelection": jsNewObject(authSel),
		"challenge":              uint8ArrayFromBytes(opts.Challenge),
		"pubKeyCredParams":       jsNewArray(jsParams),
		"rp":                     jsNewObject(rpObj),
		"timeout":                timeout,
		"user": jsNewObject(map[string]any{
			"displayName": displayName,
			"id":          uint8ArrayFromBytes(opts.User.ID),
			"name":        opts.User.Name,
		}),
	}
	if len(opts.ExcludeCredentials) > 0 {
		excl := make([]any, 0, len(opts.ExcludeCredentials))
		for _, c := range opts.ExcludeCredentials {
			typ := c.Type
			if typ == "" {
				typ = "public-key"
			}
			entry := map[string]any{
				"id":   uint8ArrayFromBytes(c.ID),
				"type": typ,
			}
			if len(c.Transports) > 0 {
				entry["transports"] = jsStringArray(c.Transports)
			}
			excl = append(excl, jsNewObject(entry))
		}
		pubKeyOpts["excludeCredentials"] = jsNewArray(excl)
	}
	if len(opts.Hints) > 0 {
		pubKeyOpts["hints"] = jsStringArray(opts.Hints)
	}
	if len(opts.AttestationFormats) > 0 {
		pubKeyOpts["attestationFormats"] = jsStringArray(opts.AttestationFormats)
	}
	if len(opts.Extensions) > 0 {
		ext, err := jsValueOf(opts.Extensions)
		if err != nil {
			return nil, fmt.Errorf("extensions: %w", err)
		}
		pubKeyOpts["extensions"] = ext
	}

	creds, err := jsAwait(cc.Call("create", jsNewObject(map[string]any{
		"publicKey": jsNewObject(pubKeyOpts),
	})))
	if err != nil {
		return nil, err
	}
	if !creds.Truthy() {
		return nil, errors.New("no credential returned")
	}
	pkc := creds.Get("response")
	if !pkc.Truthy() {
		return nil, errors.New("credential missing response")
	}
	var rawID Bytes
	if r := creds.Get("rawId"); r.Truthy() {
		rawID = uint8ArrayToBytes(jsUint8Array.New(r))
	}
	var id string
	if v := creds.Get("id"); v.Type() == js.TypeString {
		id = v.String()
	}
	var typ string
	if v := creds.Get("type"); v.Type() == js.TypeString {
		typ = v.String()
	}
	var attachment string
	if v := creds.Get("authenticatorAttachment"); v.Type() == js.TypeString {
		attachment = v.String()
	}
	var transports []string
	if fn := pkc.Get("getTransports"); fn.Type() == js.TypeFunction {
		if tr := pkc.Call("getTransports"); tr.Truthy() {
			n := tr.Length()
			transports = make([]string, 0, n)
			for i := 0; i < n; i++ {
				if item := tr.Index(i); item.Type() == js.TypeString {
					transports = append(transports, item.String())
				}
			}
		}
	}
	return &AttestationResponse{
		ID:                      id,
		RawID:                   rawID,
		Type:                    typ,
		AuthenticatorAttachment: attachment,
		ClientDataJSON:          uint8ArrayToBytes(jsUint8Array.New(pkc.Get("clientDataJSON"))),
		AttestationObject:       uint8ArrayToBytes(jsUint8Array.New(pkc.Get("attestationObject"))),
		Transports:              transports,
	}, nil
}

// Get invokes navigator.credentials.get() in a browser WASM environment using
// the provided AssertionOptions.
func Get(opts *AssertionOptions) (*AssertionResponse, error) {
	if opts == nil {
		return nil, errors.New("nil AssertionOptions")
	}
	cc := js.Global().Get("navigator").Get("credentials")
	if !cc.Truthy() {
		return nil, errors.New("CredentialsContainer is unavailable")
	}

	allow := make([]any, 0, len(opts.AllowCredentials))
	for _, c := range opts.AllowCredentials {
		typ := c.Type
		if typ == "" {
			typ = "public-key"
		}
		entry := map[string]any{
			"id":   uint8ArrayFromBytes(c.ID),
			"type": typ,
		}
		if len(c.Transports) > 0 {
			entry["transports"] = jsStringArray(c.Transports)
		}
		allow = append(allow, jsNewObject(entry))
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120000
	}
	uv := opts.UserVerification
	if uv == "" {
		uv = "preferred"
	}
	pubKeyOpts := map[string]any{
		"allowCredentials": jsNewArray(allow),
		"challenge":        uint8ArrayFromBytes(opts.Challenge),
		"timeout":          timeout,
		"userVerification": uv,
	}
	if opts.RPID != "" {
		pubKeyOpts["rpId"] = opts.RPID
	}
	if len(opts.Hints) > 0 {
		pubKeyOpts["hints"] = jsStringArray(opts.Hints)
	}
	if len(opts.Extensions) > 0 {
		ext, err := jsValueOf(opts.Extensions)
		if err != nil {
			return nil, fmt.Errorf("extensions: %w", err)
		}
		pubKeyOpts["extensions"] = ext
	}

	creds, err := jsAwait(cc.Call("get",
		jsNewObject(map[string]any{
			"publicKey": jsNewObject(pubKeyOpts),
		}),
	))
	if err != nil {
		return nil, err
	}
	if !creds.Truthy() {
		return nil, errors.New("no credential returned")
	}
	pkc := creds.Get("response")
	if !pkc.Truthy() {
		return nil, errors.New("credential missing response")
	}
	var userHandle []byte
	if uh := pkc.Get("userHandle"); uh.Truthy() {
		userHandle = uint8ArrayToBytes(jsUint8Array.New(uh))
	}
	var rawID Bytes
	if r := creds.Get("rawId"); r.Truthy() {
		rawID = uint8ArrayToBytes(jsUint8Array.New(r))
	}
	var id string
	if v := creds.Get("id"); v.Type() == js.TypeString {
		id = v.String()
	}
	var typ string
	if v := creds.Get("type"); v.Type() == js.TypeString {
		typ = v.String()
	}
	var attachment string
	if v := creds.Get("authenticatorAttachment"); v.Type() == js.TypeString {
		attachment = v.String()
	}
	return &AssertionResponse{
		ID:                      id,
		RawID:                   rawID,
		Type:                    typ,
		AuthenticatorAttachment: attachment,
		AuthenticatorData:       uint8ArrayToBytes(jsUint8Array.New(pkc.Get("authenticatorData"))),
		ClientDataJSON:          uint8ArrayToBytes(jsUint8Array.New(pkc.Get("clientDataJSON"))),
		Signature:               uint8ArrayToBytes(jsUint8Array.New(pkc.Get("signature"))),
		UserHandle:              userHandle,
	}, nil
}
