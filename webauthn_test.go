// MIT License
//
// Copyright (c) 2023-2026 TTBT Enterprises LLC
// Copyright (c) 2023-2026 Robin Thellend <rthellend@rthellend.com>
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

package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/cryptobyte"
)

func TestBytesJSON(t *testing.T) {
	raw := Bytes{0, 1, 2, 3, 254, 255}
	b64 := base64.RawURLEncoding.EncodeToString(raw)

	// MarshalJSON produces base64url string.
	marshaled, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if got, want := string(marshaled), `"`+b64+`"`; got != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}
	if got := raw.String(); got != b64 {
		t.Errorf("raw.String() = %q, want %q", got, b64)
	}
	parsed, err := ParseBytes(b64)
	if err != nil || !bytes.Equal(parsed, raw) {
		t.Errorf("ParseBytes(%q) = %v, %v; want %v", b64, parsed, err, raw)
	}

	// Nil marshals to null.
	var nilBytes Bytes
	if m, err := json.Marshal(nilBytes); err != nil || string(m) != "null" {
		t.Errorf("json.Marshal(nil) = %s, %v; want null", m, err)
	}

	// Unmarshal from base64url string.
	var fromStr Bytes
	if err := json.Unmarshal(marshaled, &fromStr); err != nil {
		t.Fatalf("json.Unmarshal(string): %v", err)
	}
	if !bytes.Equal(fromStr, raw) {
		t.Errorf("fromStr = %v, want %v", fromStr, raw)
	}

	// Unmarshal from legacy [0,1,2,3,254,255] number array.
	var fromArr Bytes
	if err := json.Unmarshal([]byte(`[0, 1, 2, 3, 254, 255]`), &fromArr); err != nil {
		t.Fatalf("json.Unmarshal(array): %v", err)
	}
	if !bytes.Equal(fromArr, raw) {
		t.Errorf("fromArr = %v, want %v", fromArr, raw)
	}

	// Unmarshal null.
	fromNull := Bytes{1, 2, 3}
	if err := json.Unmarshal([]byte(`null`), &fromNull); err != nil {
		t.Fatalf("json.Unmarshal(null): %v", err)
	}
	if fromNull != nil {
		t.Errorf("fromNull = %v, want nil", fromNull)
	}

	// Reject invalid inputs.
	for _, bad := range []string{
		`[-1]`,
		`[256]`,
		`"!!!!"`,
		`"AA=="`, // padding not allowed
		`123`,
		`{}`,
	} {
		var dst Bytes
		if err := json.Unmarshal([]byte(bad), &dst); err == nil {
			t.Errorf("json.Unmarshal(%s) succeeded, want error", bad)
		}
	}
}

func TestWithRawBrowserData(t *testing.T) {
	var (
		clientDataJSON = []byte{
			123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117,
			116, 104, 110, 46, 99, 114, 101, 97, 116, 101, 34, 44, 34, 99,
			104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34, 65, 65, 69,
			67, 65, 119, 81, 70, 66, 103, 99, 73, 67, 81, 111, 76, 68, 65,
			48, 79, 68, 120, 65, 82, 69, 104, 77, 85, 70, 82, 89, 88, 71,
			66, 107, 97, 71, 120, 119, 100, 72, 104, 56, 34, 44, 34, 111,
			114, 105, 103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 115,
			58, 47, 47, 112, 102, 102, 116, 46, 110, 101, 116, 34, 44, 34,
			99, 114, 111, 115, 115, 79, 114, 105, 103, 105, 110, 34, 58,
			102, 97, 108, 115, 101, 125,
		}
		attestationObject = []byte{
			163, 99, 102, 109, 116, 104, 102, 105, 100, 111, 45, 117, 50,
			102, 103, 97, 116, 116, 83, 116, 109, 116, 162, 99, 115, 105,
			103, 88, 72, 48, 70, 2, 33, 0, 206, 172, 115, 184, 201, 72,
			130, 231, 198, 68, 49, 220, 200, 94, 115, 84, 183, 223, 223,
			181, 86, 213, 152, 52, 204, 47, 46, 74, 28, 21, 243, 55, 2,
			33, 0, 197, 18, 140, 110, 215, 146, 61, 20, 119, 12, 229, 155,
			85, 28, 105, 90, 24, 65, 106, 52, 231, 210, 69, 46, 62, 212,
			189, 240, 120, 50, 131, 35, 99, 120, 53, 99, 129, 89, 1, 221,
			48, 130, 1, 217, 48, 130, 1, 125, 160, 3, 2, 1, 2, 2, 1, 1, 48,
			13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 96,
			49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 17, 48, 15, 6,
			3, 85, 4, 10, 12, 8, 67, 104, 114, 111, 109, 105, 117, 109, 49,
			34, 48, 32, 6, 3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101,
			110, 116, 105, 99, 97, 116, 111, 114, 32, 65, 116, 116, 101,
			115, 116, 97, 116, 105, 111, 110, 49, 26, 48, 24, 6, 3, 85, 4,
			3, 12, 17, 66, 97, 116, 99, 104, 32, 67, 101, 114, 116, 105,
			102, 105, 99, 97, 116, 101, 48, 30, 23, 13, 49, 55, 48, 55, 49,
			52, 48, 50, 52, 48, 48, 48, 90, 23, 13, 52, 50, 49, 49, 49, 55,
			50, 49, 52, 49, 49, 52, 90, 48, 96, 49, 11, 48, 9, 6, 3, 85, 4,
			6, 19, 2, 85, 83, 49, 17, 48, 15, 6, 3, 85, 4, 10, 12, 8, 67,
			104, 114, 111, 109, 105, 117, 109, 49, 34, 48, 32, 6, 3, 85, 4,
			11, 12, 25, 65, 117, 116, 104, 101, 110, 116, 105, 99, 97, 116,
			111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111,
			110, 49, 26, 48, 24, 6, 3, 85, 4, 3, 12, 17, 66, 97, 116, 99,
			104, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 48,
			89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72,
			206, 61, 3, 1, 7, 3, 66, 0, 4, 141, 97, 126, 101, 201, 80, 142,
			100, 188, 197, 103, 58, 200, 42, 103, 153, 218, 60, 20, 70, 104,
			44, 37, 140, 70, 63, 255, 223, 88, 223, 210, 250, 62, 108, 55,
			139, 83, 215, 149, 196, 164, 223, 251, 65, 153, 237, 215, 134,
			47, 35, 171, 175, 2, 3, 180, 184, 145, 27, 160, 86, 153, 148,
			225, 1, 163, 37, 48, 35, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4,
			2, 48, 0, 48, 19, 6, 11, 43, 6, 1, 4, 1, 130, 229, 28, 2, 1, 1,
			4, 4, 3, 2, 5, 32, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1,
			1, 11, 5, 0, 3, 71, 0, 48, 68, 2, 32, 110, 49, 252, 55, 238,
			119, 141, 29, 27, 125, 75, 232, 103, 146, 197, 2, 229, 163, 237,
			228, 90, 129, 140, 198, 130, 105, 199, 28, 196, 46, 25, 4, 2,
			32, 127, 75, 238, 41, 183, 177, 29, 102, 154, 202, 191, 189,
			245, 16, 158, 46, 24, 96, 245, 180, 107, 134, 72, 16, 46, 227,
			198, 14, 141, 214, 38, 149, 104, 97, 117, 116, 104, 68, 97, 116,
			97, 88, 164, 59, 173, 244, 133, 130, 181, 29, 207, 214, 72, 18,
			138, 31, 63, 249, 128, 104, 87, 82, 35, 83, 189, 56, 165, 215,
			183, 249, 127, 162, 220, 237, 110, 65, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 221, 85, 140, 104,
			176, 38, 21, 82, 83, 107, 113, 146, 112, 106, 158, 15, 37, 108,
			181, 127, 53, 192, 192, 7, 212, 230, 215, 151, 243, 175, 222,
			88, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 80, 137, 11, 175, 56,
			246, 27, 157, 96, 74, 188, 102, 243, 100, 218, 2, 99, 10, 241,
			171, 76, 122, 90, 50, 33, 210, 174, 194, 242, 198, 21, 139, 34,
			88, 32, 207, 17, 25, 199, 194, 225, 116, 13, 169, 195, 3, 52,
			180, 2, 215, 135, 212, 172, 5, 237, 7, 61, 217, 21, 209, 39,
			126, 139, 30, 104, 99, 242,
		}
		clientDataJSON2 = []byte{
			123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117,
			116, 104, 110, 46, 103, 101, 116, 34, 44, 34, 99, 104, 97, 108,
			108, 101, 110, 103, 101, 34, 58, 34, 65, 65, 69, 67, 65, 119, 81,
			70, 66, 103, 99, 73, 67, 81, 111, 76, 65, 48, 79, 68, 120,
			65, 82, 69, 104, 77, 85, 70, 82, 89, 88, 71, 66, 107, 97, 71,
			120, 119, 100, 72, 104, 56, 34, 44, 34, 111, 114, 105, 103, 105,
			110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 112, 102,
			102, 116, 46, 110, 101, 116, 34, 44, 34, 99, 114, 111, 115, 115,
			79, 114, 105, 103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 125,
		}
		authenticatorData = []byte{
			59, 173, 244, 133, 130, 181, 29, 207, 214, 72, 18, 138, 31, 63,
			249, 128, 104, 87, 82, 35, 83, 189, 56, 165, 215, 183, 249, 127,
			162, 220, 237, 110, 1, 0, 0, 0, 2,
		}
		signature = []byte{
			48, 68, 2, 32, 21, 41, 57, 157, 176, 112, 230, 228, 91, 125, 8,
			141, 56, 88, 109, 132, 34, 221, 245, 158, 45, 197, 234, 38, 61,
			70, 234, 31, 104, 115, 184, 198, 2, 32, 42, 99, 185, 185, 22,
			58, 251, 37, 98, 223, 206, 117, 40, 60, 227, 199, 58, 194, 97,
			216, 252, 247, 201, 218, 18, 237, 37, 133, 159, 252, 176, 145,
		}
	)
	// Fix byte 52 of clientDataJSON2 to match original raw test data (68).
	clientDataJSON2 = []byte{
		123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117,
		116, 104, 110, 46, 103, 101, 116, 34, 44, 34, 99, 104, 97, 108,
		108, 101, 110, 103, 101, 34, 58, 34, 65, 65, 69, 67, 65, 119, 81,
		70, 66, 103, 99, 73, 67, 81, 111, 76, 68, 65, 48, 79, 68, 120,
		65, 82, 69, 104, 77, 85, 70, 82, 89, 88, 71, 66, 107, 97, 71,
		120, 119, 100, 72, 104, 56, 34, 44, 34, 111, 114, 105, 103, 105,
		110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 112, 102,
		102, 116, 46, 110, 101, 116, 34, 44, 34, 99, 114, 111, 115, 115,
		79, 114, 105, 103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 125,
	}

	wantChallenge := make([]byte, 32)
	for i := range wantChallenge {
		wantChallenge[i] = byte(i)
	}

	if _, err := VerifyClientData(clientDataJSON, "webauthn.create", wantChallenge, "https://pfft.net"); err != nil {
		t.Fatalf("VerifyClientData(create): %v", err)
	}
	if _, err := VerifyClientData(clientDataJSON2, "webauthn.get", wantChallenge, "https://pfft.net"); err != nil {
		t.Fatalf("VerifyClientData(get): %v", err)
	}
	ao, err := ParseAttestationObject(attestationObject)
	if err != nil {
		t.Fatalf("ParseAttestationObject: %v", err)
	}
	if !ao.AuthData.UserPresence {
		t.Error("Expected UserPresence to be true")
	}
	if ao.AuthData.UserVerification {
		t.Error("Expected UserVerification to be false")
	}
	if ao.AuthData.AttestedCredentials == nil {
		t.Fatal("no AttestedCredentials")
	}
	if err := ao.VerifyAttestationStatement(clientDataJSON); err != nil {
		t.Fatalf("VerifyAttestationStatement(fido-u2f): %v", err)
	}
	if err := VerifySignature(ao.AuthData.AttestedCredentials.COSEKey, authenticatorData, clientDataJSON2, signature); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func TestWithFakeAuthenticator(t *testing.T) {
	auth, err := NewFakeAuthenticator()
	if err != nil {
		t.Fatalf("NewFakeAuthenticator: %v", err)
	}
	attestOpts, err := NewAttestationOptions()
	if err != nil {
		t.Fatalf("NewAttestationOptions: %v", err)
	}
	attestOpts.RelyingParty.ID = "example.com"
	attestOpts.User.ID = Bytes("user-1234")

	keys := make(map[string]Bytes)
	for _, tc := range []struct {
		alg int
		att string
	}{
		{AlgES256, "none"},
		{AlgES256, "packed"},
		{AlgES256, "packed-self"},
		{AlgES256, "fido-u2f"},
		{AlgEdDSA, "none"},
		{AlgEdDSA, "packed"},
		{AlgEdDSA, "packed-self"},
		{AlgES384, "packed-self"},
		{AlgES512, "packed"},
		{AlgRS256, "none"},
		{AlgRS256, "packed"},
		{AlgRS256, "packed-self"},
		{AlgRS384, "packed-self"},
		{AlgRS512, "none"},
		{AlgPS256, "packed"},
		{AlgPS384, "packed-self"},
		{AlgPS512, "none"},
	} {
		attestOpts.PubKeyCredParams = []PubKeyCredParam{
			{
				Type: "public-key",
				Alg:  tc.alg,
			},
		}
		// "packed-self" is the packed format with self attestation.
		auth.SetSelfAttestation(tc.att == "packed-self")
		switch tc.att {
		case "none":
			attestOpts.Attestation = "none"
			attestOpts.AttestationFormats = nil
		case "packed", "packed-self":
			attestOpts.Attestation = "direct"
			attestOpts.AttestationFormats = []string{"packed"}
		default:
			attestOpts.Attestation = "direct"
			attestOpts.AttestationFormats = []string{tc.att}
		}
		clientDataJSON, attestationObject, err := auth.Create(attestOpts)
		if err != nil {
			t.Fatalf("Create(alg=%d, att=%s): %v", tc.alg, tc.att, err)
		}
		ao, err := ParseAttestationObject(attestationObject)
		if err != nil {
			t.Fatalf("ParseAttestationObject(alg=%d, att=%s): %v", tc.alg, tc.att, err)
		}
		if err := ao.VerifyAttestationStatement(clientDataJSON); err != nil {
			t.Fatalf("VerifyAttestationStatement(alg=%d, att=%s): %v", tc.alg, tc.att, err)
		}
		if !ao.AuthData.UserPresence {
			t.Error("Expected UserPresence to be true")
		}
		if !ao.AuthData.UserVerification {
			t.Error("Expected UserVerification to be true")
		}
		if ao.AuthData.AttestedCredentials == nil {
			t.Fatal("no AttestedCredentials")
		}
		if _, err := ao.AuthData.AttestedCredentials.PublicKey(); err != nil {
			t.Fatalf("PublicKey(alg=%d): %v", tc.alg, err)
		}
		keys[ao.AuthData.AttestedCredentials.ID.String()] = ao.AuthData.AttestedCredentials.COSEKey
	}

	for keyID, coseKey := range keys {
		var prevCount uint32
		for step := 0; step < 2; step++ {
			assertOpts, err := NewAssertionOptions()
			if err != nil {
				t.Fatalf("NewAssertionOptions: %v", err)
			}
			kid, err := ParseBytes(keyID)
			if err != nil {
				t.Fatalf("ParseBytes: %v", err)
			}
			assertOpts.AllowCredentials = append(assertOpts.AllowCredentials, CredentialID{
				Type: "public-key",
				ID:   kid,
			})
			id, clientDataJSON, authData, signature, _, err := auth.Get(assertOpts)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(id, kid) {
				t.Errorf("Unexpected key ID. Got %q, want %q", id, kid)
			}
			var ad AuthenticatorData
			if err := ParseAuthenticatorData(authData, &ad); err != nil {
				t.Fatalf("ParseAuthenticatorData: %v", err)
			}
			if ad.SignCount <= prevCount {
				t.Errorf("SignCount did not increment: got %d, prev %d", ad.SignCount, prevCount)
			}
			prevCount = ad.SignCount
			if err := VerifySignature(coseKey, authData, clientDataJSON, signature); err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}
		}
	}

	auth.SetOrigin("https://custom.example.com")
	auth.ResetSignCount()
	// Also test resident key discovery (empty AllowCredentials).
	rkAssertOpts, err := NewAssertionOptions()
	if err != nil {
		t.Fatalf("NewAssertionOptions: %v", err)
	}
	rkID, rkCD, _, _, rkUH, err := auth.Get(rkAssertOpts)
	if err != nil {
		t.Fatalf("Get(resident): %v", err)
	}
	if len(rkID) == 0 || !bytes.Equal(rkUH, []byte("user-1234")) {
		t.Errorf("Get(resident) id=%x, userHandle=%q", rkID, rkUH)
	}
	if _, err := VerifyClientData(rkCD, "webauthn.get", rkAssertOpts.Challenge, "https://custom.example.com"); err != nil {
		t.Errorf("VerifyClientData(custom origin): %v", err)
	}

	auth.ResetSignCount()
	for keyID := range keys {
		assertOpts, err := NewAssertionOptions()
		if err != nil {
			t.Fatalf("NewAssertionOptions: %v", err)
		}
		kid, _ := ParseBytes(keyID)
		assertOpts.AllowCredentials = []CredentialID{{Type: "public-key", ID: kid}}
		_, _, authData, _, _, err := auth.Get(assertOpts)
		if err != nil {
			t.Fatalf("Get after ResetSignCount: %v", err)
		}
		var ad AuthenticatorData
		if err := ParseAuthenticatorData(authData, &ad); err != nil {
			t.Fatalf("ParseAuthenticatorData: %v", err)
		}
		if ad.SignCount != 1 {
			t.Errorf("SignCount after reset = %d, want 1", ad.SignCount)
		}
		break
	}

	if err := auth.RotateKeys(); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	// All signatures below should be invalid after key rotation.
	for keyID, coseKey := range keys {
		assertOpts, err := NewAssertionOptions()
		if err != nil {
			t.Fatalf("NewAssertionOptions: %v", err)
		}
		kid, _ := ParseBytes(keyID)
		assertOpts.AllowCredentials = append(assertOpts.AllowCredentials, CredentialID{
			ID: kid,
		})
		id, clientDataJSON, authData, signature, _, err := auth.Get(assertOpts)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !bytes.Equal(id, kid) {
			t.Errorf("Unexpected key ID. Got %q, want %q", id, kid)
		}
		if err := VerifySignature(coseKey, authData, clientDataJSON, signature); err == nil {
			t.Fatal("VerifySignature should have failed")
		}
	}
}

func TestVerifyAttestationStatementErrors(t *testing.T) {
	auth, err := NewFakeAuthenticator()
	if err != nil {
		t.Fatalf("NewFakeAuthenticator: %v", err)
	}
	opts, err := NewAttestationOptions()
	if err != nil {
		t.Fatalf("NewAttestationOptions: %v", err)
	}
	opts.RelyingParty.ID = "example.com"
	opts.User.ID = Bytes("user-1")
	opts.Attestation = "direct"
	opts.AttestationFormats = []string{"packed"}

	cdJSON, attObj, err := auth.Create(opts)
	if err != nil {
		t.Fatalf("auth.Create: %v", err)
	}
	ao, err := ParseAttestationObject(attObj)
	if err != nil {
		t.Fatalf("ParseAttestationObject: %v", err)
	}

	// 1. "none" format with non-empty attStmt or non-map attStmt must fail.
	badNone := *ao
	badNone.Format = "none"
	if err := badNone.VerifyAttestationStatement(cdJSON); err == nil {
		t.Error("VerifyAttestationStatement(none with non-empty attStmt) succeeded, want error")
	}
	nullNone := *ao
	nullNone.Format = "none"
	nullNone.AttStmt = cbor.RawMessage{0xf6} // CBOR null
	if err := nullNone.VerifyAttestationStatement(cdJSON); err == nil {
		t.Error("VerifyAttestationStatement(none with CBOR null attStmt) succeeded, want error")
	}

	// 2. "packed" with tampered clientDataJSON must fail.
	if err := ao.VerifyAttestationStatement(append(bytes.Clone(cdJSON), ' ')); err == nil {
		t.Error("VerifyAttestationStatement(packed with tampered clientDataJSON) succeeded, want error")
	}

	// 3. "packed" self-attestation with mismatched alg must fail.
	mismatchStmt, _ := cbor.Marshal(map[string]any{
		"alg": AlgRS256,
		"sig": []byte{1, 2, 3},
	})
	badSelf := *ao
	badSelf.AttStmt = cbor.RawMessage(mismatchStmt)
	if err := badSelf.VerifyAttestationStatement(cdJSON); err == nil {
		t.Error("VerifyAttestationStatement(packed self-attestation with mismatched alg) succeeded, want error")
	}

	// 3b. "packed" with empty x5c array [] must fail (not fall through to self-attestation).
	emptyX5CPacked, _ := cbor.Marshal(map[string]any{
		"alg": AlgES256,
		"sig": []byte{1, 2, 3},
		"x5c": [][]byte{},
	})
	badEmptyX5C := *ao
	badEmptyX5C.AttStmt = cbor.RawMessage(emptyX5CPacked)
	if err := badEmptyX5C.VerifyAttestationStatement(cdJSON); err == nil {
		t.Error("VerifyAttestationStatement(packed with empty x5c) succeeded, want error")
	}

	// 4. "packed" with IsCA=true certificate must fail.
	attPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Fake"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "CA Cert",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &attPriv.PublicKey, attPriv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	h := sha256.Sum256(signedBytes(ao.RawAuthData, cdJSON))
	sig, err := ecdsa.SignASN1(rand.Reader, attPriv, h[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	caStmt, _ := cbor.Marshal(map[string]any{
		"alg": AlgES256,
		"sig": sig,
		"x5c": [][]byte{caDER},
	})
	badCA := *ao
	badCA.AttStmt = cbor.RawMessage(caStmt)
	if err := badCA.VerifyAttestationStatement(cdJSON); err == nil {
		t.Error("VerifyAttestationStatement(packed with IsCA=true) succeeded, want error")
	}

	// 5. "packed" with mismatched AAGUID extension in cert must fail.
	wrongAAGUID, _ := asn1.Marshal(make([]byte, 16))
	aaguidTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Fake"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "Wrong AAGUID",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    oidFIDOGenCEAAGUID,
				Value: wrongAAGUID,
			},
		},
	}
	wrongAAGUIDDER, err := x509.CreateCertificate(rand.Reader, aaguidTmpl, aaguidTmpl, &attPriv.PublicKey, attPriv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	wrongAAGUIDStmt, _ := cbor.Marshal(map[string]any{
		"alg": AlgES256,
		"sig": sig,
		"x5c": [][]byte{wrongAAGUIDDER},
	})
	badAAGUID := *ao
	badAAGUID.AttStmt = cbor.RawMessage(wrongAAGUIDStmt)
	if err := badAAGUID.VerifyAttestationStatement(cdJSON); err == nil {
		t.Error("VerifyAttestationStatement(packed with mismatched AAGUID) succeeded, want error")
	}

	// 6. Unsupported format must fail.
	badFmt := *ao
	badFmt.Format = "unknown-fmt"
	if err := badFmt.VerifyAttestationStatement(cdJSON); err == nil {
		t.Error("VerifyAttestationStatement(unknown-fmt) succeeded, want error")
	}

	// 7. ParseAttestationObject error branches.
	if _, err := ParseAttestationObject(nil); err == nil {
		t.Error("ParseAttestationObject(nil) succeeded, want error")
	}
	if _, err := ParseAttestationObject([]byte{0x01}); err == nil {
		t.Error("ParseAttestationObject(non-map) succeeded, want error")
	}
	if _, err := ParseAttestationObject(append(bytes.Clone(attObj), 0x00)); err == nil {
		t.Error("ParseAttestationObject(trailing bytes) succeeded, want error")
	}
	noATAuthData := make([]byte, 37)
	noATAuthData[32] = FlagUserPresent
	noATObj, _ := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": noATAuthData,
	})
	if _, err := ParseAttestationObject(noATObj); err == nil {
		t.Error("ParseAttestationObject(without AT flag) succeeded, want error")
	}

	// 8. fido-u2f negative branches (non-zero AAGUID, tampered sig, wrong x5c count).
	opts.Attestation = "direct"
	opts.AttestationFormats = []string{"fido-u2f"}
	opts.PubKeyCredParams = []PubKeyCredParam{{Type: "public-key", Alg: AlgES256}}
	u2fCD, u2fObj, err := auth.Create(opts)
	if err != nil {
		t.Fatalf("Create(fido-u2f): %v", err)
	}
	u2fAO, err := ParseAttestationObject(u2fObj)
	if err != nil {
		t.Fatalf("ParseAttestationObject(fido-u2f): %v", err)
	}
	if err := u2fAO.VerifyAttestationStatement(append(bytes.Clone(u2fCD), ' ')); err == nil {
		t.Error("VerifyAttestationStatement(fido-u2f tampered clientData) succeeded, want error")
	}
	badU2FAAGUID := *u2fAO
	badCreds := *u2fAO.AuthData.AttestedCredentials
	badCreds.AAGUID = Bytes(bytes.Repeat([]byte{1}, 16))
	badU2FAAGUID.AuthData.AttestedCredentials = &badCreds
	if err := badU2FAAGUID.VerifyAttestationStatement(u2fCD); err == nil {
		t.Error("VerifyAttestationStatement(fido-u2f non-zero AAGUID) succeeded, want error")
	}
	emptyX5CStmt, _ := cbor.Marshal(map[string]any{"sig": []byte{1, 2, 3}})
	badU2FX5C := *u2fAO
	badU2FX5C.AttStmt = cbor.RawMessage(emptyX5CStmt)
	if err := badU2FX5C.VerifyAttestationStatement(u2fCD); err == nil {
		t.Error("VerifyAttestationStatement(fido-u2f missing x5c) succeeded, want error")
	}
}

func TestShortCredentialID(t *testing.T) {
	var raw [37 + 18 + 4 + 1]byte
	raw[32] = FlagUserPresent | FlagUserVerified | FlagAttestedCredentialData
	raw[37+16] = 0
	raw[37+17] = 4      // credentialId length = 4 (< 16)
	raw[37+18+4] = 0xa0 // empty CBOR map for COSEKey
	var ad AuthenticatorData
	if err := ParseAuthenticatorData(raw[:], &ad); err == nil {
		t.Errorf("ParseAuthenticatorData accepted 4-byte credentialId, want error")
	}
}

func TestParseAuthenticatorData(t *testing.T) {
	rpHash := sha256.Sum256([]byte("example.com"))
	makeAuthData := func(flags byte, counter uint32, tail []byte) []byte {
		var b cryptobyte.Builder
		b.AddBytes(rpHash[:])
		b.AddUint8(flags)
		b.AddUint32(counter)
		b.AddBytes(tail)
		return b.BytesOrPanic()
	}

	// Valid minimal authenticatorData (UP=1)
	if err := ParseAuthenticatorData(makeAuthData(FlagUserPresent, 7, nil), nil); err == nil {
		t.Error("ParseAuthenticatorData(nil) succeeded; want error")
	}
	var ad AuthenticatorData
	if err := ParseAuthenticatorData(makeAuthData(FlagUserPresent, 7, nil), &ad); err != nil {
		t.Fatalf("ParseAuthenticatorData(minimal) failed: %v", err)
	}
	if !ad.UserPresence || ad.SignCount != 7 || len(ad.Extensions) != 0 {
		t.Errorf("unexpected parsed AuthenticatorData: %+v", ad)
	}

	// WebAuthn Level 3 §6.1: BS=1 when BE=0 must be rejected.
	if err := ParseAuthenticatorData(makeAuthData(FlagUserPresent|FlagBackupState, 7, nil), &ad); err == nil {
		t.Error("ParseAuthenticatorData(BE=0, BS=1) succeeded; want error")
	}

	// BE=1, BS=1 is valid.
	if err := ParseAuthenticatorData(makeAuthData(FlagUserPresent|FlagBackupEligible|FlagBackupState, 7, nil), &ad); err != nil {
		t.Errorf("ParseAuthenticatorData(BE=1, BS=1) failed: %v", err)
	}

	// Trailing bytes without ED/AT flags must be rejected.
	if err := ParseAuthenticatorData(makeAuthData(FlagUserPresent, 7, []byte{0x00}), &ad); err == nil {
		t.Error("ParseAuthenticatorData with trailing bytes succeeded; want error")
	}

	// Valid CBOR extension map {1: true} -> 0xa1 0x01 0xf5
	cborExt := []byte{0xa1, 0x01, 0xf5}
	var adExt AuthenticatorData
	if err := ParseAuthenticatorData(makeAuthData(FlagUserPresent|FlagExtensionData, 8, cborExt), &adExt); err != nil {
		t.Fatalf("ParseAuthenticatorData(with extensions) failed: %v", err)
	}
	if !adExt.ExtensionData || !bytes.Equal(adExt.Extensions, cborExt) {
		t.Errorf("ParseAuthenticatorData extensions = %x, want %x", adExt.Extensions, cborExt)
	}

	// ED flag set but no extension bytes
	if err := ParseAuthenticatorData(makeAuthData(FlagUserPresent|FlagExtensionData, 8, nil), &adExt); err == nil {
		t.Error("ParseAuthenticatorData(ED=1, empty) succeeded; want error")
	}

	// ED flag set with trailing bytes after CBOR object
	if err := ParseAuthenticatorData(makeAuthData(FlagUserPresent|FlagExtensionData, 8, append(bytes.Clone(cborExt), 0x00)), &adExt); err == nil {
		t.Error("ParseAuthenticatorData(ED=1, trailing bytes) succeeded; want error")
	}

	// ED flag set with non-map CBOR item (e.g., integer 1 -> 0x01) must be rejected
	if err := ParseAuthenticatorData(makeAuthData(FlagUserPresent|FlagExtensionData, 8, []byte{0x01}), &adExt); err == nil {
		t.Error("ParseAuthenticatorData(ED=1, non-map CBOR) succeeded; want error")
	}
}

func TestParseCOSEKeyValidation(t *testing.T) {
	// 1. P-256 key with 31-byte X coordinate must be rejected per RFC 9053 §7.1.1.
	shortCoord, _ := cbor.Marshal(map[int]any{
		1:  2,
		3:  AlgES256,
		-1: 1,
		-2: make([]byte, 31),
		-3: make([]byte, 32),
	})
	if _, _, err := ParseCOSEKey(shortCoord); err == nil {
		t.Error("ParseCOSEKey accepted 31-byte P-256 coordinate, want error")
	}

	// 2. P-256 key with point not on curve (0, 0) must be rejected.
	offCurve, _ := cbor.Marshal(map[int]any{
		1:  2,
		3:  AlgES256,
		-1: 1,
		-2: make([]byte, 32),
		-3: make([]byte, 32),
	})
	if _, _, err := ParseCOSEKey(offCurve); err == nil {
		t.Error("ParseCOSEKey accepted off-curve P-256 point, want error")
	}

	// 3. Ed25519 key with wrong length must be rejected.
	badEd, _ := cbor.Marshal(map[int]any{
		1:  1,
		3:  AlgEdDSA,
		-1: 6,
		-2: make([]byte, 31),
	})
	if _, _, err := ParseCOSEKey(badEd); err == nil {
		t.Error("ParseCOSEKey accepted 31-byte Ed25519 key, want error")
	}

	// 4. RSA key with leading zero byte in N or E must be rejected per RFC 8230 §4.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	leadingZeroN, _ := cbor.Marshal(map[int]any{
		1:  3,
		3:  AlgRS256,
		-1: append([]byte{0x00}, rsaPriv.N.Bytes()...),
		-2: big.NewInt(int64(rsaPriv.E)).Bytes(),
	})
	if _, _, err := ParseCOSEKey(leadingZeroN); err == nil {
		t.Error("ParseCOSEKey accepted RSA modulus with leading zero byte, want error")
	}

	// 5. Trailing bytes after valid COSEKey CBOR map must be rejected.
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	validCOSE, err := MarshalCOSEKey(edPub)
	if err != nil {
		t.Fatalf("MarshalCOSEKey: %v", err)
	}
	if _, _, err := ParseCOSEKey(append(bytes.Clone(validCOSE), 0x00)); err == nil {
		t.Error("ParseCOSEKey accepted trailing bytes, want error")
	}

	// 6. Value-type ecdsa.PublicKey and rsa.PublicKey in MarshalCOSEKey, plus unsupported types.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	if _, err := MarshalCOSEKey(ecPriv.PublicKey); err != nil {
		t.Errorf("MarshalCOSEKey(ecdsa.PublicKey value): %v", err)
	}
	if _, err := MarshalCOSEKey(rsaPriv.PublicKey); err != nil {
		t.Errorf("MarshalCOSEKey(rsa.PublicKey value): %v", err)
	}
	if _, err := MarshalCOSEKey("not-a-key"); err == nil {
		t.Error("MarshalCOSEKey(string) succeeded, want error")
	}
	if _, err := MarshalCOSEKey(ed25519.PublicKey([]byte("short"))); err == nil {
		t.Error("MarshalCOSEKey(short ed25519) succeeded, want error")
	}
	if _, err := MarshalCOSEKey((*ecdsa.PublicKey)(nil)); err == nil {
		t.Error("MarshalCOSEKey(nil *ecdsa.PublicKey) succeeded, want error")
	}
	if _, err := MarshalCOSEKey((*rsa.PublicKey)(nil)); err == nil {
		t.Error("MarshalCOSEKey(nil *rsa.PublicKey) succeeded, want error")
	}
	if _, err := MarshalCOSEKey(&ecdsa.PublicKey{Curve: elliptic.P256()}); err == nil {
		t.Error("MarshalCOSEKey(nil EC X/Y) succeeded, want error")
	}
	if _, err := MarshalCOSEKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Neg(ecPriv.X), Y: ecPriv.Y}); err == nil {
		t.Error("MarshalCOSEKey(negative EC X) succeeded, want error")
	}
	if _, err := MarshalCOSEKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Lsh(big.NewInt(1), 300), Y: ecPriv.Y}); err == nil {
		t.Error("MarshalCOSEKey(oversized EC X) succeeded, want error")
	}
	if _, err := MarshalCOSEKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}); err == nil {
		t.Error("MarshalCOSEKey(off-curve EC point) succeeded, want error")
	}
	if _, err := MarshalCOSEKey(&rsa.PublicKey{}); err == nil {
		t.Error("MarshalCOSEKey(empty RSA key) succeeded, want error")
	}
	if _, err := MarshalCOSEKey(&rsa.PublicKey{N: rsaPriv.N, E: 2}); err == nil {
		t.Error("MarshalCOSEKey(even RSA exponent) succeeded, want error")
	}

	// 7. RSA small modulus (< 2048 bits) and invalid exponent.
	smallRSA, _ := cbor.Marshal(map[int]any{
		1:  3,
		3:  AlgRS256,
		-1: []byte{0x01, 0x01},
		-2: []byte{0x01, 0x00, 0x01},
	})
	if _, _, err := ParseCOSEKey(smallRSA); err == nil {
		t.Error("ParseCOSEKey(small RSA modulus) succeeded, want error")
	}
	evenExpRSA, _ := cbor.Marshal(map[int]any{
		1:  3,
		3:  AlgRS256,
		-1: rsaPriv.N.Bytes(),
		-2: []byte{0x04},
	})
	if _, _, err := ParseCOSEKey(evenExpRSA); err == nil {
		t.Error("ParseCOSEKey(even RSA exponent) succeeded, want error")
	}
}

func TestVerifyClientData(t *testing.T) {
	challenge := []byte("0123456789abcdef")
	encoded := base64.RawURLEncoding.EncodeToString(challenge)
	// Mutate the last character's unused padding bits so standard RawURLEncoding
	// would decode it to the same bytes, but Strict() rejects it.
	nonCanonical := encoded[:len(encoded)-1] + "h"

	for _, tc := range []struct {
		name       string
		js         string
		wantOrigin string
		wantErr    bool
	}{
		{"ok", `{"type":"webauthn.get","challenge":"` + encoded + `","origin":"https://example.com"}`, "https://example.com", false},
		{"ok any origin", `{"type":"webauthn.get","challenge":"` + encoded + `","origin":"https://example.com"}`, "", false},
		{"ok crossOrigin false", `{"type":"webauthn.get","challenge":"` + encoded + `","origin":"https://example.com","crossOrigin":false}`, "", false},
		{"ok tokenBinding supported", `{"type":"webauthn.get","challenge":"` + encoded + `","tokenBinding":{"status":"supported"}}`, "", false},
		{"ok tokenBinding present", `{"type":"webauthn.get","challenge":"` + encoded + `","tokenBinding":{"status":"present","id":"dG9r"}}`, "", false},
		{"tokenBinding supported with id", `{"type":"webauthn.get","challenge":"` + encoded + `","tokenBinding":{"status":"supported","id":"dG9r"}}`, "", true},
		{"tokenBinding present missing id", `{"type":"webauthn.get","challenge":"` + encoded + `","tokenBinding":{"status":"present"}}`, "", true},
		{"tokenBinding invalid status", `{"type":"webauthn.get","challenge":"` + encoded + `","tokenBinding":{"status":"not-supported"}}`, "", true},
		{"topOrigin when crossOrigin false", `{"type":"webauthn.get","challenge":"` + encoded + `","crossOrigin":false,"topOrigin":"https://top.example.com"}`, "", true},
		{"crossOrigin true", `{"type":"webauthn.get","challenge":"` + encoded + `","crossOrigin":true}`, "", true},
		{"wrong origin", `{"type":"webauthn.get","challenge":"` + encoded + `","origin":"https://evil.com"}`, "https://example.com", true},
		{"non-canonical base64url", `{"type":"webauthn.get","challenge":"` + nonCanonical + `"}`, "", true},
		{"wrong type", `{"type":"webauthn.create","challenge":"` + encoded + `"}`, "", true},
		{"wrong challenge", `{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString([]byte("nope")) + `"}`, "", true},
		{"missing challenge", `{"type":"webauthn.get"}`, "", true},
		{"unparsable challenge", `{"type":"webauthn.get","challenge":"!!!!"}`, "", true},
		{"null json", `null`, "", true},
		{"not json", `nope`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyClientData([]byte(tc.js), "webauthn.get", challenge, tc.wantOrigin)
			if got := err != nil; got != tc.wantErr {
				t.Errorf("VerifyClientData() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
	if _, err := ParseClientData([]byte("null")); err == nil {
		t.Error("ParseClientData(null) succeeded, want error")
	}
}

func TestRecoverPublicKey(t *testing.T) {
	curve := elliptic.P256()

	for iter := 0; iter < 50; iter++ {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}

		ad1, cd1, sig1 := signAssertionForTest(t, priv, fmt.Sprintf("1-%d", iter))
		ad2, cd2, sig2 := signAssertionForTest(t, priv, fmt.Sprintf("2-%d", iter))

		pk, err := RecoverPublicKey(ad1, cd1, sig1, ad2, cd2, sig2)
		if err != nil {
			t.Fatalf("iteration %d: RecoverPublicKey failed: %v", iter, err)
		}
		if pk.X.Cmp(priv.PublicKey.X) != 0 || pk.Y.Cmp(priv.PublicKey.Y) != 0 {
			t.Fatalf("iteration %d: recovered public key does not match", iter)
		}
	}
}

func signAssertionForTest(t *testing.T, priv *ecdsa.PrivateKey, tag string) (authData, clientDataJSON, sig []byte) {
	t.Helper()
	authData = []byte("authenticatorData-" + tag)
	clientDataJSON = []byte(`{"type":"webauthn.get","challenge":"` + tag + `"}`)
	hash := sha256.Sum256(signedBytes(authData, clientDataJSON))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig, err = asn1.Marshal(struct{ R, S *big.Int }{r, s}); err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return authData, clientDataJSON, sig
}

func TestRecoverPublicKeyRejectsOutOfRangeSignature(t *testing.T) {
	curve := elliptic.P256()
	p := curve.Params().P
	n := curve.Params().N

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ad, cd, good := signAssertionForTest(t, priv, "good")

	for _, tc := range []struct {
		name string
		r, s *big.Int
	}{
		{"negative r", big.NewInt(-5), big.NewInt(7)},
		{"negative s", big.NewInt(7), big.NewInt(-5)},
		{"zero r", big.NewInt(0), big.NewInt(7)},
		{"zero s", big.NewInt(7), big.NewInt(0)},
		{"r >= n", new(big.Int).Add(n, big.NewInt(1)), big.NewInt(7)},
		{"s >= n", big.NewInt(7), new(big.Int).Add(n, big.NewInt(1))},
		{"r > p", new(big.Int).Add(p, big.NewInt(12345)), big.NewInt(7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := asn1.Marshal(struct{ R, S *big.Int }{tc.r, tc.s})
			if err != nil {
				t.Fatalf("asn1.Marshal: %v", err)
			}
			for _, args := range [][2][]byte{{bad, good}, {good, bad}, {bad, bad}} {
				if _, err := RecoverPublicKey(ad, cd, args[0], ad, cd, args[1]); err == nil {
					t.Errorf("RecoverPublicKey(%v) = nil error, want error", tc.name)
				}
			}
		})
	}
}

func TestRecoverPublicKeyRejectsMalformedSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ad, cd, good := signAssertionForTest(t, priv, "good")

	for _, tc := range []struct {
		name string
		sig  []byte
	}{
		{"empty", nil},
		{"garbage", []byte{0xff, 0xff, 0xff, 0xff}},
		{"truncated", good[:len(good)/2]},
		{"trailing bytes", append(bytes.Clone(good), 0x00)},
		{"not DER", make([]byte, 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RecoverPublicKey(ad, cd, tc.sig, ad, cd, good); err == nil {
				t.Errorf("RecoverPublicKey(%v) = nil error, want error", tc.name)
			}
		})
	}
}

func TestRecoverPublicKeyRejectsMismatchedKeysAndTamperedData(t *testing.T) {
	privA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ad1, cd1, sig1 := signAssertionForTest(t, privA, "one")
	ad2, cd2, sig2 := signAssertionForTest(t, privB, "two")

	if _, err := RecoverPublicKey(ad1, cd1, sig1, ad2, cd2, sig2); err == nil {
		t.Error("RecoverPublicKey with two different keys = nil error, want error")
	}

	ad2A, cd2A, sig2A := signAssertionForTest(t, privA, "two")
	if _, err := RecoverPublicKey(append(ad1, 'x'), cd1, sig1, ad2A, cd2A, sig2A); err == nil {
		t.Error("RecoverPublicKey with tampered authData = nil error, want error")
	}
	if _, err := RecoverPublicKey(ad1, cd1, sig1, ad1, cd1, sig1); err == nil {
		t.Error("RecoverPublicKey with identical assertions = nil error, want error")
	}

	// Crafted signature r = (eG)_x, s = 1 where recoverCandidatesP256 yields
	// only 1 candidate must still be rejected when passed twice.
	curve := elliptic.P256()
	n := curve.Params().N
	hash1 := sha256.Sum256(signedBytes(ad1, cd1))
	e := new(big.Int).SetBytes(hash1[:])
	e.Mod(e, n)
	eGx, _ := curve.ScalarBaseMult(e.Bytes())
	craftedSig, err := asn1.Marshal(struct{ R, S *big.Int }{eGx, big.NewInt(1)})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	if _, err := RecoverPublicKey(ad1, cd1, craftedSig, ad1, cd1, craftedSig); err == nil {
		t.Error("RecoverPublicKey with identical single-candidate assertions = nil error, want error")
	}
}

func TestHighLevelCeremoniesAndResponseJSON(t *testing.T) {
	auth, err := NewFakeAuthenticator()
	if err != nil {
		t.Fatalf("NewFakeAuthenticator: %v", err)
	}
	auth.SetOrigin("https://login.example.com")

	attOpts, err := NewAttestationOptions()
	if err != nil {
		t.Fatalf("NewAttestationOptions: %v", err)
	}
	attOpts.RelyingParty.Name = "Example"
	attOpts.RelyingParty.ID = "example.com"
	attOpts.User.ID = Bytes("user-handle-1")
	attOpts.User.Name = "alice@example.com"
	attOpts.User.DisplayName = "Alice"
	attOpts.Attestation = "direct"
	attOpts.AttestationFormats = []string{"packed"}

	cdJSON, attObj, err := auth.Create(attOpts)
	if err != nil {
		t.Fatalf("auth.Create: %v", err)
	}

	// Test W3C Level 3 nested RegistrationResponseJSON unmarshaling.
	nestedRegJSON, err := json.Marshal(map[string]any{
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    Bytes(cdJSON),
			"attestationObject": Bytes(attObj),
			"transports":        []string{"internal", "hybrid"},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var attResp AttestationResponse
	if err := json.Unmarshal(nestedRegJSON, &attResp); err != nil {
		t.Fatalf("json.Unmarshal(AttestationResponse): %v", err)
	}

	cred, err := VerifyAttestation(&attResp, VerifyAttestationOptions{
		Challenge:                  attOpts.Challenge,
		AllowedOrigins:             []string{"https://example.com", "https://login.example.com"},
		RPID:                       "example.com",
		RequireUserVerification:    true,
		VerifyAttestationStatement: true,
		AllowedAlgorithms:          []int{AlgES256, AlgEdDSA},
	})
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	if cred.Algorithm != AlgES256 || !cred.UserVerified || len(cred.Transports) != 2 {
		t.Errorf("unexpected VerifiedCredential: %+v", cred)
	}

	// Disallowed algorithm must fail VerifyAttestation.
	if _, err := VerifyAttestation(&attResp, VerifyAttestationOptions{
		Challenge:         attOpts.Challenge,
		Origin:            "https://login.example.com",
		RPID:              "example.com",
		AllowedAlgorithms: []int{AlgEdDSA},
	}); err == nil {
		t.Error("VerifyAttestation with disallowed algorithm succeeded, want error")
	}

	// Missing Origin and AllowedOrigins must fail VerifyAttestation.
	if _, err := VerifyAttestation(&attResp, VerifyAttestationOptions{
		Challenge: attOpts.Challenge,
		RPID:      "example.com",
	}); err == nil {
		t.Error("VerifyAttestation without Origin/AllowedOrigins succeeded, want error")
	}

	// Mismatched id and rawId in AttestationResponse JSON must fail UnmarshalJSON.
	if err := json.Unmarshal([]byte(`{"id":"AAAA","rawId":"BBBB","clientDataJSON":"AAAA","attestationObject":"AAAA"}`), new(AttestationResponse)); err == nil {
		t.Error("UnmarshalJSON(mismatched id/rawId) succeeded, want error")
	}
	if err := json.Unmarshal([]byte(`{"id":"AAAA","rawId":"","clientDataJSON":"AAAA","attestationObject":"AAAA"}`), new(AttestationResponse)); err == nil {
		t.Error("UnmarshalJSON(id with empty rawId string) succeeded, want error")
	}
	if err := json.Unmarshal([]byte(`{"id":"AAAA","rawId":[],"clientDataJSON":"AAAA","attestationObject":"AAAA"}`), new(AttestationResponse)); err == nil {
		t.Error("UnmarshalJSON(id with empty rawId array) succeeded, want error")
	}
	if err := json.Unmarshal([]byte(`{"id":"!!!!","clientDataJSON":"AAAA","attestationObject":"AAAA"}`), new(AttestationResponse)); err == nil {
		t.Error("UnmarshalJSON(invalid id base64url) succeeded, want error")
	}

	// Now test assertion ceremony via W3C Level 3 nested AuthenticationResponseJSON.
	assertOpts, err := NewAssertionOptions()
	if err != nil {
		t.Fatalf("NewAssertionOptions: %v", err)
	}
	id, assertCD, assertAD, sig, uh, err := auth.Get(assertOpts)
	if err != nil {
		t.Fatalf("auth.Get: %v", err)
	}
	nestedAuthJSON, err := json.Marshal(map[string]any{
		"id":   Bytes(id).String(),
		"type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    Bytes(assertCD),
			"authenticatorData": Bytes(assertAD),
			"signature":         Bytes(sig),
			"userHandle":        Bytes(uh),
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var assertResp AssertionResponse
	if err := json.Unmarshal(nestedAuthJSON, &assertResp); err != nil {
		t.Fatalf("json.Unmarshal(AssertionResponse): %v", err)
	}

	verifiedAssert, err := VerifyAssertion(&assertResp, VerifyAssertionOptions{
		Challenge:               assertOpts.Challenge,
		Origin:                  "https://login.example.com",
		RPID:                    "example.com",
		COSEKey:                 cred.COSEKey,
		CredentialID:            cred.ID,
		UserHandle:              attOpts.User.ID,
		RequireUserVerification: true,
		PrevSignCount:           cred.SignCount,
	})
	if err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
	if verifiedAssert.SignCount <= cred.SignCount {
		t.Errorf("verifiedAssert.SignCount = %d, want > %d", verifiedAssert.SignCount, cred.SignCount)
	}

	// Replaying with PrevSignCount >= SignCount must fail unless IgnoreSignCount is set.
	if _, err := VerifyAssertion(&assertResp, VerifyAssertionOptions{
		Challenge:     assertOpts.Challenge,
		Origin:        "https://login.example.com",
		RPID:          "example.com",
		COSEKey:       cred.COSEKey,
		PrevSignCount: verifiedAssert.SignCount,
	}); err == nil {
		t.Error("VerifyAssertion with non-increasing SignCount succeeded, want error")
	}
	if _, err := VerifyAssertion(&assertResp, VerifyAssertionOptions{
		Challenge:       assertOpts.Challenge,
		Origin:          "https://login.example.com",
		RPID:            "example.com",
		COSEKey:         cred.COSEKey,
		PrevSignCount:   verifiedAssert.SignCount,
		IgnoreSignCount: true,
	}); err != nil {
		t.Errorf("VerifyAssertion(IgnoreSignCount=true) failed: %v", err)
	}

	// VerifyAssertion with CredentialID set when resp has empty ID/RawID must fail.
	noIDResp := assertResp
	noIDResp.ID = ""
	noIDResp.RawID = nil
	if _, err := VerifyAssertion(&noIDResp, VerifyAssertionOptions{
		Challenge:       assertOpts.Challenge,
		Origin:          "https://login.example.com",
		RPID:            "example.com",
		COSEKey:         cred.COSEKey,
		CredentialID:    cred.ID,
		IgnoreSignCount: true,
	}); err == nil {
		t.Error("VerifyAssertion with empty response ID and non-empty opts.CredentialID succeeded, want error")
	}
}

func TestAssertionOptionsJSON(t *testing.T) {
	// Options that are not created with NewAssertionOptions must not marshal
	// to "allowCredentials":null or "userVerification":"", which browsers
	// reject.
	b, err := json.Marshal(AssertionOptions{Challenge: Bytes{1, 2, 3}, RPID: "example.com"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if got, want := string(b), `{"challenge":"AQID","rpId":"example.com"}`; got != want {
		t.Errorf("AssertionOptions JSON = %s, want %s", got, want)
	}

	opts, err := NewAssertionOptions()
	if err != nil {
		t.Fatalf("NewAssertionOptions: %v", err)
	}
	opts.AllowCredentials = []CredentialID{{Type: "public-key", ID: Bytes{4, 5, 6}}}
	if b, err = json.Marshal(opts); err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got := m["userVerification"]; got != "required" {
		t.Errorf("userVerification = %v, want required", got)
	}
	if got, ok := m["allowCredentials"].([]any); !ok || len(got) != 1 {
		t.Errorf("allowCredentials = %v, want one credential", m["allowCredentials"])
	}
}

func TestFakeAuthenticatorAttestationFormat(t *testing.T) {
	for _, tc := range []struct {
		attestation string
		formats     []string
		self        bool
		wantFormat  string
		wantX5C     bool
		wantErr     bool
	}{
		{attestation: "", wantFormat: "none"},
		{attestation: "none", wantFormat: "none"},
		{attestation: "none", formats: []string{"packed"}, wantFormat: "none"},
		{attestation: "direct", wantFormat: "packed", wantX5C: true},
		{attestation: "direct", self: true, wantFormat: "packed"},
		{attestation: "indirect", formats: []string{"packed"}, wantFormat: "packed", wantX5C: true},
		{attestation: "enterprise", formats: []string{"tpm", "fido-u2f", "packed"}, wantFormat: "fido-u2f", wantX5C: true},
		{attestation: "direct", formats: []string{"none"}, wantFormat: "none"},
		{attestation: "direct", formats: []string{"tpm"}, wantFormat: "packed", wantX5C: true},
		// Attestation statement formats are not conveyance preferences.
		{attestation: "packed", wantErr: true},
		{attestation: "packed-self", wantErr: true},
		{attestation: "fido-u2f", wantErr: true},
	} {
		auth, err := NewFakeAuthenticator()
		if err != nil {
			t.Fatalf("NewFakeAuthenticator: %v", err)
		}
		auth.SetSelfAttestation(tc.self)
		opts, err := NewAttestationOptions()
		if err != nil {
			t.Fatalf("NewAttestationOptions: %v", err)
		}
		opts.RelyingParty.ID = "example.com"
		opts.User.ID = Bytes("user-1")
		opts.PubKeyCredParams = []PubKeyCredParam{{Type: "public-key", Alg: AlgES256}}
		opts.Attestation = tc.attestation
		opts.AttestationFormats = tc.formats

		cdJSON, attObj, err := auth.Create(opts)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Create(attestation=%q) succeeded, want error", tc.attestation)
			}
			continue
		}
		if err != nil {
			t.Errorf("Create(attestation=%q, formats=%q): %v", tc.attestation, tc.formats, err)
			continue
		}
		ao, err := ParseAttestationObject(attObj)
		if err != nil {
			t.Errorf("ParseAttestationObject(attestation=%q, formats=%q): %v", tc.attestation, tc.formats, err)
			continue
		}
		if ao.Format != tc.wantFormat {
			t.Errorf("attestation=%q formats=%q self=%v: fmt = %q, want %q", tc.attestation, tc.formats, tc.self, ao.Format, tc.wantFormat)
		}
		var stmt struct {
			X5C [][]byte `cbor:"x5c"`
		}
		if err := cbor.Unmarshal(ao.AttStmt, &stmt); err != nil {
			t.Errorf("cbor.Unmarshal(attStmt): %v", err)
		}
		if got := len(stmt.X5C) > 0; got != tc.wantX5C {
			t.Errorf("attestation=%q formats=%q self=%v: has x5c = %v, want %v", tc.attestation, tc.formats, tc.self, got, tc.wantX5C)
		}
		if err := ao.VerifyAttestationStatement(cdJSON); err != nil {
			t.Errorf("VerifyAttestationStatement(attestation=%q, formats=%q): %v", tc.attestation, tc.formats, err)
		}
	}
}
