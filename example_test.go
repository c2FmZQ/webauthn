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

package webauthn_test

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/c2FmZQ/webauthn"
)

func Example_registration() {
	// Placeholder storage for short-lived challenges (e.g. server session store)
	// and registered credentials (e.g. user database).
	type storedCredential struct {
		ID         webauthn.Bytes
		UserHandle webauthn.Bytes
		COSEKey    webauthn.Bytes
		SignCount  uint32
		Transports []string
	}
	pendingChallenges := make(map[string][]byte)
	userCredentials := make(map[string]map[string]*storedCredential)

	// Placeholder for server <-> browser communication (e.g. HTTP/JSON).
	// In production, the server sends optionsJSON to the browser, the browser
	// calls navigator.credentials.create() (or webauthn.Create in Go WASM),
	// and sends the RegistrationResponseJSON back to the server.
	// FakeAuthenticator simulates the browser and authenticator here.
	auth, err := webauthn.NewFakeAuthenticator()
	if err != nil {
		log.Fatal(err)
	}
	auth.SetOrigin("https://example.com")
	browserCreate := func(optionsJSON []byte) (responseJSON []byte, err error) {
		var opts webauthn.AttestationOptions
		if err := json.Unmarshal(optionsJSON, &opts); err != nil {
			return nil, err
		}
		clientDataJSON, attestationObject, err := auth.Create(&opts)
		if err != nil {
			return nil, err
		}
		att, err := webauthn.ParseAttestationObject(attestationObject)
		if err != nil {
			return nil, err
		}
		credID := att.AuthData.AttestedCredentials.ID
		return json.Marshal(map[string]any{
			"id":    credID.String(),
			"rawId": credID,
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    webauthn.Bytes(clientDataJSON),
				"attestationObject": webauthn.Bytes(attestationObject),
				"transports":        []string{"internal"},
			},
		})
	}

	// Step 1 (Server): Build AttestationOptions and store the challenge.
	opts, err := webauthn.NewAttestationOptions()
	if err != nil {
		log.Fatal(err)
	}
	opts.RelyingParty = webauthn.RelyingPartyEntity{
		Name: "Example Corp",
		ID:   "example.com",
	}
	opts.User = webauthn.UserEntity{
		ID:          webauthn.Bytes("alice-uid"),
		Name:        "alice@example.com",
		DisplayName: "Alice",
	}
	// Exclude any credentials already registered for this user.
	for _, existing := range userCredentials["alice"] {
		opts.ExcludeCredentials = append(opts.ExcludeCredentials, webauthn.CredentialID{
			Type:       "public-key",
			ID:         existing.ID,
			Transports: existing.Transports,
		})
	}
	pendingChallenges["session-1"] = opts.Challenge

	optionsJSON, err := json.Marshal(opts)
	if err != nil {
		log.Fatal(err)
	}

	// Step 2 (Browser): Send optionsJSON to the browser and receive responseJSON.
	responseJSON, err := browserCreate(optionsJSON)
	if err != nil {
		log.Fatal(err)
	}

	// Step 3 (Server): Load the challenge, verify the attestation, and save the credential.
	challenge := pendingChallenges["session-1"]
	delete(pendingChallenges, "session-1")

	var resp webauthn.AttestationResponse
	if err := json.Unmarshal(responseJSON, &resp); err != nil {
		log.Fatal(err)
	}
	cred, err := webauthn.VerifyAttestation(&resp, webauthn.VerifyAttestationOptions{
		Challenge:               challenge,
		Origin:                  "https://example.com",
		RPID:                    "example.com",
		RequireUserVerification: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	if userCredentials["alice"] == nil {
		userCredentials["alice"] = make(map[string]*storedCredential)
	}
	userCredentials["alice"][cred.ID.String()] = &storedCredential{
		ID:         cred.ID,
		UserHandle: opts.User.ID,
		COSEKey:    cred.COSEKey,
		SignCount:  cred.SignCount,
		Transports: cred.Transports,
	}

	fmt.Printf("registered: userVerified=%v hasKey=%v\n", cred.UserVerified, len(cred.COSEKey) > 0)
	// Output:
	// registered: userVerified=true hasKey=true
}

func Example_authentication() {
	// Placeholder storage for short-lived challenges (e.g. server session store)
	// and previously registered credentials (e.g. user database).
	type storedCredential struct {
		ID         webauthn.Bytes
		UserHandle webauthn.Bytes
		COSEKey    webauthn.Bytes
		SignCount  uint32
		Transports []string
	}
	pendingChallenges := make(map[string][]byte)
	userCredentials := make(map[string]map[string]*storedCredential)

	// Setup: populate storage with an existing registered key for "alice".
	auth, err := webauthn.NewFakeAuthenticator()
	if err != nil {
		log.Fatal(err)
	}
	auth.SetOrigin("https://example.com")
	regOpts, err := webauthn.NewAttestationOptions()
	if err != nil {
		log.Fatal(err)
	}
	regOpts.RelyingParty = webauthn.RelyingPartyEntity{Name: "Example Corp", ID: "example.com"}
	regOpts.User = webauthn.UserEntity{ID: webauthn.Bytes("alice-uid"), Name: "alice@example.com", DisplayName: "Alice"}
	regCD, regAtt, err := auth.Create(regOpts)
	if err != nil {
		log.Fatal(err)
	}
	regCred, err := webauthn.VerifyAttestation(&webauthn.AttestationResponse{
		ClientDataJSON:    regCD,
		AttestationObject: regAtt,
	}, webauthn.VerifyAttestationOptions{
		Challenge: regOpts.Challenge,
		Origin:    "https://example.com",
		RPID:      "example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	userCredentials["alice"] = map[string]*storedCredential{
		regCred.ID.String(): {
			ID:         regCred.ID,
			UserHandle: regOpts.User.ID,
			COSEKey:    regCred.COSEKey,
			SignCount:  regCred.SignCount,
		},
	}

	// Placeholder for server <-> browser communication (e.g. HTTP/JSON).
	// In production, the server sends optionsJSON to the browser, the browser
	// calls navigator.credentials.get() (or webauthn.Get in Go WASM), and
	// sends the AuthenticationResponseJSON back to the server.
	browserGet := func(optionsJSON []byte) (responseJSON []byte, err error) {
		var opts webauthn.AssertionOptions
		if err := json.Unmarshal(optionsJSON, &opts); err != nil {
			return nil, err
		}
		id, clientDataJSON, authData, sig, userHandle, err := auth.Get(&opts)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{
			"id":    webauthn.Bytes(id).String(),
			"rawId": webauthn.Bytes(id),
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    webauthn.Bytes(clientDataJSON),
				"authenticatorData": webauthn.Bytes(authData),
				"signature":         webauthn.Bytes(sig),
				"userHandle":        webauthn.Bytes(userHandle),
			},
		})
	}

	// Step 1 (Server): Build AssertionOptions from stored credentials and save the challenge.
	opts, err := webauthn.NewAssertionOptions()
	if err != nil {
		log.Fatal(err)
	}
	opts.RPID = "example.com"
	for _, cred := range userCredentials["alice"] {
		opts.AllowCredentials = append(opts.AllowCredentials, webauthn.CredentialID{
			Type:       "public-key",
			ID:         cred.ID,
			Transports: cred.Transports,
		})
	}
	pendingChallenges["session-2"] = opts.Challenge

	optionsJSON, err := json.Marshal(opts)
	if err != nil {
		log.Fatal(err)
	}

	// Step 2 (Browser): Send optionsJSON to the browser and receive responseJSON.
	responseJSON, err := browserGet(optionsJSON)
	if err != nil {
		log.Fatal(err)
	}

	// Step 3 (Server): Load the challenge and credential, verify the assertion,
	// and update SignCount in storage.
	challenge := pendingChallenges["session-2"]
	delete(pendingChallenges, "session-2")

	var resp webauthn.AssertionResponse
	if err := json.Unmarshal(responseJSON, &resp); err != nil {
		log.Fatal(err)
	}
	stored := userCredentials["alice"][resp.RawID.String()]
	if stored == nil {
		log.Fatal("unknown credential")
	}
	res, err := webauthn.VerifyAssertion(&resp, webauthn.VerifyAssertionOptions{
		Challenge:               challenge,
		Origin:                  "https://example.com",
		RPID:                    "example.com",
		COSEKey:                 stored.COSEKey,
		CredentialID:            stored.ID,
		UserHandle:              stored.UserHandle,
		PrevSignCount:           stored.SignCount,
		RequireUserVerification: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	stored.SignCount = res.SignCount

	fmt.Printf("authenticated: userVerified=%v signCount=%d\n", res.UserVerified, stored.SignCount)
	// Output:
	// authenticated: userVerified=true signCount=1
}
