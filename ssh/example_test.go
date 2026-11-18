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

package ssh_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"

	gossh "golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/webauthn"
	"github.com/c2FmZQ/webauthn/ssh"
)

func Example_registration() {
	// Placeholder storage for pending challenges, OpenSSH authorized_keys, and
	// PEM-encoded private key handles.
	pendingChallenges := make(map[string][]byte)
	authorizedKeys := make(map[string][]byte)
	privateKeyPEMs := make(map[string][]byte)

	// Placeholder for server <-> browser communication (e.g. HTTP/JSON).
	// In production, the browser calls navigator.credentials.create() (or
	// ssh.Create in a GOOS=js GOARCH=wasm client) and sends the JSON response
	// back to the server.
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
			},
		})
	}

	// Step 1 (Server): Request an ES256 (ECDSA P-256) WebAuthn credential.
	opts, err := webauthn.NewAttestationOptions()
	if err != nil {
		log.Fatal(err)
	}
	opts.RelyingParty = webauthn.RelyingPartyEntity{Name: "Example Corp", ID: "example.com"}
	opts.User = webauthn.UserEntity{ID: webauthn.Bytes("alice-uid"), Name: "alice", DisplayName: "Alice"}
	opts.PubKeyCredParams = []webauthn.PubKeyCredParam{{Type: "public-key", Alg: webauthn.AlgES256}}
	pendingChallenges["session-1"] = opts.Challenge

	optionsJSON, err := json.Marshal(opts)
	if err != nil {
		log.Fatal(err)
	}

	// Step 2 (Browser): Create the credential and return the attestation JSON.
	responseJSON, err := browserCreate(optionsJSON)
	if err != nil {
		log.Fatal(err)
	}

	// Step 3 (Server): Verify the attestation, build an *ssh.Key, and store both
	// the OpenSSH authorized_keys entry and the encrypted PEM key handle.
	challenge := pendingChallenges["session-1"]
	delete(pendingChallenges, "session-1")

	var resp webauthn.AttestationResponse
	if err := json.Unmarshal(responseJSON, &resp); err != nil {
		log.Fatal(err)
	}
	cred, err := webauthn.VerifyAttestation(&resp, webauthn.VerifyAttestationOptions{
		Challenge: challenge,
		Origin:    "https://example.com",
		RPID:      "example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	pubKey, ok := cred.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("unexpected public key type %T", cred.PublicKey)
	}
	key, err := ssh.NewKey(cred.ID, pubKey, []byte("example.com"))
	if err != nil {
		log.Fatal(err)
	}

	authorizedKeys["alice"] = gossh.MarshalAuthorizedKey(key)
	block, err := key.MarshalPrivate("passphrase")
	if err != nil {
		log.Fatal(err)
	}
	privateKeyPEMs["alice"] = pem.EncodeToMemory(block)

	fmt.Printf("registered: type=%s hasAuthKey=%v hasPEM=%v\n",
		key.Type(), len(authorizedKeys["alice"]) > 0, len(privateKeyPEMs["alice"]) > 0)
	// Output:
	// registered: type=sk-ecdsa-sha2-nistp256@openssh.com hasAuthKey=true hasPEM=true
}

func Example_authentication() {
	// Placeholder storage for pending challenges, OpenSSH authorized_keys, and
	// PEM-encoded key handles.
	pendingChallenges := make(map[string][]byte)
	authorizedKeys := make(map[string][]byte)
	privateKeyPEMs := make(map[string][]byte)

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
	regOpts.User = webauthn.UserEntity{ID: webauthn.Bytes("alice-uid"), Name: "alice", DisplayName: "Alice"}
	regOpts.PubKeyCredParams = []webauthn.PubKeyCredParam{{Type: "public-key", Alg: webauthn.AlgES256}}
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
	regKey, err := ssh.NewKey(regCred.ID, regCred.PublicKey.(*ecdsa.PublicKey), []byte("example.com"))
	if err != nil {
		log.Fatal(err)
	}
	authorizedKeys["alice"] = gossh.MarshalAuthorizedKey(regKey)
	pemBlock, err := regKey.MarshalPrivate("passphrase")
	if err != nil {
		log.Fatal(err)
	}
	privateKeyPEMs["alice"] = pem.EncodeToMemory(pemBlock)

	// Placeholder for server <-> browser communication (e.g. HTTP/JSON or WebSocket).
	// In production, the browser loads its key via ssh.Unmarshal (or ssh.Discover)
	// and calls (*ssh.Key).Sign(rand.Reader, challenge) in GOOS=js GOARCH=wasm,
	// returning the marshaled *gossh.Signature to the server.
	browserSign := func(challenge []byte) ([]byte, error) {
		clientKey, err := ssh.Unmarshal(privateKeyPEMs["alice"], "alice", func(string) (string, error) {
			return "passphrase", nil
		})
		if err != nil {
			return nil, err
		}
		_, cd, adBytes, rawSig, _, err := auth.Get(&webauthn.AssertionOptions{
			Challenge: challenge,
			RPID:      string(clientKey.RPID()),
			AllowCredentials: []webauthn.CredentialID{
				{Type: "public-key", ID: clientKey.ID()},
			},
		})
		if err != nil {
			return nil, err
		}
		var ad webauthn.AuthenticatorData
		if err := webauthn.ParseAuthenticatorData(adBytes, &ad); err != nil {
			return nil, err
		}
		parsedCD, err := webauthn.ParseClientData(cd)
		if err != nil {
			return nil, err
		}
		var ecSig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(rawSig, &ecSig); err != nil {
			return nil, err
		}
		sshSig := gossh.Signature{
			Format: ssh.SignatureFormat,
			Blob:   gossh.Marshal(ecSig),
			Rest: gossh.Marshal(struct {
				Flags      byte
				Counter    uint32
				Origin     string
				ClientData string
				Extensions string
			}{
				Flags:      ad.Flags,
				Counter:    ad.SignCount,
				Origin:     parsedCD.Origin,
				ClientData: string(cd),
				Extensions: string(ad.Extensions),
			}),
		}
		return gossh.Marshal(sshSig), nil
	}

	// Step 1 (Server): Load the user's public key and generate a challenge.
	pub, _, _, _, err := gossh.ParseAuthorizedKey(authorizedKeys["alice"])
	if err != nil {
		log.Fatal(err)
	}
	serverKey, err := ssh.UnmarshalPublic(pub.Marshal())
	if err != nil {
		log.Fatal(err)
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		log.Fatal(err)
	}
	pendingChallenges["session-2"] = challenge

	// Step 2 (Browser): Sign the challenge and send the SSH signature back.
	sigBytes, err := browserSign(challenge)
	if err != nil {
		log.Fatal(err)
	}

	// Step 3 (Server): Load the expected challenge and verify the signature.
	wantChallenge := pendingChallenges["session-2"]
	delete(pendingChallenges, "session-2")

	var sig gossh.Signature
	if err := gossh.Unmarshal(sigBytes, &sig); err != nil {
		log.Fatal(err)
	}
	if err := serverKey.Verify(wantChallenge, &sig); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("verified: format=%s\n", sig.Format)
	// Output:
	// verified: format=webauthn-sk-ecdsa-sha2-nistp256@openssh.com
}
