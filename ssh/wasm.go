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

package ssh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/webauthn"
)

// Create registers a new ECDSA P-256 SSH security key credential via the
// browser's WebAuthn API (navigator.credentials.create).
func Create(name string, resident bool) (*Key, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	// user.id is the only field that an assertion returns (as userHandle), so
	// for a discoverable credential it carries the key name and lets Discover
	// restore it. The spec asks for an opaque value that doesn't identify the
	// user, so this is limited to resident keys, where it buys something;
	// everything else gets a random handle.
	//
	// Note that authenticators key discoverable credentials on
	// (rpID, user.id), so creating a resident key replaces any existing one
	// with the same name. Callers are expected to confirm overwrites.
	var uid []byte
	if resident && len(name) > 0 && len(name) <= 64 && isPrintableASCII(name) {
		uid = []byte(name)
	} else {
		uid = make([]byte, 32)
		if _, err := rand.Read(uid); err != nil {
			return nil, err
		}
	}
	// "required" rather than "preferred": with "preferred" an authenticator
	// that cannot store a discoverable credential silently creates a
	// non-discoverable one instead, and the caller would never learn that the
	// key it just created can't be found again by Get.
	residentKey := "discouraged"
	if resident {
		residentKey = "required"
	}
	rpName := webauthn.Hostname()
	resp, err := webauthn.Create(&webauthn.AttestationOptions{
		Challenge:   challenge,
		Attestation: "none",
		Timeout:     120000,
		RelyingParty: webauthn.RelyingPartyEntity{
			Name: rpName,
		},
		User: webauthn.UserEntity{
			ID:          uid,
			Name:        name,
			DisplayName: name,
		},
		PubKeyCredParams: []webauthn.PubKeyCredParam{
			{Type: "public-key", Alg: webauthn.AlgES256},
			{Type: "public-key", Alg: webauthn.AlgRS256}, // Included to avoid browser console warnings
		},
		AuthenticatorSelection: webauthn.AuthenticatorSelection{
			ResidentKey:        residentKey,
			RequireResidentKey: resident,
			UserVerification:   "preferred",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("WebAuthnCreate: %w", err)
	}
	// The credential is created without an explicit RP ID, which then
	// defaults to the origin's effective domain.
	cred, err := webauthn.VerifyAttestation(resp, webauthn.VerifyAttestationOptions{
		Challenge: challenge,
		Origin:    webauthn.Origin(),
		RPID:      rpName,
	})
	if err != nil {
		return nil, fmt.Errorf("VerifyAttestation: %w", err)
	}
	ecpk, ok := cred.PublicKey.(*ecdsa.PublicKey)
	if !ok || ecpk.Curve != elliptic.P256() {
		return nil, fmt.Errorf("PublicKey: unexpected public key type %T", cred.PublicKey)
	}
	return &Key{
		typ:    KeyType,
		id:     cred.ID,
		pubKey: ecpk,
		rpID:   []byte(rpName),
	}, nil
}

// Discover discovers a resident key on an authenticator by performing two
// assertions to recover and verify the ECDSA P-256 public key.
// It returns the Key, the username from userHandle (if available), and any error.
func Discover(promptTouch func(string)) (*Key, string, error) {
	challenge1 := make([]byte, 32)
	if _, err := rand.Read(challenge1); err != nil {
		return nil, "", err
	}
	if promptTouch != nil {
		promptTouch("Touch your security key to discover resident keys...\n")
	}
	resp1, err := webauthn.Get(&webauthn.AssertionOptions{
		Challenge:        challenge1,
		Timeout:          120000,
		UserVerification: "preferred",
	})
	if err != nil {
		return nil, "", fmt.Errorf("WebAuthnGet: %w", err)
	}
	origin := webauthn.Origin()
	if _, err := webauthn.VerifyClientData(resp1.ClientDataJSON, "webauthn.get", challenge1, origin); err != nil {
		return nil, "", fmt.Errorf("assertion 1: %w", err)
	}
	rpID := []byte(webauthn.Hostname())
	rpHash := sha256.Sum256(rpID)
	var ad1 webauthn.AuthenticatorData
	if err := webauthn.ParseAuthenticatorData(resp1.AuthenticatorData, &ad1); err != nil {
		return nil, "", fmt.Errorf("assertion 1 ParseAuthenticatorData: %w", err)
	}
	if !bytes.Equal(ad1.RPIDHash, rpHash[:]) {
		return nil, "", errors.New("assertion 1: rpIdHash mismatch")
	}
	if !ad1.UserPresence || ad1.AttestedCredentialData {
		return nil, "", errors.New("assertion 1: invalid authenticatorData flags")
	}

	challenge2 := make([]byte, 32)
	if _, err := rand.Read(challenge2); err != nil {
		return nil, "", err
	}
	if promptTouch != nil {
		promptTouch("Touch your security key again to verify public key...\n")
	}
	resp2, err := webauthn.Get(&webauthn.AssertionOptions{
		Challenge:        challenge2,
		Timeout:          120000,
		UserVerification: "preferred",
		AllowCredentials: []webauthn.CredentialID{
			{Type: "public-key", ID: resp1.RawID},
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("WebAuthnGet: %w", err)
	}
	if _, err := webauthn.VerifyClientData(resp2.ClientDataJSON, "webauthn.get", challenge2, origin); err != nil {
		return nil, "", fmt.Errorf("assertion 2: %w", err)
	}
	var ad2 webauthn.AuthenticatorData
	if err := webauthn.ParseAuthenticatorData(resp2.AuthenticatorData, &ad2); err != nil {
		return nil, "", fmt.Errorf("assertion 2 ParseAuthenticatorData: %w", err)
	}
	if !bytes.Equal(ad2.RPIDHash, rpHash[:]) {
		return nil, "", errors.New("assertion 2: rpIdHash mismatch")
	}
	if !ad2.UserPresence || ad2.AttestedCredentialData {
		return nil, "", errors.New("assertion 2: invalid authenticatorData flags")
	}
	if !bytes.Equal(resp1.RawID, resp2.RawID) {
		return nil, "", errors.New("the authenticator returned a different credential for the second assertion")
	}

	pk, err := webauthn.RecoverPublicKey(resp1.AuthenticatorData, resp1.ClientDataJSON, resp1.Signature, resp2.AuthenticatorData, resp2.ClientDataJSON, resp2.Signature)
	if err != nil {
		// An assertion with an empty allow list can return any discoverable
		// credential for this origin, including one that isn't an ES256 key.
		// Those fail while parsing the ECDSA signature, which is worth
		// translating into something the user can act on.
		var structErr asn1.StructuralError
		var syntaxErr asn1.SyntaxError
		if errors.As(err, &structErr) || errors.As(err, &syntaxErr) {
			return nil, "", errors.New("the selected credential is not an ECDSA P-256 key; only ecdsa-sk keys can be discovered")
		}
		return nil, "", fmt.Errorf("RecoverPublicKey: %w", err)
	}

	// The user handle holds the key name when the credential was created by
	// Create. Anything else is treated as not having a name.
	var userName string
	if cand := strings.TrimSpace(string(resp1.UserHandle)); cand != "" && isPrintableASCII(cand) {
		userName = cand
	}

	key := &Key{
		typ:    KeyType,
		id:     resp1.RawID,
		pubKey: pk,
		rpID:   rpID,
	}
	return key, userName, nil
}

// Sign produces an OpenSSH webauthn-sk-ecdsa-sha2-nistp256@openssh.com
// signature over data using the browser's WebAuthn API (navigator.credentials.get).
func (k *Key) Sign(_ io.Reader, data []byte) (*gossh.Signature, error) {
	if k == nil || k.pubKey == nil {
		return nil, errors.New("ssh: nil key")
	}
	opts := &webauthn.AssertionOptions{
		Challenge:        data,
		Timeout:          120000,
		RPID:             string(k.rpID),
		UserVerification: "preferred",
	}
	if len(k.id) > 0 {
		opts.AllowCredentials = []webauthn.CredentialID{
			{Type: "public-key", ID: k.id},
		}
	}
	resp, err := webauthn.Get(opts)
	if err != nil {
		return nil, fmt.Errorf("WebAuthnGet: %w", err)
	}
	if len(k.id) > 0 && !bytes.Equal(resp.RawID, k.id) {
		return nil, errors.New("authenticator returned unexpected credential ID")
	}
	var ad webauthn.AuthenticatorData
	if err := webauthn.ParseAuthenticatorData(resp.AuthenticatorData, &ad); err != nil {
		return nil, fmt.Errorf("ParseAuthenticatorData: %w", err)
	}
	rpHash := sha256.Sum256(k.rpID)
	if !bytes.Equal(ad.RPIDHash, rpHash[:]) {
		return nil, fmt.Errorf("rpIdHash mismatch (key application %q does not match current origin)", k.rpID)
	}
	if !ad.UserPresence || ad.AttestedCredentialData {
		return nil, errors.New("invalid authenticatorData flags in assertion")
	}
	cd, err := webauthn.VerifyClientData(resp.ClientDataJSON, "webauthn.get", data, webauthn.Origin())
	if err != nil {
		return nil, err
	}

	var sig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(resp.Signature, &sig)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("signature: unexpected trailing bytes")
	}
	n := k.pubKey.Curve.Params().N
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.R.Cmp(n) >= 0 || sig.S.Sign() <= 0 || sig.S.Cmp(n) >= 0 {
		return nil, errors.New("signature: value out of range")
	}

	sshSig := &gossh.Signature{
		Format: SignatureFormat,
		Blob:   gossh.Marshal(sig),
		Rest: gossh.Marshal(struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}{
			Flags:      ad.Flags,
			Counter:    ad.SignCount,
			Origin:     cd.Origin,
			ClientData: string(resp.ClientDataJSON),
			Extensions: string(ad.Extensions),
		}),
	}
	if err := k.Verify(data, sshSig); err != nil {
		return nil, fmt.Errorf("Verify: %w", err)
	}
	return sshSig, nil
}
