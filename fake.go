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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
)

// FakeAuthenticator mimics the behavior of a WebAuthn authenticator for testing.
type FakeAuthenticator struct {
	keys            map[string]fakeAuthKey
	rpIDHash        []byte
	origin          string
	selfAttestation bool
}

type fakeAuthKey struct {
	id         []byte
	uid        []byte
	rpIDHash   []byte
	rk         bool
	alg        int
	privateKey crypto.Signer
	signCount  uint32
}

// NewFakeAuthenticator returns a new FakeAuthenticator for testing.
func NewFakeAuthenticator() (*FakeAuthenticator, error) {
	return &FakeAuthenticator{
		keys:   make(map[string]fakeAuthKey),
		origin: "https://example.com/",
	}, nil
}

// SetOrigin sets the origin reported in clientDataJSON by the fake authenticator.
func (a *FakeAuthenticator) SetOrigin(orig string) {
	a.origin = orig
}

// SetSelfAttestation selects the kind of "packed" attestation statement that
// the fake authenticator produces: self attestation (signed with the
// credential private key) when self is true, or basic attestation with an x5c
// attestation certificate when it is false (the default).
func (a *FakeAuthenticator) SetSelfAttestation(self bool) {
	a.selfAttestation = self
}

// attestationFormat returns the attestation statement format to use for
// options, like a client and authenticator would choose it.
//
// options.Attestation is the attestation conveyance preference: with "none"
// (or empty), the attestation statement is always "none". Otherwise, the
// format is the first supported one in options.AttestationFormats ("packed",
// "fido-u2f", or "none"), or "packed" when there is none.
func attestationFormat(options *AttestationOptions) (string, error) {
	switch options.Attestation {
	case "", "none":
		return "none", nil
	case "indirect", "direct", "enterprise":
	default:
		return "", fmt.Errorf("invalid attestation conveyance preference %q", options.Attestation)
	}
	for _, f := range options.AttestationFormats {
		switch f {
		case "none", "packed", "fido-u2f":
			return f, nil
		}
	}
	return "packed", nil
}

// Create mimics the behavior of the WebAuthn navigator.credentials.create() call.
//
// The attestation statement format is selected with options.Attestation and
// options.AttestationFormats. To get a "packed" or "fido-u2f" attestation, set
// Attestation to "direct" and AttestationFormats to the desired format. See
// also SetSelfAttestation.
func (a *FakeAuthenticator) Create(options *AttestationOptions) (clientDataJSON, attestationObject []byte, err error) {
	if len(options.PubKeyCredParams) == 0 {
		return nil, nil, errors.New("empty options.PubKeyCredParams")
	}
	attFormat, err := attestationFormat(options)
	if err != nil {
		return nil, nil, err
	}
	var authKey fakeAuthKey
	authKey.alg = options.PubKeyCredParams[0].Alg
	var coseKey []byte

	switch authKey.alg {
	case AlgES256:
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if coseKey, err = MarshalCOSEKey(&privKey.PublicKey); err != nil {
			return nil, nil, err
		}
		authKey.privateKey = privKey

	case AlgES384:
		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if coseKey, err = MarshalCOSEKey(&privKey.PublicKey); err != nil {
			return nil, nil, err
		}
		authKey.privateKey = privKey

	case AlgES512:
		privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if coseKey, err = MarshalCOSEKey(&privKey.PublicKey); err != nil {
			return nil, nil, err
		}
		authKey.privateKey = privKey

	case AlgEdDSA:
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if coseKey, err = MarshalCOSEKey(pubKey); err != nil {
			return nil, nil, err
		}
		authKey.privateKey = privKey

	case AlgRS256, AlgRS384, AlgRS512, AlgPS256, AlgPS384, AlgPS512:
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		if coseKey, err = MarshalCOSEKeyWithAlg(&privKey.PublicKey, authKey.alg); err != nil {
			return nil, nil, err
		}
		authKey.privateKey = privKey

	default:
		return nil, nil, errors.New("unexpected options.PubKeyCredParams alg")
	}

	cd := ClientData{
		Type:      "webauthn.create",
		Challenge: base64.RawURLEncoding.EncodeToString(options.Challenge),
		Origin:    a.origin,
	}
	if clientDataJSON, err = json.Marshal(cd); err != nil {
		return nil, nil, err
	}

	authKey.uid = bytes.Clone(options.User.ID)
	authKey.rk = options.AuthenticatorSelection.ResidentKey == "preferred" ||
		options.AuthenticatorSelection.ResidentKey == "required" ||
		options.AuthenticatorSelection.RequireResidentKey

	authKey.id = make([]byte, 32)
	if _, err := rand.Read(authKey.id); err != nil {
		return nil, nil, err
	}
	rpIDHash := sha256.Sum256([]byte(options.RelyingParty.ID))
	a.rpIDHash = rpIDHash[:]
	authKey.rpIDHash = rpIDHash[:]

	var aaguid [16]byte
	if attFormat == "packed" && !a.selfAttestation {
		// Use a non-zero synthetic AAGUID for packed attestation tests.
		for i := range aaguid {
			aaguid[i] = byte(i + 1)
		}
	}

	authData, err := authKey.makeAuthData(authKey.rpIDHash, aaguid[:], coseKey)
	if err != nil {
		return nil, nil, err
	}

	att, err := buildAttestation(attFormat, a.selfAttestation, authKey, aaguid[:], authData, clientDataJSON)
	if err != nil {
		return nil, nil, err
	}
	if attestationObject, err = cbor.Marshal(att); err != nil {
		return nil, nil, err
	}
	a.keys[base64.RawURLEncoding.EncodeToString(authKey.id)] = authKey
	return
}

func buildAttestation(format string, self bool, authKey fakeAuthKey, aaguid, authData, clientDataJSON []byte) (*Attestation, error) {
	if format == "packed" && self {
		format = "packed-self"
	}
	switch format {
	case "none":
		emptyMap, _ := cbor.Marshal(map[string]any{})
		return &Attestation{
			Format:      "none",
			AttStmt:     cbor.RawMessage(emptyMap),
			RawAuthData: authData,
		}, nil

	case "packed-self":
		sig, err := signAssertionBytes(authKey, authData, clientDataJSON)
		if err != nil {
			return nil, err
		}
		stmtBytes, err := cbor.Marshal(map[string]any{
			"alg": authKey.alg,
			"sig": sig,
		})
		if err != nil {
			return nil, err
		}
		return &Attestation{
			Format:      "packed",
			AttStmt:     cbor.RawMessage(stmtBytes),
			RawAuthData: authData,
		}, nil

	case "packed":
		attPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		aaguidASN1, err := asn1.Marshal(aaguid)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Country:            []string{"US"},
				Organization:       []string{"FakeAuthenticator"},
				OrganizationalUnit: []string{"Authenticator Attestation"},
				CommonName:         "Fake Packed Attestation",
			},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			ExtraExtensions: []pkix.Extension{
				{
					Id:       oidFIDOGenCEAAGUID,
					Critical: false,
					Value:    aaguidASN1,
				},
			},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &attPriv.PublicKey, attPriv)
		if err != nil {
			return nil, err
		}
		signed := signedBytes(authData, clientDataJSON)
		h := sha256.Sum256(signed)
		sig, err := ecdsa.SignASN1(rand.Reader, attPriv, h[:])
		if err != nil {
			return nil, err
		}
		stmtBytes, err := cbor.Marshal(map[string]any{
			"alg": AlgES256,
			"sig": sig,
			"x5c": [][]byte{certDER},
		})
		if err != nil {
			return nil, err
		}
		return &Attestation{
			Format:      "packed",
			AttStmt:     cbor.RawMessage(stmtBytes),
			RawAuthData: authData,
		}, nil

	case "fido-u2f":
		ecPriv, ok := authKey.privateKey.(*ecdsa.PrivateKey)
		if !ok || ecPriv.Curve != elliptic.P256() {
			return nil, errors.New("fido-u2f requires ES256 P-256 credential key")
		}
		attPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Fake U2F Attestation"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &attPriv.PublicKey, attPriv)
		if err != nil {
			return nil, err
		}
		var publicKeyU2F [65]byte
		publicKeyU2F[0] = 0x04
		ecPriv.PublicKey.X.FillBytes(publicKeyU2F[1:33])
		ecPriv.PublicKey.Y.FillBytes(publicKeyU2F[33:65])

		clientDataHash := sha256.Sum256(clientDataJSON)
		var verificationData bytes.Buffer
		verificationData.WriteByte(0x00)
		verificationData.Write(authData[:32])
		verificationData.Write(clientDataHash[:])
		verificationData.Write(authKey.id)
		verificationData.Write(publicKeyU2F[:])

		h := sha256.Sum256(verificationData.Bytes())
		sig, err := ecdsa.SignASN1(rand.Reader, attPriv, h[:])
		if err != nil {
			return nil, err
		}
		stmtBytes, err := cbor.Marshal(map[string]any{
			"sig": sig,
			"x5c": [][]byte{certDER},
		})
		if err != nil {
			return nil, err
		}
		return &Attestation{
			Format:      "fido-u2f",
			AttStmt:     cbor.RawMessage(stmtBytes),
			RawAuthData: authData,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported attestation format %q", format)
	}
}

// Get mimics the behavior of the WebAuthn navigator.credentials.get() call.
func (a *FakeAuthenticator) Get(options *AssertionOptions) (id, clientDataJSON, authData, signature, userHandle []byte, err error) {
	var authKey fakeAuthKey
	var mapKey string
	if len(options.AllowCredentials) > 0 {
		for _, k := range options.AllowCredentials {
			mk := base64.RawURLEncoding.EncodeToString(k.ID)
			if ak, ok := a.keys[mk]; ok {
				id = bytes.Clone(k.ID)
				authKey = ak
				mapKey = mk
				break
			}
		}
	} else {
		for kid, key := range a.keys {
			if key.rk {
				id, _ = base64.RawURLEncoding.DecodeString(kid)
				authKey = key
				userHandle = bytes.Clone(key.uid)
				mapKey = kid
				break
			}
		}
	}
	if len(id) == 0 {
		err = errors.New("key not found")
		return
	}
	cd := ClientData{
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(options.Challenge),
		Origin:    a.origin,
	}
	if clientDataJSON, err = json.Marshal(cd); err != nil {
		return
	}
	authKey.signCount++
	a.keys[mapKey] = authKey
	rpHash := authKey.rpIDHash
	if len(rpHash) == 0 {
		rpHash = a.rpIDHash
	}
	if authData, err = authKey.makeAuthData(rpHash, nil, nil); err != nil {
		return
	}
	signature, err = signAssertionBytes(authKey, authData, clientDataJSON)
	return
}

// ResetSignCount resets the signature counter of all the keys, like a cloned
// authenticator would.
func (a *FakeAuthenticator) ResetSignCount() {
	for k, v := range a.keys {
		v.signCount = 0
		a.keys[k] = v
	}
}

// RotateKeys replaces all private keys in the fake authenticator so subsequent
// signatures will fail verification against the previously attested public keys.
func (a *FakeAuthenticator) RotateKeys() error {
	for k, v := range a.keys {
		switch v.alg {
		case AlgEdDSA:
			_, privKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			v.privateKey = privKey
		case AlgES384:
			privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				return err
			}
			v.privateKey = privKey
		case AlgES512:
			privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				return err
			}
			v.privateKey = privKey
		case AlgRS256, AlgRS384, AlgRS512, AlgPS256, AlgPS384, AlgPS512:
			privKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return err
			}
			v.privateKey = privKey
		default:
			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			v.privateKey = privKey
		}
		a.keys[k] = v
	}
	return nil
}

func (k *fakeAuthKey) makeAuthData(rpIDHash, aaguid, coseKey []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(rpIDHash)

	var bits uint8
	bits |= FlagUserPresent
	bits |= FlagUserVerified
	if coseKey != nil {
		bits |= FlagAttestedCredentialData
	}
	buf.WriteByte(bits)
	binary.Write(&buf, binary.BigEndian, k.signCount)

	if coseKey != nil {
		if len(aaguid) == 16 {
			buf.Write(aaguid)
		} else {
			var zero [16]byte
			buf.Write(zero[:])
		}
		binary.Write(&buf, binary.BigEndian, uint16(len(k.id)))
		buf.Write(k.id)
		buf.Write(coseKey)
	}
	return buf.Bytes(), nil
}

func signAssertionBytes(authKey fakeAuthKey, authData, clientDataJSON []byte) ([]byte, error) {
	signed := signedBytes(authData, clientDataJSON)
	switch authKey.alg {
	case AlgEdDSA:
		return authKey.privateKey.Sign(rand.Reader, signed, crypto.Hash(0))
	case AlgES384, AlgRS384:
		h := sha512.Sum384(signed)
		return authKey.privateKey.Sign(rand.Reader, h[:], crypto.SHA384)
	case AlgES512, AlgRS512:
		h := sha512.Sum512(signed)
		return authKey.privateKey.Sign(rand.Reader, h[:], crypto.SHA512)
	case AlgPS256:
		h := sha256.Sum256(signed)
		return authKey.privateKey.Sign(rand.Reader, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case AlgPS384:
		h := sha512.Sum384(signed)
		return authKey.privateKey.Sign(rand.Reader, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384})
	case AlgPS512:
		h := sha512.Sum512(signed)
		return authKey.privateKey.Sign(rand.Reader, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512})
	default:
		h := sha256.Sum256(signed)
		return authKey.privateKey.Sign(rand.Reader, h[:], crypto.SHA256)
	}
}
