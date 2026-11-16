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

// Package ssh implements OpenSSH FIDO2/WebAuthn ECDSA P-256 security keys
// (sk-ecdsa-sha2-nistp256@openssh.com) and browser WebAuthn SSH signatures
// (webauthn-sk-ecdsa-sha2-nistp256@openssh.com) per OpenSSH PROTOCOL.u2f.
package ssh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
	gossh "golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/webauthn"
)

const (
	// KeyType is the OpenSSH public key identifier for ECDSA P-256 security keys.
	KeyType = gossh.KeyAlgoSKECDSA256
	// CertType is the OpenSSH certificate identifier for ECDSA P-256 security keys.
	CertType = gossh.CertAlgoSKECDSA256v01
	// SignatureFormat is the OpenSSH signature format identifier for browser
	// WebAuthn assertions with an ECDSA P-256 security key.
	SignatureFormat = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
)

const (
	// minIter is the minimum number of PBKDF2 iterations accepted when
	// decrypting keys.
	minIter = 1000
	// defaultIter is the number of PBKDF2 iterations used to encrypt keys.
	defaultIter = 100000
	// maxIter is the maximum number of PBKDF2 iterations accepted when
	// decrypting keys. It protects against crafted files that would hang
	// the app.
	maxIter = 1000000
)

// isPrintableASCII reports whether s consists only of printable ASCII
// characters. It deliberately works a byte at a time so that any non-ASCII
// byte, including a fragment of a truncated multi-byte rune, is rejected.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

func marshalP256Point(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 65)
	out[0] = 0x04
	pub.X.FillBytes(out[1:33])
	pub.Y.FillBytes(out[33:65])
	return out
}

func unmarshalP256Point(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 65 || b[0] != 0x04 {
		return nil, errors.New("invalid public key")
	}
	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, errors.New("invalid public key")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(b[1:33]),
		Y:     new(big.Int).SetBytes(b[33:65]),
	}, nil
}

// Key represents an OpenSSH ECDSA P-256 WebAuthn security key.
type Key struct {
	typ    string
	id     []byte
	pubKey *ecdsa.PublicKey
	rpID   []byte
}

// NewKey constructs a Key from a credential ID, P-256 public key, and Relying
// Party ID (application string).
func NewKey(id []byte, pubKey *ecdsa.PublicKey, rpID []byte) (*Key, error) {
	if pubKey == nil || pubKey.Curve != elliptic.P256() ||
		pubKey.X == nil || pubKey.Y == nil ||
		pubKey.X.Sign() < 0 || pubKey.Y.Sign() < 0 ||
		pubKey.X.BitLen() > 256 || pubKey.Y.BitLen() > 256 {
		return nil, errors.New("invalid P-256 public key")
	}
	cleanPub, err := unmarshalP256Point(marshalP256Point(pubKey))
	if err != nil {
		return nil, err
	}
	return &Key{
		typ:    KeyType,
		id:     bytes.Clone(id),
		pubKey: cleanPub,
		rpID:   bytes.Clone(rpID),
	}, nil
}

// ID returns the credential ID associated with the key.
func (k *Key) ID() []byte {
	return bytes.Clone(k.id)
}

// RPID returns the Relying Party ID (OpenSSH application string) of the key.
func (k *Key) RPID() []byte {
	return bytes.Clone(k.rpID)
}

// Unmarshal parses a PEM-encoded WEBAUTHN KEY or WEBAUTHN ENCRYPTED KEY block.
func Unmarshal(priv []byte, name string, rp func(string) (string, error)) (*Key, error) {
	if !bytes.HasPrefix(priv, []byte("-----BEGIN WEBAUTHN ")) {
		return nil, errors.New("unexpected key format")
	}
	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	str := cryptobyte.String(block.Bytes)
	var ver uint8
	if !str.ReadUint8(&ver) {
		return nil, webauthn.ErrTooShort
	}
	if ver != 1 && ver != 2 {
		return nil, fmt.Errorf("unexpected version %d", ver)
	}
	var pubBytes cryptobyte.String
	if !str.ReadUint16LengthPrefixed(&pubBytes) {
		return nil, webauthn.ErrTooShort
	}
	key, err := UnmarshalPublic(pubBytes)
	if err != nil {
		return nil, err
	}

	var privBytes cryptobyte.String
	if !str.ReadUint16LengthPrefixed(&privBytes) || !str.Empty() {
		return nil, webauthn.ErrTooShort
	}

	switch block.Type {
	case "WEBAUTHN KEY":
		key.id = bytes.Clone([]byte(privBytes))

	case "WEBAUTHN ENCRYPTED KEY":
		salt := make([]byte, 16)
		if !privBytes.ReadBytes(&salt, 16) {
			return nil, webauthn.ErrTooShort
		}
		var numIter uint32
		if !privBytes.ReadUint32(&numIter) {
			return nil, webauthn.ErrTooShort
		}
		if numIter < minIter || numIter > maxIter {
			return nil, fmt.Errorf("invalid iteration count %d", numIter)
		}
		if rp == nil {
			return nil, errors.New("passphrase required")
		}
		passphrase, err := rp("Enter the passphrase for " + name + ": ")
		if err != nil {
			return nil, err
		}
		dk := pbkdf2.Key([]byte(passphrase), salt, int(numIter), 32, sha256.New)
		cBlock, err := aes.NewCipher(dk)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(cBlock)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, gcm.NonceSize())
		if !privBytes.ReadBytes(&nonce, len(nonce)) {
			return nil, webauthn.ErrTooShort
		}
		var aad []byte
		if ver >= 2 {
			aad = []byte(pubBytes)
		}
		keyID, err := gcm.Open(nil, nonce, []byte(privBytes), aad)
		if err != nil {
			return nil, errors.New("invalid passphrase")
		}
		key.id = keyID
	default:
		return nil, errors.New("invalid webauthn key ID")
	}
	return key, nil
}

// UnmarshalPublic parses an OpenSSH wire-encoded sk-ecdsa-sha2-nistp256@openssh.com
// (or legacy webauthn-sk-ecdsa-sha2-nistp256@openssh.com) public key blob.
func UnmarshalPublic(pub []byte) (*Key, error) {
	var data struct {
		Name        string
		ID          string
		Key         []byte
		Application string
	}
	if err := gossh.Unmarshal(pub, &data); err != nil {
		return nil, fmt.Errorf("Unmarshal: %w", err)
	}
	if (data.Name != KeyType && data.Name != SignatureFormat) || data.ID != "nistp256" {
		return nil, fmt.Errorf("unexpected key type %q", data.Name)
	}
	pubKey, err := unmarshalP256Point(data.Key)
	if err != nil {
		return nil, err
	}
	return &Key{
		typ:    KeyType,
		rpID:   []byte(data.Application),
		pubKey: pubKey,
	}, nil
}

// MarshalPrivate serializes the key into a WEBAUTHN KEY (unencrypted) or
// WEBAUTHN ENCRYPTED KEY (AES-256-GCM encrypted with PBKDF2-HMAC-SHA256) PEM
// block.
func (k *Key) MarshalPrivate(passphrase string) (*pem.Block, error) {
	pubBytes := k.Marshal()
	if passphrase == "" {
		buf := cryptobyte.NewBuilder([]byte{2})
		buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(pubBytes)
		})
		buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(k.id)
		})
		data, err := buf.Bytes()
		if err != nil {
			return nil, err
		}
		return &pem.Block{
			Type:  "WEBAUTHN KEY",
			Bytes: data,
		}, nil
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	numIter := defaultIter
	dk := pbkdf2.Key([]byte(passphrase), salt, numIter, 32, sha256.New)
	cBlock, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(cBlock)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	encID := gcm.Seal(nonce, nonce, k.id, pubBytes)
	buf := cryptobyte.NewBuilder([]byte{2})
	buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(pubBytes)
	})
	buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(salt)
		b.AddUint32(uint32(numIter))
		b.AddBytes(encID)
	})
	data, err := buf.Bytes()
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:  "WEBAUTHN ENCRYPTED KEY",
		Bytes: data,
	}, nil
}

// Type returns the OpenSSH public key algorithm identifier
// ("sk-ecdsa-sha2-nistp256@openssh.com").
func (k *Key) Type() string {
	return k.typ
}

// Marshal serializes the public key in OpenSSH wire format.
func (k *Key) Marshal() []byte {
	w := struct {
		Name        string
		ID          string
		Key         []byte
		Application string
	}{
		k.Type(),
		"nistp256",
		marshalP256Point(k.pubKey),
		string(k.rpID),
	}
	return gossh.Marshal(&w)
}

// Verify verifies an OpenSSH signature in either sk-ecdsa-sha2-nistp256@openssh.com
// or webauthn-sk-ecdsa-sha2-nistp256@openssh.com format per OpenSSH PROTOCOL.u2f.
func (k *Key) Verify(data []byte, sig *gossh.Signature) error {
	if k == nil || k.pubKey == nil || sig == nil {
		return errors.New("ssh: nil key or signature")
	}
	var ecSig struct {
		R, S *big.Int
	}
	if err := gossh.Unmarshal(sig.Blob, &ecSig); err != nil {
		return err
	}
	n := k.pubKey.Curve.Params().N
	if ecSig.R == nil || ecSig.S == nil || ecSig.R.Sign() <= 0 || ecSig.R.Cmp(n) >= 0 || ecSig.S.Sign() <= 0 || ecSig.S.Cmp(n) >= 0 {
		return errors.New("ssh: signature value out of range")
	}

	appHash := sha256.Sum256(k.rpID)
	var signed cryptobyte.Builder
	signed.AddBytes(appHash[:])

	switch sig.Format {
	case KeyType:
		var extra struct {
			Flags   byte
			Counter uint32
		}
		if err := gossh.Unmarshal(sig.Rest, &extra); err != nil {
			return err
		}
		if (extra.Flags & webauthn.FlagUserPresent) == 0 {
			return errors.New("ssh: missing user presence flag")
		}
		dataHash := sha256.Sum256(data)
		signed.AddUint8(extra.Flags)
		signed.AddUint32(extra.Counter)
		signed.AddBytes(dataHash[:])

	case SignatureFormat:
		var extra struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}
		if err := gossh.Unmarshal(sig.Rest, &extra); err != nil {
			return err
		}
		if (extra.Flags & webauthn.FlagUserPresent) == 0 {
			return errors.New("ssh: missing user presence flag")
		}
		if (extra.Flags & webauthn.FlagAttestedCredentialData) != 0 {
			return errors.New("ssh: unexpected attested credential data flag in assertion")
		}
		if ((extra.Flags & webauthn.FlagExtensionData) != 0) != (len(extra.Extensions) != 0) {
			return errors.New("ssh: extension data flag does not match extensions length")
		}
		if (!strings.HasPrefix(extra.Origin, "https://") && !strings.HasPrefix(extra.Origin, "http://")) || strings.IndexByte(extra.Origin, '"') != -1 {
			return errors.New("ssh: invalid origin")
		}
		// Match OpenSSH webauthn_check_prepare_hash prefix check in ssh-ecdsa-sk.c.
		expectedPrefix := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"%s"`,
			base64.RawURLEncoding.EncodeToString(data), extra.Origin)
		if len(extra.ClientData) <= len(expectedPrefix) || !strings.HasPrefix(extra.ClientData, expectedPrefix) ||
			(extra.ClientData[len(expectedPrefix)] != '}' && extra.ClientData[len(expectedPrefix)] != ',') {
			return errors.New("ssh: clientData does not match expected WebAuthn format")
		}
		if _, err := webauthn.VerifyClientData([]byte(extra.ClientData), "webauthn.get", data, extra.Origin); err != nil {
			return err
		}
		clientDataHash := sha256.Sum256([]byte(extra.ClientData))
		signed.AddUint8(extra.Flags)
		signed.AddUint32(extra.Counter)
		signed.AddBytes([]byte(extra.Extensions))
		signed.AddBytes(clientDataHash[:])

	default:
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}

	msg, err := signed.Bytes()
	if err != nil {
		return err
	}
	hash := sha256.Sum256(msg)
	if !ecdsa.Verify(k.pubKey, hash[:], ecSig.R, ecSig.S) {
		return errors.New("ssh: signature did not verify")
	}
	return nil
}

// PublicKey returns the gossh.PublicKey for k.
func (k *Key) PublicKey() gossh.PublicKey {
	return k
}
