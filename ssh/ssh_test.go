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

package ssh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
	gossh "golang.org/x/crypto/ssh"
)

func TestIsPrintableASCII(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", true},
		{"default", true},
		{"my key 1", true},
		{"~!@#$%^&*()", true},
		{"caf\xc3\xa9", false},
		{"caf\xc3", false}, // truncated multi-byte rune
		{"tab\there", false},
		{"nl\n", false},
		{"nul\x00", false},
		{"del\x7f", false},
	} {
		if got := isPrintableASCII(tc.in); got != tc.want {
			t.Errorf("isPrintableASCII(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestKeyMarshalUnmarshal(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	orig, err := NewKey([]byte("credential-id-12345"), &priv.PublicKey, []byte("ssh:default"))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if !bytes.Equal(orig.ID(), []byte("credential-id-12345")) || !bytes.Equal(orig.RPID(), []byte("ssh:default")) {
		t.Errorf("orig ID/RPID mismatch")
	}
	if orig.PublicKey() != orig {
		t.Errorf("orig.PublicKey() != orig")
	}
	if _, err := NewKey(nil, nil, nil); err == nil {
		t.Error("NewKey(nil) succeeded, want error")
	}
	if _, err := NewKey(nil, &ecdsa.PublicKey{Curve: elliptic.P256()}, nil); err == nil {
		t.Error("NewKey(nil X/Y) succeeded, want error")
	}
	if _, err := NewKey(nil, &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Neg(priv.X), Y: priv.Y}, nil); err == nil {
		t.Error("NewKey(negative X) succeeded, want error")
	}
	if _, err := NewKey(nil, &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Lsh(big.NewInt(1), 300), Y: priv.Y}, nil); err == nil {
		t.Error("NewKey(oversized X) succeeded, want error")
	}
	if _, err := NewKey(nil, &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}, nil); err == nil {
		t.Error("NewKey(off-curve) succeeded, want error")
	}
	passphrase := "secret-passphrase"
	rp := func(string) (string, error) { return passphrase, nil }

	// Round-trip without passphrase
	block, err := orig.MarshalPrivate("")
	if err != nil {
		t.Fatalf("MarshalPrivate(\"\"): %v", err)
	}
	got, err := Unmarshal(pem.EncodeToMemory(block), "test", rp)
	if err != nil {
		t.Fatalf("Unmarshal(unencrypted): %v", err)
	}
	if got.typ != orig.typ || !bytes.Equal(got.rpID, orig.rpID) || !bytes.Equal(got.id, orig.id) {
		t.Errorf("Unmarshal(unencrypted) mismatch: got %+v, want %+v", got, orig)
	}

	// Round-trip with passphrase
	block, err = orig.MarshalPrivate(passphrase)
	if err != nil {
		t.Fatalf("MarshalPrivate(passphrase): %v", err)
	}
	got, err = Unmarshal(pem.EncodeToMemory(block), "test", rp)
	if err != nil {
		t.Fatalf("Unmarshal(passphrase): %v", err)
	}
	if got.typ != orig.typ || !bytes.Equal(got.rpID, orig.rpID) || !bytes.Equal(got.id, orig.id) {
		t.Errorf("Unmarshal(passphrase) mismatch: got %+v, want %+v", got, orig)
	}

	// Tampered pubBytes must fail AES-GCM authentication (AAD binding)
	pubLen := int(binary.BigEndian.Uint16(block.Bytes[1:3]))
	tampered := append([]byte(nil), block.Bytes...)
	tampered[1+2+pubLen-1] ^= 0x01
	tamperedPEM := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: tampered})
	if _, err := Unmarshal(tamperedPEM, "test", rp); err == nil {
		t.Error("Unmarshal with tampered pubBytes succeeded; want AAD failure")
	}

	// Downgrading a v2 key to v1 must also fail AES-GCM authentication
	downgraded := append([]byte(nil), block.Bytes...)
	downgraded[0] = 1
	downgradedPEM := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: downgraded})
	if _, err := Unmarshal(downgradedPEM, "test", rp); err == nil {
		t.Error("Unmarshal with v2->v1 version downgrade succeeded; want AAD failure")
	}

	// Backward compatibility: a legacy v1 encrypted key (sealed with nil AAD) still unmarshals
	pubBytes := orig.Marshal()
	salt := make([]byte, 16)
	rand.Read(salt)
	dk := pbkdf2.Key([]byte(passphrase), salt, minIter, 32, sha256.New)
	cBlock, err := aes.NewCipher(dk)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(cBlock)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	encIDv1 := gcm.Seal(nonce, nonce, orig.id, nil)
	v1Buf := cryptobyte.NewBuilder([]byte{1})
	v1Buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(pubBytes)
	})
	v1Buf.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(salt)
		b.AddUint32(uint32(minIter))
		b.AddBytes(encIDv1)
	})
	v1PEM := pem.EncodeToMemory(&pem.Block{Type: "WEBAUTHN ENCRYPTED KEY", Bytes: v1Buf.BytesOrPanic()})
	gotV1, err := Unmarshal(v1PEM, "test", rp)
	if err != nil {
		t.Fatalf("Unmarshal(legacy v1): %v", err)
	}
	if gotV1.typ != orig.typ || !bytes.Equal(gotV1.rpID, orig.rpID) || !bytes.Equal(gotV1.id, orig.id) {
		t.Errorf("Unmarshal(legacy v1) mismatch: got %+v, want %+v", gotV1, orig)
	}

	// Backward compatibility: a legacy v2 encrypted key whose pubBytes used
	// "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" as the public key type
	// still unmarshals (preserving AAD verification) and normalizes its Type()
	// to "sk-ecdsa-sha2-nistp256@openssh.com".
	legacyKey := &Key{
		typ:    SignatureFormat,
		id:     orig.id,
		rpID:   orig.rpID,
		pubKey: orig.pubKey,
	}
	legacyBlock, err := legacyKey.MarshalPrivate(passphrase)
	if err != nil {
		t.Fatalf("legacyKey.MarshalPrivate: %v", err)
	}
	gotLegacy, err := Unmarshal(pem.EncodeToMemory(legacyBlock), "test", rp)
	if err != nil {
		t.Fatalf("Unmarshal(legacy v2 key type): %v", err)
	}
	if gotLegacy.Type() != KeyType || !bytes.Equal(gotLegacy.rpID, orig.rpID) || !bytes.Equal(gotLegacy.id, orig.id) {
		t.Errorf("Unmarshal(legacy v2 key type) mismatch: got %+v, want %+v", gotLegacy, orig)
	}

	// Iteration count below minIter or above maxIter must be rejected
	iterOffset := 1 + 2 + pubLen + 2 + 16
	for _, badIter := range []uint32{0, 1, 999, maxIter + 1} {
		badBytes := append([]byte(nil), block.Bytes...)
		binary.BigEndian.PutUint32(badBytes[iterOffset:iterOffset+4], badIter)
		badPEM := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: badBytes})
		if _, err := Unmarshal(badPEM, "test", rp); err == nil {
			t.Errorf("Unmarshal with numIter=%d succeeded; want error", badIter)
		}
	}

	// Encrypted key with nil passphrase callback must return an error, not panic
	if _, err := Unmarshal(pem.EncodeToMemory(block), "test", nil); err == nil {
		t.Error("Unmarshal(encrypted, nil rp) succeeded; want error")
	}

	// Trailing bytes after privBytes in outer binary container must be rejected
	trailingPEM := pem.EncodeToMemory(&pem.Block{
		Type:  block.Type,
		Bytes: append(append([]byte(nil), block.Bytes...), 0x00),
	})
	if _, err := Unmarshal(trailingPEM, "test", rp); err == nil {
		t.Error("Unmarshal with trailing container bytes succeeded; want error")
	}
}

func TestCertificateSigning(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key, err := NewKey([]byte("credential-id-12345"), &priv.PublicKey, []byte("example.com"))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}

	// Marshal as authorized_keys line and parse with standard golang.org/x/crypto/ssh.
	authKey := gossh.MarshalAuthorizedKey(key)
	parsedPub, _, _, _, err := gossh.ParseAuthorizedKey(authKey)
	if err != nil {
		t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
	}
	if !bytes.Equal(parsedPub.Marshal(), key.Marshal()) {
		t.Fatalf("parsed public key bytes do not match key.Marshal()")
	}

	// Sign an SSH user certificate for the WebAuthn public key.
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	caSigner, err := gossh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	cert := &gossh.Certificate{
		Key:             parsedPub,
		Serial:          1,
		CertType:        gossh.UserCert,
		KeyId:           "testuser",
		ValidPrincipals: []string{"testuser"},
		ValidBefore:     gossh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("cert.SignCert: %v", err)
	}
	if got, want := cert.Type(), CertType; got != want {
		t.Errorf("cert.Type() = %q, want %q", got, want)
	}

	// Verify the marshaled certificate parses back and matches key.Marshal().
	parsedCertKey, _, _, _, err := gossh.ParseAuthorizedKey(gossh.MarshalAuthorizedKey(cert))
	if err != nil {
		t.Fatalf("ssh.ParseAuthorizedKey(cert): %v", err)
	}
	parsedCert, ok := parsedCertKey.(*gossh.Certificate)
	if !ok {
		t.Fatalf("parsed key is %T, want *ssh.Certificate", parsedCertKey)
	}
	if !bytes.Equal(parsedCert.Key.Marshal(), key.Marshal()) {
		t.Errorf("parsedCert.Key.Marshal() does not match key.Marshal()")
	}
}

func TestKeyVerify(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key, err := NewKey([]byte("credential-id-12345"), &priv.PublicKey, []byte("example.com"))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	data := []byte("ssh-session-data-to-sign")
	appHash := sha256.Sum256(key.rpID)
	flags := byte(0x05)
	counter := uint32(42)

	// 1. Verify webauthn-sk-ecdsa-sha2-nistp256@openssh.com signature.
	origin := "https://example.com"
	clientData := fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":%q}`,
		base64.RawURLEncoding.EncodeToString(data), origin)
	cdHash := sha256.Sum256([]byte(clientData))

	var webauthnSigned cryptobyte.Builder
	webauthnSigned.AddBytes(appHash[:])
	webauthnSigned.AddUint8(flags)
	webauthnSigned.AddUint32(counter)
	webauthnSigned.AddBytes(cdHash[:])
	webauthnHash := sha256.Sum256(webauthnSigned.BytesOrPanic())
	r, s, err := ecdsa.Sign(rand.Reader, priv, webauthnHash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	webauthnSig := &gossh.Signature{
		Format: SignatureFormat,
		Blob:   gossh.Marshal(struct{ R, S *big.Int }{r, s}),
		Rest: gossh.Marshal(struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}{
			Flags:      flags,
			Counter:    counter,
			Origin:     origin,
			ClientData: clientData,
		}),
	}
	if err := key.Verify(data, webauthnSig); err != nil {
		t.Errorf("key.Verify(webauthnSig) failed: %v", err)
	}
	if err := key.Verify([]byte("wrong-data"), webauthnSig); err == nil {
		t.Error("key.Verify(wrong-data) succeeded; want error")
	}

	// 2. Verify sk-ecdsa-sha2-nistp256@openssh.com signature.
	dataHash := sha256.Sum256(data)
	var skSigned cryptobyte.Builder
	skSigned.AddBytes(appHash[:])
	skSigned.AddUint8(flags)
	skSigned.AddUint32(counter)
	skSigned.AddBytes(dataHash[:])
	skHash := sha256.Sum256(skSigned.BytesOrPanic())
	r2, s2, err := ecdsa.Sign(rand.Reader, priv, skHash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	skSig := &gossh.Signature{
		Format: KeyType,
		Blob:   gossh.Marshal(struct{ R, S *big.Int }{r2, s2}),
		Rest: gossh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{
			Flags:   flags,
			Counter: counter,
		}),
	}
	if err := key.Verify(data, skSig); err != nil {
		t.Errorf("key.Verify(skSig) failed: %v", err)
	}
	if err := key.Verify([]byte("wrong-data"), skSig); err == nil {
		t.Error("key.Verify(wrong-data) succeeded; want error")
	}

	// 3. Verify WebAuthn signature with extensions (flags 0x85) succeeds.
	extBytes := string([]byte{0xa1, 0x01, 0xf5})
	var extSigned cryptobyte.Builder
	extSigned.AddBytes(appHash[:])
	extSigned.AddUint8(0x85)
	extSigned.AddUint32(counter)
	extSigned.AddBytes([]byte(extBytes))
	extSigned.AddBytes(cdHash[:])
	extHash := sha256.Sum256(extSigned.BytesOrPanic())
	rExt, sExt, err := ecdsa.Sign(rand.Reader, priv, extHash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	extSig := &gossh.Signature{
		Format: SignatureFormat,
		Blob:   gossh.Marshal(struct{ R, S *big.Int }{rExt, sExt}),
		Rest: gossh.Marshal(struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}{
			Flags:      0x85,
			Counter:    counter,
			Origin:     origin,
			ClientData: clientData,
			Extensions: extBytes,
		}),
	}
	if err := key.Verify(data, extSig); err != nil {
		t.Errorf("key.Verify(extSig) failed: %v", err)
	}

	// 4. Negative cases for WebAuthn & SK signature flags, origin, and clientData.
	signWebAuthn := func(f byte, orig, cd, ext string) *gossh.Signature {
		h := sha256.Sum256([]byte(cd))
		var b cryptobyte.Builder
		b.AddBytes(appHash[:])
		b.AddUint8(f)
		b.AddUint32(counter)
		b.AddBytes([]byte(ext))
		b.AddBytes(h[:])
		digest := sha256.Sum256(b.BytesOrPanic())
		rr, ss, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatalf("ecdsa.Sign: %v", err)
		}
		return &gossh.Signature{
			Format: SignatureFormat,
			Blob:   gossh.Marshal(struct{ R, S *big.Int }{rr, ss}),
			Rest: gossh.Marshal(struct {
				Flags      byte
				Counter    uint32
				Origin     string
				ClientData string
				Extensions string
			}{
				Flags:      f,
				Counter:    counter,
				Origin:     orig,
				ClientData: cd,
				Extensions: ext,
			}),
		}
	}

	b64Chall := base64.RawURLEncoding.EncodeToString(data)
	for _, tc := range []struct {
		name string
		sig  *gossh.Signature
	}{
		{
			name: "webauthn missing UP flag",
			sig:  signWebAuthn(0x04, origin, clientData, ""),
		},
		{
			name: "webauthn AT flag set",
			sig:  signWebAuthn(0x41, origin, clientData, ""),
		},
		{
			name: "webauthn ED flag set with empty extensions",
			sig:  signWebAuthn(0x81, origin, clientData, ""),
		},
		{
			name: "webauthn ED flag clear with non-empty extensions",
			sig:  signWebAuthn(0x01, origin, clientData, extBytes),
		},
		{
			name: "webauthn invalid origin scheme",
			sig:  signWebAuthn(0x01, "ftp://example.com", fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":"ftp://example.com"}`, b64Chall), ""),
		},
		{
			name: "webauthn crossOrigin true",
			sig:  signWebAuthn(0x01, origin, fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":%q,"crossOrigin":true}`, b64Chall, origin), ""),
		},
		{
			name: "webauthn reordered clientData fields",
			sig:  signWebAuthn(0x01, origin, fmt.Sprintf(`{"origin":%q,"type":"webauthn.get","challenge":%q}`, origin, b64Chall), ""),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := key.Verify(data, tc.sig); err == nil {
				t.Errorf("key.Verify(%s) succeeded; want error", tc.name)
			}
		})
	}

	// SK signature missing UP flag (0x00) must also fail
	var skNoUP cryptobyte.Builder
	skNoUP.AddBytes(appHash[:])
	skNoUP.AddUint8(0x00)
	skNoUP.AddUint32(counter)
	skNoUP.AddBytes(dataHash[:])
	skNoUPHash := sha256.Sum256(skNoUP.BytesOrPanic())
	rNoUP, sNoUP, err := ecdsa.Sign(rand.Reader, priv, skNoUPHash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	skNoUPSig := &gossh.Signature{
		Format: KeyType,
		Blob:   gossh.Marshal(struct{ R, S *big.Int }{rNoUP, sNoUP}),
		Rest: gossh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{
			Flags:   0x00,
			Counter: counter,
		}),
	}
	if err := key.Verify(data, skNoUPSig); err == nil {
		t.Error("key.Verify(sk missing UP flag) succeeded; want error")
	}
	if err := key.Verify(data, nil); err == nil {
		t.Error("key.Verify(nil sig) succeeded; want error")
	}
	if err := (*Key)(nil).Verify(data, webauthnSig); err == nil {
		t.Error("(*Key)(nil).Verify succeeded; want error")
	}
}
