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

// Package webauthn implements the server and client primitives of the W3C
// WebAuthn specification.
package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
)

var cborDecMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

const (
	// COSE algorithm identifiers.
	// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
	// https://w3c.github.io/webauthn/#sctn-alg-identifier
	AlgES256 = -7   // ECDSA w/ SHA-256 on P-256
	AlgEdDSA = -8   // EdDSA on Ed25519
	AlgES384 = -35  // ECDSA w/ SHA-384 on P-384
	AlgES512 = -36  // ECDSA w/ SHA-512 on P-521
	AlgPS256 = -37  // RSASSA-PSS w/ SHA-256
	AlgPS384 = -38  // RSASSA-PSS w/ SHA-384
	AlgPS512 = -39  // RSASSA-PSS w/ SHA-512
	AlgRS256 = -257 // RSASSA-PKCS1-v1_5 w/ SHA-256
	AlgRS384 = -258 // RSASSA-PKCS1-v1_5 w/ SHA-384
	AlgRS512 = -259 // RSASSA-PKCS1-v1_5 w/ SHA-512
)

const (
	// Authenticator data flags.
	// https://w3c.github.io/webauthn/#sctn-authenticator-data
	FlagUserPresent            byte = 1 << 0 // 0x01 UP
	FlagUserVerified           byte = 1 << 2 // 0x04 UV
	FlagBackupEligible         byte = 1 << 3 // 0x08 BE
	FlagBackupState            byte = 1 << 4 // 0x10 BS
	FlagAttestedCredentialData byte = 1 << 6 // 0x40 AT
	FlagExtensionData          byte = 1 << 7 // 0x80 ED
)

// ErrTooShort indicates that the message is too short and cannot be decoded.
var ErrTooShort = errors.New("too short")

// Bytes is a byte slice that marshals to JSON as an unpadded base64url string
// per W3C WebAuthn Level 3, and unmarshals from either an unpadded base64url
// string or a JSON array of byte integers ([1, 2, 3]) for backward
// compatibility.
type Bytes []byte

// ParseBytes decodes an unpadded base64url string into Bytes.
func ParseBytes(s string) (Bytes, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	return Bytes(b), nil
}

// String returns the unpadded base64url representation of b.
func (b Bytes) String() string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// MarshalJSON marshals b as an unpadded base64url JSON string (or null if nil).
func (b Bytes) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	return []byte(`"` + base64.RawURLEncoding.EncodeToString(b) + `"`), nil
}

// UnmarshalJSON unmarshals b from either an unpadded base64url JSON string or
// a JSON array of integers in [0, 255].
func (b *Bytes) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return errors.New("empty JSON input")
	}
	if string(data) == "null" {
		*b = nil
		return nil
	}
	switch data[0] {
	case '"':
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		dec, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil {
			return fmt.Errorf("invalid base64url bytes: %w", err)
		}
		*b = Bytes(dec)
		return nil

	case '[':
		var nums []int
		if err := json.Unmarshal(data, &nums); err != nil {
			return err
		}
		out := make(Bytes, len(nums))
		for i, v := range nums {
			if v < 0 || v > 255 {
				return fmt.Errorf("byte value %d at index %d out of range [0, 255]", v, i)
			}
			out[i] = byte(v)
		}
		*b = out
		return nil

	default:
		return errors.New("expected base64url string or byte array")
	}
}

// RelyingPartyEntity describes the Relying Party in AttestationOptions.
type RelyingPartyEntity struct {
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
}

// UserEntity describes the user account in AttestationOptions.
type UserEntity struct {
	ID          Bytes  `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// AuthenticatorSelection specifies requirements regarding authenticator
// attributes during credential creation.
type AuthenticatorSelection struct {
	// AuthenticatorAttachment: "platform" or "cross-platform".
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	// UserVerification: "required", "preferred", or "discouraged".
	UserVerification string `json:"userVerification,omitempty"`
	// ResidentKey: "required", "preferred", or "discouraged".
	ResidentKey string `json:"residentKey,omitempty"`
	// RequireResidentKey is the WebAuthn Level 1 boolean field. It should
	// be true iff ResidentKey is "required".
	RequireResidentKey bool `json:"requireResidentKey,omitempty"`
}

// AttestationOptions encapsulates the options to navigator.credentials.create()
// (PublicKeyCredentialCreationOptions).
type AttestationOptions struct {
	// The cryptographic challenge (32 random bytes).
	Challenge Bytes `json:"challenge"`
	// The name and optional ID of the relying party.
	RelyingParty RelyingPartyEntity `json:"rp"`
	// The user information.
	User UserEntity `json:"user"`
	// The acceptable public key parameters.
	PubKeyCredParams []PubKeyCredParam `json:"pubKeyCredParams,omitempty"`
	// Timeout in milliseconds.
	Timeout int `json:"timeout,omitempty"`
	// A list of credentials already registered for this user.
	ExcludeCredentials []CredentialID `json:"excludeCredentials,omitempty"`
	// The type of attestation conveyance preference ("none", "indirect", "direct", "enterprise").
	Attestation string `json:"attestation,omitempty"`
	// Optional list of preferred attestation statement formats.
	AttestationFormats []string `json:"attestationFormats,omitempty"`
	// Authenticator selection parameters.
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	// Optional hints ("security-key", "client-device", "hybrid").
	Hints []string `json:"hints,omitempty"`
	// Extensions. With the WASM client (Create and Get), binary inputs must
	// be []byte or Bytes values; they are passed to the browser as Uint8Array.
	Extensions map[string]any `json:"extensions,omitempty"`
}

// NewAttestationOptions returns a new AttestationOptions with Challenge,
// PubKeyCredParams, Timeout, Attestation, and AuthenticatorSelection populated
// with passkey-friendly defaults.
func NewAttestationOptions() (*AttestationOptions, error) {
	ao := &AttestationOptions{
		PubKeyCredParams: []PubKeyCredParam{
			{
				Type: "public-key",
				Alg:  AlgES256,
			},
			{
				Type: "public-key",
				Alg:  AlgEdDSA,
			},
			{
				Type: "public-key",
				Alg:  AlgRS256,
			},
		},
		Timeout:     120000, // 120 sec
		Attestation: "none",
		AuthenticatorSelection: AuthenticatorSelection{
			UserVerification: "required",
			ResidentKey:      "preferred",
		},
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	ao.Challenge = challenge
	return ao, nil
}

// AssertionOptions encapsulates the options to navigator.credentials.get()
// (PublicKeyCredentialRequestOptions).
type AssertionOptions struct {
	// The cryptographic challenge (32 random bytes).
	Challenge Bytes `json:"challenge"`
	// Timeout in milliseconds.
	Timeout int `json:"timeout,omitempty"`
	// Optional Relying Party ID.
	RPID string `json:"rpId,omitempty"`
	// A list of credentials already registered for this user.
	AllowCredentials []CredentialID `json:"allowCredentials,omitempty"`
	// UserVerification: "required", "preferred", or "discouraged".
	UserVerification string `json:"userVerification,omitempty"`
	// Optional hints ("security-key", "client-device", "hybrid").
	Hints []string `json:"hints,omitempty"`
	// Extensions. With the WASM client (Create and Get), binary inputs must
	// be []byte or Bytes values; they are passed to the browser as Uint8Array.
	Extensions map[string]any `json:"extensions,omitempty"`
}

// NewAssertionOptions returns a new AssertionOptions with Challenge, Timeout,
// UserVerification, and an empty AllowCredentials slice populated.
func NewAssertionOptions() (*AssertionOptions, error) {
	ao := &AssertionOptions{
		Timeout:          120000, // 120 sec
		UserVerification: "required",
		AllowCredentials: make([]CredentialID, 0),
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	ao.Challenge = challenge
	return ao, nil
}

// PubKeyCredParam specifies a credential type and COSE algorithm identifier.
type PubKeyCredParam struct {
	// The type of credential. Always "public-key".
	Type string `json:"type"`
	// The COSE algorithm identifier (e.g. -7 for ES256, -8 for EdDSA, -257 for RS256).
	Alg int `json:"alg"`
}

// CredentialID is a public key credential descriptor.
type CredentialID struct {
	// The type of credential. Always "public-key".
	Type string `json:"type"`
	// The credential ID.
	ID Bytes `json:"id"`
	// The available transports for this credential.
	Transports []string `json:"transports,omitempty"`
}

// AttestationResponse represents a credential registration response from
// navigator.credentials.create(). Its JSON unmarshaler accepts both the W3C
// WebAuthn Level 3 RegistrationResponseJSON structure (with a nested "response"
// object) and a flat JSON object structure.
type AttestationResponse struct {
	ID                      string   `json:"id,omitempty"`
	RawID                   Bytes    `json:"rawId,omitempty"`
	Type                    string   `json:"type,omitempty"`
	AuthenticatorAttachment string   `json:"authenticatorAttachment,omitempty"`
	ClientDataJSON          Bytes    `json:"clientDataJSON"`
	AttestationObject       Bytes    `json:"attestationObject"`
	Transports              []string `json:"transports,omitempty"`
}

// UnmarshalJSON unmarshals an AttestationResponse from either a W3C Level 3
// RegistrationResponseJSON object or a flat JSON object.
func (r *AttestationResponse) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID                      string   `json:"id"`
		RawID                   Bytes    `json:"rawId"`
		Type                    string   `json:"type"`
		AuthenticatorAttachment string   `json:"authenticatorAttachment"`
		ClientDataJSON          Bytes    `json:"clientDataJSON"`
		AttestationObject       Bytes    `json:"attestationObject"`
		Transports              []string `json:"transports"`
		Response                *struct {
			ClientDataJSON    Bytes    `json:"clientDataJSON"`
			AttestationObject Bytes    `json:"attestationObject"`
			Transports        []string `json:"transports"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = AttestationResponse{
		ID:                      raw.ID,
		RawID:                   raw.RawID,
		Type:                    raw.Type,
		AuthenticatorAttachment: raw.AuthenticatorAttachment,
		ClientDataJSON:          raw.ClientDataJSON,
		AttestationObject:       raw.AttestationObject,
		Transports:              raw.Transports,
	}
	if raw.Response != nil {
		if len(r.ClientDataJSON) == 0 {
			r.ClientDataJSON = raw.Response.ClientDataJSON
		}
		if len(r.AttestationObject) == 0 {
			r.AttestationObject = raw.Response.AttestationObject
		}
		if len(r.Transports) == 0 {
			r.Transports = raw.Response.Transports
		}
	}
	var err error
	r.ID, r.RawID, err = reconcileCredentialID(r.ID, r.RawID)
	return err
}

// AssertionResponse represents an authentication assertion response from
// navigator.credentials.get(). Its JSON unmarshaler accepts both the W3C
// WebAuthn Level 3 AuthenticationResponseJSON structure (with a nested
// "response" object) and a flat JSON object structure.
type AssertionResponse struct {
	ID                      string `json:"id,omitempty"`
	RawID                   Bytes  `json:"rawId,omitempty"`
	Type                    string `json:"type,omitempty"`
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ClientDataJSON          Bytes  `json:"clientDataJSON"`
	AuthenticatorData       Bytes  `json:"authenticatorData"`
	Signature               Bytes  `json:"signature"`
	UserHandle              Bytes  `json:"userHandle,omitempty"`
}

// UnmarshalJSON unmarshals an AssertionResponse from either a W3C Level 3
// AuthenticationResponseJSON object or a flat JSON object.
func (r *AssertionResponse) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID                      string `json:"id"`
		RawID                   Bytes  `json:"rawId"`
		Type                    string `json:"type"`
		AuthenticatorAttachment string `json:"authenticatorAttachment"`
		ClientDataJSON          Bytes  `json:"clientDataJSON"`
		AuthenticatorData       Bytes  `json:"authenticatorData"`
		Signature               Bytes  `json:"signature"`
		UserHandle              Bytes  `json:"userHandle"`
		Response                *struct {
			ClientDataJSON    Bytes `json:"clientDataJSON"`
			AuthenticatorData Bytes `json:"authenticatorData"`
			Signature         Bytes `json:"signature"`
			UserHandle        Bytes `json:"userHandle"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = AssertionResponse{
		ID:                      raw.ID,
		RawID:                   raw.RawID,
		Type:                    raw.Type,
		AuthenticatorAttachment: raw.AuthenticatorAttachment,
		ClientDataJSON:          raw.ClientDataJSON,
		AuthenticatorData:       raw.AuthenticatorData,
		Signature:               raw.Signature,
		UserHandle:              raw.UserHandle,
	}
	if raw.Response != nil {
		if len(r.ClientDataJSON) == 0 {
			r.ClientDataJSON = raw.Response.ClientDataJSON
		}
		if len(r.AuthenticatorData) == 0 {
			r.AuthenticatorData = raw.Response.AuthenticatorData
		}
		if len(r.Signature) == 0 {
			r.Signature = raw.Response.Signature
		}
		if len(r.UserHandle) == 0 {
			r.UserHandle = raw.Response.UserHandle
		}
	}
	var err error
	r.ID, r.RawID, err = reconcileCredentialID(r.ID, r.RawID)
	return err
}

// reconcileCredentialID returns the consistent (id, rawId) pair of a
// credential response. Either one can be derived from the other when it is
// missing; when both are present, id must be the base64url encoding of rawId.
func reconcileCredentialID(id string, rawID Bytes) (string, Bytes, error) {
	switch {
	case id == "":
		if len(rawID) > 0 {
			id = rawID.String()
		}
	case rawID == nil:
		b, err := ParseBytes(id)
		if err != nil {
			return "", nil, fmt.Errorf("invalid credential id: %w", err)
		}
		rawID = b
	case id != rawID.String():
		return "", nil, errors.New("credential id and rawId mismatch")
	}
	return id, rawID, nil
}

// TokenBinding represents the tokenBinding member of CollectedClientData.
// https://w3c.github.io/webauthn/#dom-collectedclientdata-tokenbinding
type TokenBinding struct {
	Status string `json:"status"`
	ID     string `json:"id,omitempty"`
}

// ClientData is a decoded CollectedClientData (clientDataJSON) object.
// https://w3c.github.io/webauthn/#dictdef-collectedclientdata
type ClientData struct {
	Type         string        `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	CrossOrigin  bool          `json:"crossOrigin,omitempty"`
	TopOrigin    string        `json:"topOrigin,omitempty"`
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}

// ParseClientData parses a clientDataJSON blob and validates structural
// invariants on optional fields (crossOrigin/topOrigin and tokenBinding).
func ParseClientData(js []byte) (*ClientData, error) {
	if trimmed := bytes.TrimSpace(js); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("invalid clientDataJSON: expected JSON object")
	}
	var out ClientData
	if err := json.Unmarshal(js, &out); err != nil {
		return nil, err
	}
	if !out.CrossOrigin && out.TopOrigin != "" {
		return nil, errors.New("topOrigin present when crossOrigin is false")
	}
	if out.TokenBinding != nil {
		switch out.TokenBinding.Status {
		case "present":
			if out.TokenBinding.ID == "" {
				return nil, errors.New("tokenBinding status is present without id")
			}
		case "supported":
			if out.TokenBinding.ID != "" {
				return nil, errors.New("tokenBinding id present when status is supported")
			}
		default:
			return nil, fmt.Errorf("invalid tokenBinding status %q", out.TokenBinding.Status)
		}
	}
	return &out, nil
}

// VerifyClientData checks that a clientDataJSON blob belongs to the ceremony
// requested by the caller: it validates the type ("webauthn.create" or
// "webauthn.get"), rejects cross-origin ceremonies, verifies that the
// base64url-encoded challenge strictly decodes to wantChallenge, and (when
// wantOrigin is non-empty) checks that Origin matches wantOrigin.
func VerifyClientData(js []byte, wantType string, wantChallenge []byte, wantOrigin string) (*ClientData, error) {
	cd, err := ParseClientData(js)
	if err != nil {
		return nil, fmt.Errorf("ParseClientData: %w", err)
	}
	if cd.Type != wantType {
		return nil, fmt.Errorf("unexpected client data type %q, want %q", cd.Type, wantType)
	}
	if cd.CrossOrigin {
		return nil, errors.New("cross-origin client data not allowed")
	}
	if wantOrigin != "" && cd.Origin != wantOrigin {
		return nil, fmt.Errorf("unexpected client data origin %q, want %q", cd.Origin, wantOrigin)
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(cd.Challenge)
	if err != nil {
		return nil, fmt.Errorf("invalid client data challenge: %w", err)
	}
	if len(wantChallenge) == 0 || subtle.ConstantTimeCompare(challenge, wantChallenge) != 1 {
		return nil, errors.New("client data challenge doesn't match")
	}
	return cd, nil
}

// VerifyAttestationOptions configures server-side verification of a credential
// registration response per W3C WebAuthn Level 3 §7.1.
type VerifyAttestationOptions struct {
	// Challenge is the expected raw challenge bytes sent in AttestationOptions.
	Challenge []byte
	// Origin is the expected clientData.origin (e.g. "https://example.com").
	Origin string
	// AllowedOrigins is an optional list of acceptable origins (used if Origin is empty).
	AllowedOrigins []string
	// RPID is the Relying Party Identifier (e.g. "example.com").
	RPID string
	// RequireUserVerification requires the UV flag to be set in authenticatorData.
	RequireUserVerification bool
	// VerifyAttestationStatement requires the attestation statement signature
	// ("none", "packed", "fido-u2f") to be verified.
	VerifyAttestationStatement bool
	// AllowedAlgorithms is an optional list of acceptable COSE algorithm
	// identifiers. If empty, all supported algorithms are allowed.
	AllowedAlgorithms []int
}

// VerifiedCredential contains the validated credential information resulting
// from a successful registration ceremony (VerifyAttestation).
type VerifiedCredential struct {
	ID             Bytes
	PublicKey      crypto.PublicKey
	COSEKey        Bytes
	Algorithm      int
	AAGUID         Bytes
	RPIDHash       Bytes
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
	UserVerified   bool
	Transports     []string
	Attestation    *Attestation
	ClientData     *ClientData
}

// VerifyAttestation performs server-side verification of a registration
// response per W3C WebAuthn Level 3 §7.1.
func VerifyAttestation(resp *AttestationResponse, opts VerifyAttestationOptions) (*VerifiedCredential, error) {
	if resp == nil {
		return nil, errors.New("nil attestation response")
	}
	if resp.Type != "" && resp.Type != "public-key" {
		return nil, fmt.Errorf("unexpected credential type %q", resp.Type)
	}
	_, rawID, err := reconcileCredentialID(resp.ID, resp.RawID)
	if err != nil {
		return nil, err
	}
	// The origin is checked by checkAllowedOrigin below.
	cd, err := VerifyClientData(resp.ClientDataJSON, "webauthn.create", opts.Challenge, "")
	if err != nil {
		return nil, err
	}
	if err := checkAllowedOrigin(cd.Origin, opts.Origin, opts.AllowedOrigins); err != nil {
		return nil, err
	}
	att, pubKey, alg, err := parseAttestationObject(resp.AttestationObject)
	if err != nil {
		return nil, err
	}
	if opts.RPID == "" {
		return nil, errors.New("missing RPID in VerifyAttestationOptions")
	}
	wantRPHash := sha256.Sum256([]byte(opts.RPID))
	if subtle.ConstantTimeCompare(att.AuthData.RPIDHash, wantRPHash[:]) != 1 {
		return nil, errors.New("rpIdHash mismatch")
	}
	if !att.AuthData.UserPresence {
		return nil, errors.New("user presence flag not set")
	}
	if opts.RequireUserVerification && !att.AuthData.UserVerification {
		return nil, errors.New("user verification flag not set")
	}
	ac := att.AuthData.AttestedCredentials
	if len(rawID) > 0 && !bytes.Equal(rawID, ac.ID) {
		return nil, errors.New("response rawId does not match attested credentialId")
	}
	if len(opts.AllowedAlgorithms) > 0 && !slices.Contains(opts.AllowedAlgorithms, alg) {
		return nil, fmt.Errorf("disallowed credential algorithm %d", alg)
	}
	if opts.VerifyAttestationStatement {
		credKey := func() (crypto.PublicKey, int, error) {
			return pubKey, alg, nil
		}
		if err := att.verifyAttestationStatement(resp.ClientDataJSON, credKey); err != nil {
			return nil, err
		}
	}
	return &VerifiedCredential{
		ID:             bytes.Clone(ac.ID),
		PublicKey:      pubKey,
		COSEKey:        bytes.Clone(ac.COSEKey),
		Algorithm:      alg,
		AAGUID:         bytes.Clone(ac.AAGUID),
		RPIDHash:       bytes.Clone(att.AuthData.RPIDHash),
		SignCount:      att.AuthData.SignCount,
		BackupEligible: att.AuthData.BackupEligible,
		BackupState:    att.AuthData.BackupState,
		UserVerified:   att.AuthData.UserVerification,
		Transports:     slices.Clone(resp.Transports),
		Attestation:    att,
		ClientData:     cd,
	}, nil
}

// VerifyAssertionOptions configures server-side verification of an
// authentication assertion response per W3C WebAuthn Level 3 §7.2.
type VerifyAssertionOptions struct {
	// Challenge is the expected raw challenge bytes sent in AssertionOptions.
	Challenge []byte
	// Origin is the expected clientData.origin (e.g. "https://example.com").
	Origin string
	// AllowedOrigins is an optional list of acceptable origins (used if Origin is empty).
	AllowedOrigins []string
	// RPID is the Relying Party Identifier (e.g. "example.com").
	RPID string
	// COSEKey is the stored CBOR-encoded COSE_Key for the credential.
	COSEKey []byte
	// CredentialID, if non-empty, must match the credential ID in the response.
	CredentialID []byte
	// UserHandle, if non-empty, must match a non-empty userHandle in the response.
	UserHandle []byte
	// RequireUserVerification requires the UV flag to be set in authenticatorData.
	RequireUserVerification bool
	// PrevSignCount is the previously recorded signature counter for this credential.
	PrevSignCount uint32
	// IgnoreSignCount disables the signature counter progression check.
	IgnoreSignCount bool
}

// VerifiedAssertion contains the validated assertion details resulting from a
// successful authentication ceremony (VerifyAssertion).
type VerifiedAssertion struct {
	CredentialID   Bytes
	UserHandle     Bytes
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
	UserVerified   bool
	AuthData       AuthenticatorData
	ClientData     *ClientData
}

// VerifyAssertion performs server-side verification of an authentication
// assertion response per W3C WebAuthn Level 3 §7.2.
func VerifyAssertion(resp *AssertionResponse, opts VerifyAssertionOptions) (*VerifiedAssertion, error) {
	if resp == nil {
		return nil, errors.New("nil assertion response")
	}
	if resp.Type != "" && resp.Type != "public-key" {
		return nil, fmt.Errorf("unexpected credential type %q", resp.Type)
	}
	_, rawID, err := reconcileCredentialID(resp.ID, resp.RawID)
	if err != nil {
		return nil, err
	}
	if len(opts.CredentialID) > 0 && subtle.ConstantTimeCompare(rawID, opts.CredentialID) != 1 {
		return nil, errors.New("credential ID mismatch")
	}
	if len(opts.UserHandle) > 0 && len(resp.UserHandle) > 0 && subtle.ConstantTimeCompare(resp.UserHandle, opts.UserHandle) != 1 {
		return nil, errors.New("userHandle mismatch")
	}
	// The origin is checked by checkAllowedOrigin below.
	cd, err := VerifyClientData(resp.ClientDataJSON, "webauthn.get", opts.Challenge, "")
	if err != nil {
		return nil, err
	}
	if err := checkAllowedOrigin(cd.Origin, opts.Origin, opts.AllowedOrigins); err != nil {
		return nil, err
	}
	var ad AuthenticatorData
	if err := ParseAuthenticatorData(resp.AuthenticatorData, &ad); err != nil {
		return nil, err
	}
	if ad.AttestedCredentialData {
		return nil, errors.New("unexpected attested credential data in assertion")
	}
	if opts.RPID == "" {
		return nil, errors.New("missing RPID in VerifyAssertionOptions")
	}
	wantRPHash := sha256.Sum256([]byte(opts.RPID))
	if subtle.ConstantTimeCompare(ad.RPIDHash, wantRPHash[:]) != 1 {
		return nil, errors.New("rpIdHash mismatch")
	}
	if !ad.UserPresence {
		return nil, errors.New("user presence flag not set")
	}
	if opts.RequireUserVerification && !ad.UserVerification {
		return nil, errors.New("user verification flag not set")
	}
	if err := VerifySignature(opts.COSEKey, resp.AuthenticatorData, resp.ClientDataJSON, resp.Signature); err != nil {
		return nil, err
	}
	if !opts.IgnoreSignCount && (ad.SignCount != 0 || opts.PrevSignCount != 0) {
		if ad.SignCount <= opts.PrevSignCount {
			return nil, fmt.Errorf("invalid signature counter %d <= %d", ad.SignCount, opts.PrevSignCount)
		}
	}
	return &VerifiedAssertion{
		CredentialID:   bytes.Clone(rawID),
		UserHandle:     bytes.Clone(resp.UserHandle),
		SignCount:      ad.SignCount,
		BackupEligible: ad.BackupEligible,
		BackupState:    ad.BackupState,
		UserVerified:   ad.UserVerification,
		AuthData:       ad,
		ClientData:     cd,
	}, nil
}

func checkAllowedOrigin(gotOrigin, wantOrigin string, allowedOrigins []string) error {
	if gotOrigin == "" {
		return errors.New("missing client data origin")
	}
	if wantOrigin != "" {
		if gotOrigin != wantOrigin {
			return fmt.Errorf("unexpected client data origin %q, want %q", gotOrigin, wantOrigin)
		}
		return nil
	}
	if len(allowedOrigins) == 0 {
		return errors.New("missing Origin or AllowedOrigins in verification options")
	}
	if !slices.Contains(allowedOrigins, gotOrigin) {
		return fmt.Errorf("unexpected client data origin %q", gotOrigin)
	}
	return nil
}

// Attestation represents a parsed WebAuthn attestationObject.
// https://w3c.github.io/webauthn/#sctn-attestation
type Attestation struct {
	Format      string          `cbor:"fmt"`
	AttStmt     cbor.RawMessage `cbor:"attStmt"`
	RawAuthData Bytes           `cbor:"authData"`

	AuthData AuthenticatorData `cbor:"-"`
}

// AuthenticatorData is the authenticator data provided during attestation and
// assertion ceremonies.
// https://w3c.github.io/webauthn/#sctn-authenticator-data
type AuthenticatorData struct {
	Flags                  byte                 `json:"flags"`
	RPIDHash               Bytes                `json:"rpIdHash"`
	UserPresence           bool                 `json:"up"`
	BackupEligible         bool                 `json:"be"`
	BackupState            bool                 `json:"bs"`
	UserVerification       bool                 `json:"uv"`
	AttestedCredentialData bool                 `json:"at"`
	ExtensionData          bool                 `json:"ed"`
	SignCount              uint32               `json:"signCount"`
	AttestedCredentials    *AttestedCredentials `json:"attestedCredentialData,omitempty"`
	Extensions             Bytes                `json:"extensions,omitempty"`
}

// AttestedCredentials holds the attested credential data from an
// AuthenticatorData structure.
// https://w3c.github.io/webauthn/#sctn-attested-credential-data
type AttestedCredentials struct {
	AAGUID  Bytes `json:"AAGUID"`
	ID      Bytes `json:"credentialId"`
	COSEKey Bytes `json:"credentialPublicKey"`
}

// PublicKey parses and validates the COSE_Key in c.COSEKey and returns the
// corresponding standard library crypto.PublicKey (*ecdsa.PublicKey,
// ed25519.PublicKey, or *rsa.PublicKey).
func (c AttestedCredentials) PublicKey() (crypto.PublicKey, error) {
	pub, _, err := ParseCOSEKey(c.COSEKey)
	return pub, err
}

// ParseAttestationObject parses a CBOR-encoded attestationObject and its
// embedded authenticatorData. It does not verify the attestation statement
// signature unless VerifyAttestationStatement is called on the returned
// Attestation.
func ParseAttestationObject(attestationObject []byte) (*Attestation, error) {
	att, _, _, err := parseAttestationObject(attestationObject)
	return att, err
}

// parseAttestationObject is ParseAttestationObject that also returns the
// parsed credential public key and its COSE algorithm, so that callers don't
// have to decode the COSE_Key again.
func parseAttestationObject(attestationObject []byte) (*Attestation, crypto.PublicKey, int, error) {
	if len(attestationObject) == 0 || attestationObject[0]>>5 != 5 {
		return nil, nil, 0, errors.New("invalid attestationObject CBOR type")
	}
	var att Attestation
	rest, err := cborDecMode.UnmarshalFirst(attestationObject, &att)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("cbor.Unmarshal: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, 0, errors.New("unexpected trailing bytes in attestationObject")
	}
	if att.Format == "" {
		return nil, nil, 0, errors.New("missing fmt in attestationObject")
	}
	if len(att.AttStmt) == 0 || att.AttStmt[0]>>5 != 5 {
		return nil, nil, 0, errors.New("invalid attStmt CBOR type")
	}
	if err := ParseAuthenticatorData(att.RawAuthData, &att.AuthData); err != nil {
		return nil, nil, 0, fmt.Errorf("ParseAuthenticatorData: %w", err)
	}
	if !att.AuthData.AttestedCredentialData || att.AuthData.AttestedCredentials == nil {
		return nil, nil, 0, errors.New("attestationObject missing attested credential data")
	}
	pubKey, alg, err := ParseCOSEKey(att.AuthData.AttestedCredentials.COSEKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("invalid credentialPublicKey: %w", err)
	}
	return &att, pubKey, alg, nil
}

// oidFIDOGenCEAAGUID is the FIDO alliance OID 1.3.6.1.4.1.45724.1.1.4 for the
// AAGUID certificate extension in packed attestation certificates.
var oidFIDOGenCEAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// VerifyAttestationStatement optionally verifies the attestation statement
// signature for "none", "packed" (both x5c and self-attestation), and
// "fido-u2f" formats per W3C WebAuthn Level 3 §8.
func (att *Attestation) VerifyAttestationStatement(clientDataJSON []byte) error {
	if att == nil || att.AuthData.AttestedCredentials == nil {
		return errors.New("missing attested credentials")
	}
	return att.verifyAttestationStatement(clientDataJSON, func() (crypto.PublicKey, int, error) {
		return ParseCOSEKey(att.AuthData.AttestedCredentials.COSEKey)
	})
}

// verifyAttestationStatement implements VerifyAttestationStatement. credKey
// returns the parsed credential public key and its COSE algorithm; it is only
// called by the formats that need it.
func (att *Attestation) verifyAttestationStatement(clientDataJSON []byte, credKey func() (crypto.PublicKey, int, error)) error {
	if att == nil || att.AuthData.AttestedCredentials == nil {
		return errors.New("missing attested credentials")
	}
	if len(att.AttStmt) > 0 && att.AttStmt[0]>>5 != 5 {
		return errors.New("invalid attStmt CBOR type")
	}
	switch att.Format {
	case "none":
		if len(att.AttStmt) == 0 {
			return nil
		}
		var m map[any]any
		rest, err := cborDecMode.UnmarshalFirst(att.AttStmt, &m)
		if err != nil {
			return fmt.Errorf("none attStmt: %w", err)
		}
		if len(rest) != 0 || len(m) != 0 {
			return errors.New("none attestation format must have an empty attStmt map")
		}
		return nil

	case "packed":
		// https://w3c.github.io/webauthn/#sctn-packed-attestation
		var stmt struct {
			Alg int      `cbor:"alg"`
			Sig []byte   `cbor:"sig"`
			X5C [][]byte `cbor:"x5c"`
		}
		rest, err := cborDecMode.UnmarshalFirst(att.AttStmt, &stmt)
		if err != nil {
			return fmt.Errorf("packed attStmt: %w", err)
		}
		if len(rest) != 0 {
			return errors.New("packed attStmt: unexpected trailing bytes")
		}
		if len(stmt.Sig) == 0 {
			return errors.New("packed attStmt: missing signature")
		}
		signed := signedBytes(att.RawAuthData, clientDataJSON)
		if stmt.X5C != nil {
			if len(stmt.X5C) == 0 || len(stmt.X5C[0]) == 0 {
				return errors.New("packed attStmt: empty attestation certificate")
			}
			cert, err := x509.ParseCertificate(stmt.X5C[0])
			if err != nil {
				return fmt.Errorf("packed attStmt x5c: %w", err)
			}
			// Verify §8.2.1 packed attestation certificate requirements.
			if cert.Version != 3 {
				return fmt.Errorf("packed attStmt cert: unexpected version %d, want 3", cert.Version)
			}
			if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] == "" {
				return errors.New("packed attStmt cert: missing Subject-C")
			}
			if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] == "" {
				return errors.New("packed attStmt cert: missing Subject-O")
			}
			if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != "Authenticator Attestation" {
				return errors.New("packed attStmt cert: Subject-OU must be \"Authenticator Attestation\"")
			}
			if cert.Subject.CommonName == "" {
				return errors.New("packed attStmt cert: missing Subject-CN")
			}
			if !cert.BasicConstraintsValid || cert.IsCA {
				return errors.New("packed attStmt cert: BasicConstraints must be present with CA=false")
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("packed attStmt cert: certificate is expired or not yet valid")
			}
			if len(cert.UnhandledCriticalExtensions) > 0 {
				return errors.New("packed attStmt cert: unhandled critical extension")
			}
			for _, ext := range cert.Extensions {
				if ext.Id.Equal(oidFIDOGenCEAAGUID) {
					if ext.Critical {
						return errors.New("packed attStmt cert: AAGUID extension must not be critical")
					}
					var aaguid []byte
					rem, err := asn1.Unmarshal(ext.Value, &aaguid)
					if err != nil || len(rem) != 0 {
						return errors.New("packed attStmt cert: invalid AAGUID extension ASN.1")
					}
					if !bytes.Equal(aaguid, att.AuthData.AttestedCredentials.AAGUID) {
						return errors.New("packed attStmt cert: AAGUID extension does not match authenticatorData AAGUID")
					}
				}
			}
			prev := cert
			for i := 1; i < len(stmt.X5C); i++ {
				issuer, err := x509.ParseCertificate(stmt.X5C[i])
				if err != nil {
					return fmt.Errorf("packed attStmt x5c[%d]: %w", i, err)
				}
				if now.Before(issuer.NotBefore) || now.After(issuer.NotAfter) {
					return fmt.Errorf("packed attStmt x5c[%d]: certificate is expired or not yet valid", i)
				}
				if !issuer.BasicConstraintsValid || !issuer.IsCA {
					return fmt.Errorf("packed attStmt x5c[%d]: intermediate certificate is not a CA", i)
				}
				if err := prev.CheckSignatureFrom(issuer); err != nil {
					return fmt.Errorf("packed attStmt x5c[%d]: %w", i, err)
				}
				prev = issuer
			}
			return verifySignatureWithPublicKey(cert.PublicKey, stmt.Alg, signed, stmt.Sig)
		}
		// Self attestation: validate that alg matches credentialPublicKey's alg.
		pubKey, credAlg, err := credKey()
		if err != nil {
			return err
		}
		if stmt.Alg != credAlg {
			return fmt.Errorf("packed self-attestation alg %d does not match credential alg %d", stmt.Alg, credAlg)
		}
		return verifySignatureWithPublicKey(pubKey, stmt.Alg, signed, stmt.Sig)

	case "fido-u2f":
		// https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation
		var stmt struct {
			Sig []byte   `cbor:"sig"`
			X5C [][]byte `cbor:"x5c"`
		}
		rest, err := cborDecMode.UnmarshalFirst(att.AttStmt, &stmt)
		if err != nil {
			return fmt.Errorf("fido-u2f attStmt: %w", err)
		}
		if len(rest) != 0 {
			return errors.New("fido-u2f attStmt: unexpected trailing bytes")
		}
		if len(stmt.X5C) != 1 || len(stmt.X5C[0]) == 0 {
			return errors.New("fido-u2f attStmt: x5c must contain a single attCert")
		}
		if len(stmt.Sig) == 0 {
			return errors.New("fido-u2f attStmt: missing signature")
		}
		attCert, err := x509.ParseCertificate(stmt.X5C[0])
		if err != nil {
			return fmt.Errorf("fido-u2f attCert: %w", err)
		}
		attPubKey, ok := attCert.PublicKey.(*ecdsa.PublicKey)
		if !ok || attPubKey.Curve != elliptic.P256() {
			return errors.New("fido-u2f attCert public key is not ECDSA P-256")
		}
		var zeroAAGUID [16]byte
		if !bytes.Equal(att.AuthData.AttestedCredentials.AAGUID, zeroAAGUID[:]) {
			return errors.New("fido-u2f authenticatorData AAGUID must be all zeroes")
		}
		credPub, credAlg, err := credKey()
		if err != nil {
			return err
		}
		ecCredPub, ok := credPub.(*ecdsa.PublicKey)
		if !ok || credAlg != AlgES256 || ecCredPub.Curve != elliptic.P256() {
			return errors.New("fido-u2f credential public key is not ES256 P-256")
		}
		var publicKeyU2F [65]byte
		publicKeyU2F[0] = 0x04
		ecCredPub.X.FillBytes(publicKeyU2F[1:33])
		ecCredPub.Y.FillBytes(publicKeyU2F[33:65])

		clientDataHash := sha256.Sum256(clientDataJSON)
		var verificationData bytes.Buffer
		verificationData.WriteByte(0x00)
		verificationData.Write(att.AuthData.RPIDHash)
		verificationData.Write(clientDataHash[:])
		verificationData.Write(att.AuthData.AttestedCredentials.ID)
		verificationData.Write(publicKeyU2F[:])

		hash := sha256.Sum256(verificationData.Bytes())
		if !verifyECDSADER(attPubKey, hash[:], stmt.Sig) {
			return errors.New("fido-u2f attestation signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported attestation format %q", att.Format)
	}
}

// ParseAuthenticatorData parses raw authenticatorData bytes into ad and
// validates structural and flag invariants per W3C WebAuthn Level 3 §6.1.
func ParseAuthenticatorData(raw []byte, ad *AuthenticatorData) error {
	// https://w3c.github.io/webauthn/#sctn-authenticator-data
	if ad == nil {
		return errors.New("nil AuthenticatorData")
	}
	if len(raw) < 37 {
		return ErrTooShort
	}
	*ad = AuthenticatorData{}
	ad.RPIDHash = Bytes(bytes.Clone(raw[:32]))
	raw = raw[32:]
	ad.Flags = raw[0]
	ad.UserPresence = raw[0]&FlagUserPresent != 0
	ad.UserVerification = raw[0]&FlagUserVerified != 0
	ad.BackupEligible = raw[0]&FlagBackupEligible != 0
	ad.BackupState = raw[0]&FlagBackupState != 0
	ad.AttestedCredentialData = raw[0]&FlagAttestedCredentialData != 0
	ad.ExtensionData = raw[0]&FlagExtensionData != 0
	raw = raw[1:]

	// WebAuthn Level 3 §6.1: BS must be 0 if BE is 0.
	if !ad.BackupEligible && ad.BackupState {
		return errors.New("invalid authenticatorData flags: backupState set when backupEligible is false")
	}

	ad.SignCount = binary.BigEndian.Uint32(raw[:4])
	raw = raw[4:]

	if ad.AttestedCredentialData {
		// https://w3c.github.io/webauthn/#sctn-attested-credential-data
		if len(raw) < 18 {
			return ErrTooShort
		}
		ad.AttestedCredentials = &AttestedCredentials{}
		ad.AttestedCredentials.AAGUID = Bytes(bytes.Clone(raw[:16]))
		raw = raw[16:]

		sz := binary.BigEndian.Uint16(raw[:2])
		raw = raw[2:]
		if sz < 16 || sz > 1023 {
			return errors.New("invalid credentialId length")
		}
		if len(raw) < int(sz) {
			return ErrTooShort
		}
		ad.AttestedCredentials.ID = Bytes(bytes.Clone(raw[:int(sz)]))
		raw = raw[int(sz):]

		var coseKey cbor.RawMessage
		var err error
		if raw, err = cborDecMode.UnmarshalFirst(raw, &coseKey); err != nil {
			return err
		}
		if len(coseKey) == 0 || coseKey[0]>>5 != 5 {
			return errors.New("invalid COSEKey CBOR type")
		}
		var coseMap map[any]any
		if rem, err := cborDecMode.UnmarshalFirst(coseKey, &coseMap); err != nil || len(rem) != 0 {
			return errors.New("invalid COSEKey CBOR map")
		}
		ad.AttestedCredentials.COSEKey = Bytes(bytes.Clone(coseKey))
	}
	if ad.ExtensionData {
		if len(raw) == 0 {
			return ErrTooShort
		}
		var ext cbor.RawMessage
		var err error
		if raw, err = cborDecMode.UnmarshalFirst(raw, &ext); err != nil {
			return err
		}
		if len(ext) == 0 || ext[0]>>5 != 5 {
			return errors.New("invalid extensions CBOR type")
		}
		var extMap map[any]any
		if rem, err := cborDecMode.UnmarshalFirst(ext, &extMap); err != nil || len(rem) != 0 {
			return errors.New("invalid extensions CBOR map")
		}
		ad.Extensions = Bytes(bytes.Clone(ext))
	}
	if len(raw) != 0 {
		return errors.New("unexpected trailing bytes in authenticatorData")
	}
	return nil
}

// ParseCOSEKey parses and validates a CBOR-encoded COSE_Key (RFC 9052 /
// RFC 9053 / RFC 8230 / RFC 8812) and returns the corresponding
// crypto.PublicKey and COSE algorithm identifier.
func ParseCOSEKey(coseKey []byte) (crypto.PublicKey, int, error) {
	if len(coseKey) == 0 || coseKey[0]>>5 != 5 {
		return nil, 0, errors.New("invalid COSEKey CBOR type")
	}
	var header struct {
		KTY int `cbor:"1,keyasint"`
		ALG int `cbor:"3,keyasint"`
	}
	rest, err := cborDecMode.UnmarshalFirst(coseKey, &header)
	if err != nil {
		return nil, 0, fmt.Errorf("cbor.Unmarshal: %w", err)
	}
	if len(rest) != 0 {
		return nil, 0, errors.New("unexpected trailing bytes in COSEKey")
	}

	switch header.KTY {
	case 1: // OKP public key (RFC 9053 §7.2)
		var okpKey struct {
			KTY   int    `cbor:"1,keyasint"`
			ALG   int    `cbor:"3,keyasint"`
			Curve int    `cbor:"-1,keyasint"`
			X     []byte `cbor:"-2,keyasint"`
		}
		if err := cborDecMode.Unmarshal(coseKey, &okpKey); err != nil {
			return nil, 0, err
		}
		if okpKey.ALG != AlgEdDSA {
			return nil, 0, fmt.Errorf("unexpected OKP key alg %d", okpKey.ALG)
		}
		if okpKey.Curve != 6 { // Ed25519
			return nil, 0, fmt.Errorf("unexpected OKP key curve %d", okpKey.Curve)
		}
		if len(okpKey.X) != ed25519.PublicKeySize {
			return nil, 0, fmt.Errorf("invalid Ed25519 public key length %d", len(okpKey.X))
		}
		return ed25519.PublicKey(bytes.Clone(okpKey.X)), AlgEdDSA, nil

	case 2: // EC2 public key (RFC 9053 §7.1)
		var ecKey struct {
			KTY   int    `cbor:"1,keyasint"`
			ALG   int    `cbor:"3,keyasint"`
			Curve int    `cbor:"-1,keyasint"`
			X     []byte `cbor:"-2,keyasint"`
			Y     []byte `cbor:"-3,keyasint"`
		}
		if err := cborDecMode.Unmarshal(coseKey, &ecKey); err != nil {
			return nil, 0, err
		}
		var (
			stdCurve  elliptic.Curve
			ecdhCurve ecdh.Curve
			coordLen  int
		)
		switch ecKey.ALG {
		case AlgES256:
			if ecKey.Curve != 1 { // P-256
				return nil, 0, errors.New("unexpected EC key curve for ES256")
			}
			stdCurve = elliptic.P256()
			ecdhCurve = ecdh.P256()
			coordLen = 32
		case AlgES384:
			if ecKey.Curve != 2 { // P-384
				return nil, 0, errors.New("unexpected EC key curve for ES384")
			}
			stdCurve = elliptic.P384()
			ecdhCurve = ecdh.P384()
			coordLen = 48
		case AlgES512:
			if ecKey.Curve != 3 { // P-521
				return nil, 0, errors.New("unexpected EC key curve for ES512")
			}
			stdCurve = elliptic.P521()
			ecdhCurve = ecdh.P521()
			coordLen = 66
		default:
			return nil, 0, fmt.Errorf("unexpected EC key alg %d", ecKey.ALG)
		}
		// RFC 9053 §7.1.1: X and Y MUST be the fixed size of a coordinate for the curve.
		if len(ecKey.X) != coordLen || len(ecKey.Y) != coordLen {
			return nil, 0, fmt.Errorf("invalid EC coordinate length (%d, %d), want %d", len(ecKey.X), len(ecKey.Y), coordLen)
		}
		uncompressed := make([]byte, 1+2*coordLen)
		uncompressed[0] = 0x04
		copy(uncompressed[1:1+coordLen], ecKey.X)
		copy(uncompressed[1+coordLen:], ecKey.Y)
		if _, err := ecdhCurve.NewPublicKey(uncompressed); err != nil {
			return nil, 0, errors.New("invalid EC public key point")
		}
		return &ecdsa.PublicKey{
			Curve: stdCurve,
			X:     new(big.Int).SetBytes(ecKey.X),
			Y:     new(big.Int).SetBytes(ecKey.Y),
		}, ecKey.ALG, nil

	case 3: // RSA public key (RFC 8230 §4 / RFC 8812 §2)
		var rsaKey struct {
			KTY int    `cbor:"1,keyasint"`
			ALG int    `cbor:"3,keyasint"`
			N   []byte `cbor:"-1,keyasint"`
			E   []byte `cbor:"-2,keyasint"`
		}
		if err := cborDecMode.Unmarshal(coseKey, &rsaKey); err != nil {
			return nil, 0, err
		}
		switch rsaKey.ALG {
		case AlgRS256, AlgRS384, AlgRS512, AlgPS256, AlgPS384, AlgPS512:
		default:
			return nil, 0, fmt.Errorf("unexpected RSA key alg %d", rsaKey.ALG)
		}
		// RFC 8230 §4: N and E are unsigned big-endian representations stripped of leading zeros.
		if len(rsaKey.N) == 0 || rsaKey.N[0] == 0 {
			return nil, 0, errors.New("invalid RSA modulus encoding")
		}
		if len(rsaKey.E) == 0 || rsaKey.E[0] == 0 {
			return nil, 0, errors.New("invalid RSA exponent encoding")
		}
		n := new(big.Int).SetBytes(rsaKey.N)
		if n.BitLen() < 2048 || n.Bit(0) == 0 {
			return nil, 0, errors.New("invalid RSA modulus")
		}
		e := new(big.Int).SetBytes(rsaKey.E)
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Bit(0) == 0 {
			return nil, 0, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		}, rsaKey.ALG, nil

	default:
		return nil, 0, fmt.Errorf("unsupported COSE key type %d", header.KTY)
	}
}

// MarshalCOSEKey encodes a crypto.PublicKey (*ecdsa.PublicKey,
// ed25519.PublicKey, or *rsa.PublicKey) as a CBOR COSE_Key structure using its
// default COSE algorithm (AlgES256/AlgES384/AlgES512 for ECDSA, AlgEdDSA for
// Ed25519, and AlgRS256 for RSA). To specify an explicit RSA algorithm (such as
// AlgPS256 or AlgRS384), use MarshalCOSEKeyWithAlg.
func MarshalCOSEKey(pub crypto.PublicKey) (Bytes, error) {
	return MarshalCOSEKeyWithAlg(pub, 0)
}

// MarshalCOSEKeyWithAlg encodes a crypto.PublicKey as a CBOR COSE_Key structure
// with the specified COSE algorithm identifier (if alg is 0, the default
// algorithm for the key type is used).
func MarshalCOSEKeyWithAlg(pub crypto.PublicKey, alg int) (Bytes, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key size")
		}
		if alg != 0 && alg != AlgEdDSA {
			return nil, fmt.Errorf("invalid algorithm %d for Ed25519 key", alg)
		}
		okpKey := struct {
			KTY   int    `cbor:"1,keyasint"`
			ALG   int    `cbor:"3,keyasint"`
			Curve int    `cbor:"-1,keyasint"`
			X     []byte `cbor:"-2,keyasint"`
		}{
			KTY:   1,
			ALG:   AlgEdDSA,
			Curve: 6,
			X:     bytes.Clone(k),
		}
		return cbor.Marshal(okpKey)

	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("nil ECDSA public key")
		}
		return marshalECDSACOSEKey(*k, alg)

	case ecdsa.PublicKey:
		return marshalECDSACOSEKey(k, alg)

	case *rsa.PublicKey:
		if k == nil {
			return nil, errors.New("nil RSA public key")
		}
		return marshalRSACOSEKey(*k, alg)

	case rsa.PublicKey:
		return marshalRSACOSEKey(k, alg)

	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func marshalECDSACOSEKey(k ecdsa.PublicKey, wantAlg int) (Bytes, error) {
	var (
		alg       int
		crv       int
		coordLen  int
		ecdhCurve ecdh.Curve
	)
	switch k.Curve {
	case elliptic.P256():
		alg, crv, coordLen, ecdhCurve = AlgES256, 1, 32, ecdh.P256()
	case elliptic.P384():
		alg, crv, coordLen, ecdhCurve = AlgES384, 2, 48, ecdh.P384()
	case elliptic.P521():
		alg, crv, coordLen, ecdhCurve = AlgES512, 3, 66, ecdh.P521()
	default:
		return nil, errors.New("unsupported EC curve")
	}
	if wantAlg != 0 && wantAlg != alg {
		return nil, fmt.Errorf("invalid algorithm %d for curve", wantAlg)
	}
	if k.X == nil || k.Y == nil || k.X.Sign() < 0 || k.Y.Sign() < 0 || k.X.BitLen() > coordLen*8 || k.Y.BitLen() > coordLen*8 {
		return nil, errors.New("invalid EC public key coordinates")
	}
	x := make([]byte, coordLen)
	y := make([]byte, coordLen)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	uncompressed := make([]byte, 1+2*coordLen)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+coordLen], x)
	copy(uncompressed[1+coordLen:], y)
	if _, err := ecdhCurve.NewPublicKey(uncompressed); err != nil {
		return nil, errors.New("invalid EC public key point")
	}
	ecKey := struct {
		KTY   int    `cbor:"1,keyasint"`
		ALG   int    `cbor:"3,keyasint"`
		Curve int    `cbor:"-1,keyasint"`
		X     []byte `cbor:"-2,keyasint"`
		Y     []byte `cbor:"-3,keyasint"`
	}{
		KTY:   2,
		ALG:   alg,
		Curve: crv,
		X:     x,
		Y:     y,
	}
	return cbor.Marshal(ecKey)
}

func marshalRSACOSEKey(k rsa.PublicKey, alg int) (Bytes, error) {
	if alg == 0 {
		alg = AlgRS256
	}
	switch alg {
	case AlgRS256, AlgRS384, AlgRS512, AlgPS256, AlgPS384, AlgPS512:
	default:
		return nil, fmt.Errorf("unsupported RSA algorithm %d", alg)
	}
	if k.N == nil || k.N.Sign() <= 0 || k.N.BitLen() < 2048 || k.N.Bit(0) == 0 {
		return nil, errors.New("invalid RSA modulus")
	}
	if k.E < 3 || k.E > 1<<31-1 || k.E&1 == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	rsaKey := struct {
		KTY int    `cbor:"1,keyasint"`
		ALG int    `cbor:"3,keyasint"`
		N   []byte `cbor:"-1,keyasint"`
		E   []byte `cbor:"-2,keyasint"`
	}{
		KTY: 3,
		ALG: alg,
		N:   k.N.Bytes(),
		E:   big.NewInt(int64(k.E)).Bytes(),
	}
	return cbor.Marshal(rsaKey)
}

func signedBytes(authData, clientDataJSON []byte) []byte {
	clientDataHash := sha256.Sum256(clientDataJSON)
	out := make([]byte, len(authData)+len(clientDataHash))
	copy(out, authData)
	copy(out[len(authData):], clientDataHash[:])
	return out
}

func verifyECDSADER(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	var rs struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(sig, &rs)
	if err != nil || len(rest) != 0 {
		return false
	}
	n := pub.Curve.Params().N
	if rs.R == nil || rs.S == nil || rs.R.Sign() <= 0 || rs.R.Cmp(n) >= 0 || rs.S.Sign() <= 0 || rs.S.Cmp(n) >= 0 {
		return false
	}
	return ecdsa.VerifyASN1(pub, hash, sig)
}

func verifySignatureWithPublicKey(pubKey crypto.PublicKey, alg int, signed, signature []byte) error {
	switch alg {
	case AlgEdDSA:
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("key type mismatch for EdDSA")
		}
		if !ed25519.Verify(edKey, signed, signature) {
			return errors.New("invalid signature")
		}
		return nil

	case AlgES256:
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok || ecKey.Curve != elliptic.P256() {
			return errors.New("key type mismatch for ES256")
		}
		h := sha256.Sum256(signed)
		if !verifyECDSADER(ecKey, h[:], signature) {
			return errors.New("invalid signature")
		}
		return nil

	case AlgES384:
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok || ecKey.Curve != elliptic.P384() {
			return errors.New("key type mismatch for ES384")
		}
		h := sha512.Sum384(signed)
		if !verifyECDSADER(ecKey, h[:], signature) {
			return errors.New("invalid signature")
		}
		return nil

	case AlgES512:
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok || ecKey.Curve != elliptic.P521() {
			return errors.New("key type mismatch for ES512")
		}
		h := sha512.Sum512(signed)
		if !verifyECDSADER(ecKey, h[:], signature) {
			return errors.New("invalid signature")
		}
		return nil

	case AlgRS256:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for RS256")
		}
		h := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, h[:], signature)

	case AlgRS384:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for RS384")
		}
		h := sha512.Sum384(signed)
		return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA384, h[:], signature)

	case AlgRS512:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for RS512")
		}
		h := sha512.Sum512(signed)
		return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA512, h[:], signature)

	case AlgPS256:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for PS256")
		}
		h := sha256.Sum256(signed)
		return rsa.VerifyPSS(rsaKey, crypto.SHA256, h[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})

	case AlgPS384:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for PS384")
		}
		h := sha512.Sum384(signed)
		return rsa.VerifyPSS(rsaKey, crypto.SHA384, h[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})

	case AlgPS512:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for PS512")
		}
		h := sha512.Sum512(signed)
		return rsa.VerifyPSS(rsaKey, crypto.SHA512, h[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})

	default:
		return fmt.Errorf("unsupported signature algorithm %d", alg)
	}
}

// VerifySignature verifies a WebAuthn assertion or attestation signature over
// authData || SHA-256(clientDataJSON) using the given CBOR-encoded COSE_Key.
func VerifySignature(coseKey, authData, clientDataJSON, signature []byte) error {
	pubKey, alg, err := ParseCOSEKey(coseKey)
	if err != nil {
		return err
	}
	signed := signedBytes(authData, clientDataJSON)
	return verifySignatureWithPublicKey(pubKey, alg, signed, signature)
}

// recoverCandidatesP256 returns every ECDSA public key that could have produced
// the signature (r, s) over hash. There are up to four, and a second signature
// over a different hash is needed to tell them apart.
//
// The implementation is specific to P-256: it relies on the curve equation
// having a == -3, and on p ≡ 3 (mod 4) so that a square root modulo p can be
// computed as ySq^((p+1)/4).
func recoverCandidatesP256(hash []byte, r, s *big.Int) []*ecdsa.PublicKey {
	curve := elliptic.P256()
	params := curve.Params()
	p := params.P
	n := params.N

	// r and s are used below both as a curve coordinate and as scalars, and
	// crypto/elliptic panics (rather than returning an error) when handed a
	// point that is not on the curve. Callers validate these too; this guard
	// keeps the panic unreachable if a new caller forgets.
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return nil
	}

	e := new(big.Int).SetBytes(hash)
	e.Mod(e, n)
	rInv := new(big.Int).ModInverse(r, n)
	if rInv == nil {
		return nil
	}

	eGx, eGy := curve.ScalarBaseMult(e.Bytes())
	// Negate eG. crypto/elliptic represents the point at infinity as (0, 0),
	// whose negation must stay (0, 0) rather than becoming (0, p).
	neGy := new(big.Int)
	if eGy.Sign() != 0 {
		neGy.Sub(p, eGy)
	}

	var res []*ecdsa.PublicKey

	xs := []*big.Int{r}
	if rPlusN := new(big.Int).Add(r, n); rPlusN.Cmp(p) < 0 {
		xs = append(xs, rPlusN)
	}

	for _, x := range xs {
		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)
		threeX := new(big.Int).Mul(big.NewInt(3), x)
		ySq := new(big.Int).Sub(x3, threeX)
		ySq.Add(ySq, params.B)
		ySq.Mod(ySq, p)

		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Div(exp, big.NewInt(4))
		y := new(big.Int).Exp(ySq, exp, p)

		check := new(big.Int).Exp(y, big.NewInt(2), p)
		if check.Cmp(ySq) != 0 {
			// ySq is not a quadratic residue, so this x is not on the curve.
			continue
		}

		yCands := []*big.Int{y}
		if y.Sign() != 0 {
			yCands = append(yCands, new(big.Int).Sub(p, y))
		}

		for _, yCand := range yCands {
			sRx, sRy := curve.ScalarMult(x, yCand, s.Bytes())
			diffX, diffY := curve.Add(sRx, sRy, eGx, neGy)
			qx, qy := curve.ScalarMult(diffX, diffY, rInv.Bytes())
			if qx.Sign() == 0 && qy.Sign() == 0 {
				// Point at infinity; not a usable public key.
				continue
			}
			res = append(res, &ecdsa.PublicKey{
				Curve: curve,
				X:     qx,
				Y:     qy,
			})
		}
	}
	return res
}

// RecoverPublicKey recovers the ECDSA P-256 public key from two WebAuthn
// assertions using different challenges. Two assertions are required to
// uniquely identify the public key among the mathematically possible ECDSA
// recovery candidates.
func RecoverPublicKey(authData1, clientDataJSON1, sig1Bytes, authData2, clientDataJSON2, sig2Bytes []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	n := curve.Params().N

	var sig1, sig2 struct {
		R, S *big.Int
	}
	rest1, err := asn1.Unmarshal(sig1Bytes, &sig1)
	if err != nil {
		return nil, fmt.Errorf("sig1: %w", err)
	}
	if len(rest1) != 0 {
		return nil, errors.New("sig1: unexpected trailing bytes")
	}
	rest2, err := asn1.Unmarshal(sig2Bytes, &sig2)
	if err != nil {
		return nil, fmt.Errorf("sig2: %w", err)
	}
	if len(rest2) != 0 {
		return nil, errors.New("sig2: unexpected trailing bytes")
	}
	// asn1.Unmarshal accepts negative integers and values larger than the group
	// order. Both are out of range for ECDSA and would panic inside
	// crypto/elliptic, so reject them here with a usable error message.
	for i, sig := range []struct{ R, S *big.Int }{sig1, sig2} {
		if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.R.Cmp(n) >= 0 || sig.S.Sign() <= 0 || sig.S.Cmp(n) >= 0 {
			return nil, fmt.Errorf("sig%d: signature value out of range", i+1)
		}
	}

	hash1 := sha256.Sum256(signedBytes(authData1, clientDataJSON1))
	hash2 := sha256.Sum256(signedBytes(authData2, clientDataJSON2))
	if hash1 == hash2 || (sig1.R.Cmp(sig2.R) == 0 && sig1.S.Cmp(sig2.S) == 0) {
		return nil, errors.New("assertions must be distinct")
	}

	cands1 := recoverCandidatesP256(hash1[:], sig1.R, sig1.S)
	cands2 := recoverCandidatesP256(hash2[:], sig2.R, sig2.S)

	seen := make(map[string]bool)
	var matches []*ecdsa.PublicKey
	for _, c1 := range cands1 {
		for _, c2 := range cands2 {
			if c1.X.Cmp(c2.X) != 0 || c1.Y.Cmp(c2.Y) != 0 {
				continue
			}
			var key [65]byte
			key[0] = 0x04
			c1.X.FillBytes(key[1:33])
			c1.Y.FillBytes(key[33:65])
			k := string(key[:])
			if seen[k] {
				continue
			}
			seen[k] = true
			matches = append(matches, c1)
		}
	}

	if len(matches) == 0 {
		return nil, errors.New("no matching public key found from assertions")
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("multiple matching public keys found (%d)", len(matches))
	}
	pk := matches[0]
	if !verifyECDSADER(pk, hash1[:], sig1Bytes) || !verifyECDSADER(pk, hash2[:], sig2Bytes) {
		return nil, errors.New("recovered public key failed signature verification")
	}
	return pk, nil
}
