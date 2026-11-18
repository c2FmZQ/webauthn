[![Tests](https://github.com/c2FmZQ/webauthn/actions/workflows/pr.yml/badge.svg)](https://github.com/c2FmZQ/webauthn/actions/workflows/pr.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/c2FmZQ/webauthn.svg)](https://pkg.go.dev/github.com/c2FmZQ/webauthn)

# webauthn

`github.com/c2FmZQ/webauthn` is a general-purpose W3C WebAuthn library for Go Relying Parties (servers) and WebAssembly clients, along with OpenSSH FIDO2/WebAuthn security key (`sk-ecdsa-sha2-nistp256@openssh.com` and `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`) support in `github.com/c2FmZQ/webauthn/ssh`.

## Packages

### `github.com/c2FmZQ/webauthn`

Core WebAuthn types, CBOR/COSE key parsing, and ceremony verification:

- **Options & Wire Types**:
  - `AttestationOptions` (`NewAttestationOptions`), `AssertionOptions` (`NewAssertionOptions`), `RelyingPartyEntity`, `UserEntity`, `AuthenticatorSelection`, `PubKeyCredParam`, `CredentialID`.
  - `AttestationResponse` and `AssertionResponse`: unmarshal from both W3C WebAuthn Level 3 `RegistrationResponseJSON` / `AuthenticationResponseJSON` (nested `response` object) and flat JSON objects.
  - `Bytes`: marshals to unpadded `base64url` per WebAuthn Level 3, and unmarshals from both `base64url` strings and `[1, 2, 3]` byte arrays.
- **High-Level Ceremony Verification**:
  - `VerifyAttestation(resp, VerifyAttestationOptions) (*VerifiedCredential, error)` (W3C WebAuthn Level 3 §7.1)
  - `VerifyAssertion(resp, VerifyAssertionOptions) (*VerifiedAssertion, error)` (W3C WebAuthn Level 3 §7.2)
- **Low-Level Primitives**:
  - `ParseClientData` and `VerifyClientData`
  - `ParseAttestationObject` and `(*Attestation).VerifyAttestationStatement` (supports `"none"`, `"packed"` x5c and self-attestation, and `"fido-u2f"`)
  - `ParseAuthenticatorData`
  - `ParseCOSEKey`, `MarshalCOSEKey`, and `MarshalCOSEKeyWithAlg` (`AlgES256`, `AlgEdDSA`, `AlgES384`, `AlgES512`, `AlgPS256`, `AlgPS384`, `AlgPS512`, `AlgRS256`, `AlgRS384`, `AlgRS512`)
  - `VerifySignature`
  - `RecoverPublicKey` (recovers an ECDSA P-256 public key from two WebAuthn assertions)
- **Testing**: `FakeAuthenticator` (`NewFakeAuthenticator`) for testing registration and authentication ceremonies across all supported algorithms and attestation formats.
- **Browser WebAssembly (`GOOS=js GOARCH=wasm`)**: `Create(*AttestationOptions)`, `Get(*AssertionOptions)`, `Origin()`, and `Hostname()` wrapping `navigator.credentials`.

### `github.com/c2FmZQ/webauthn/ssh`

OpenSSH ECDSA P-256 security keys (`sk-ecdsa-sha2-nistp256@openssh.com`) and browser WebAuthn SSH signatures (`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`) per OpenSSH `PROTOCOL.u2f`:

- `Key` implementing `golang.org/x/crypto/ssh.PublicKey` (and `ssh.Signer` under `GOOS=js GOARCH=wasm`)
- `NewKey`, `Unmarshal`, `UnmarshalPublic`, `(*Key).MarshalPrivate`, `(*Key).Verify`
- `Create`, `Discover`, and `(*Key).Sign` under `GOOS=js GOARCH=wasm`
