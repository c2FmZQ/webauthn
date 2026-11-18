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
//
// [Key] implements [golang.org/x/crypto/ssh.PublicKey] on all platforms and
// [golang.org/x/crypto/ssh.Signer] when built for browser WebAssembly
// (GOOS=js GOARCH=wasm).
//
// # Key Registration
//
// A [Key] can be registered either on a server from a standard WebAuthn
// registration ceremony or directly in a browser WebAssembly client:
//
//   - Server-driven registration: run a WebAuthn registration ceremony using
//     [github.com/c2FmZQ/webauthn.NewAttestationOptions] (restricted to
//     [github.com/c2FmZQ/webauthn.AlgES256]) and
//     [github.com/c2FmZQ/webauthn.VerifyAttestation], then construct a [Key]
//     with [NewKey].
//   - Browser WASM registration (GOOS=js GOARCH=wasm): call Create(name,
//     resident) to invoke navigator.credentials.create() and verify the
//     resulting P-256 credential locally.
//
// Once created, the public key can be formatted for OpenSSH authorized_keys
// with [golang.org/x/crypto/ssh.MarshalAuthorizedKey] or signed into an
// OpenSSH certificate (see [CertType]). The key handle and metadata can be
// serialized with [Key.MarshalPrivate] as a PEM-encoded WEBAUTHN KEY or
// passphrase-protected WEBAUTHN ENCRYPTED KEY.
//
// # Authentication and Signature Verification
//
// Stored keys are loaded with [Unmarshal] (from PEM) or [UnmarshalPublic]
// (from OpenSSH wire format, e.g. after [golang.org/x/crypto/ssh.ParseAuthorizedKey]).
//
// In a browser WebAssembly client (GOOS=js GOARCH=wasm), (*Key).Sign produces
// an OpenSSH signature in [SignatureFormat] via navigator.credentials.get(),
// and Discover recovers a resident ECDSA P-256 key from two assertions.
//
// On any platform, [Key.Verify] verifies both hardware security key signatures
// ([KeyType]) and browser WebAuthn signatures ([SignatureFormat]).
package ssh
