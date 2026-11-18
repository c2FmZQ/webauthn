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

// Package webauthn implements the server (Relying Party) and browser WebAssembly
// client primitives of the W3C WebAuthn Level 3 specification.
//
// # Registration
//
// Registering a new credential (passkey or security key) is a three-step
// ceremony between the server and the browser:
//
//  1. Server: call [NewAttestationOptions], set RelyingParty and User (and
//     optionally ExcludeCredentials to avoid re-registering existing keys),
//     persist Challenge in session storage, and JSON-marshal the options to
//     send to the browser.
//  2. Browser: pass the options to navigator.credentials.create() (converting
//     base64url byte fields to ArrayBuffer/Uint8Array in JavaScript, or calling
//     Create directly in a GOOS=js GOARCH=wasm client) and send the JSON
//     response back to the server.
//  3. Server: unmarshal [AttestationResponse] (which accepts both W3C Level 3
//     RegistrationResponseJSON and flat JSON), load the expected Challenge from
//     session storage, call [VerifyAttestation] with [VerifyAttestationOptions],
//     and store the resulting [VerifiedCredential] (ID, COSEKey, SignCount,
//     Transports, etc.).
//
// # Authentication
//
// Authenticating with an existing credential follows a similar three-step
// ceremony:
//
//  1. Server: call [NewAssertionOptions], set RPID and AllowCredentials (or
//     leave AllowCredentials empty for discoverable credentials), persist
//     Challenge in session storage, and JSON-marshal the options to send to
//     the browser.
//  2. Browser: pass the options to navigator.credentials.get() (or call Get
//     directly in a GOOS=js GOARCH=wasm client) and send the JSON response back
//     to the server.
//  3. Server: unmarshal [AssertionResponse] (which accepts both W3C Level 3
//     AuthenticationResponseJSON and flat JSON), look up the stored credential
//     using resp.RawID (and resp.UserHandle for discoverable credentials), load
//     the expected Challenge from session storage, call [VerifyAssertion] with
//     [VerifyAssertionOptions], and update the stored SignCount from
//     [VerifiedAssertion].
//
// # Wire Format
//
// Binary fields use [Bytes], which marshals to JSON as unpadded base64url
// strings per W3C WebAuthn Level 3 and unmarshals from either unpadded
// base64url strings or legacy JSON arrays of byte integers.
//
// # Browser WebAssembly Client
//
// When built with GOOS=js GOARCH=wasm, the package additionally provides
// Create, Get, Hostname, and Origin wrapping the browser's
// navigator.credentials API. Binary inputs in Extensions maps must be passed
// as []byte or [Bytes] so they are converted to JavaScript Uint8Array values.
//
// # Low-Level Primitives and Testing
//
// Lower-level building blocks are also exported for custom verification flows:
// [ParseClientData], [VerifyClientData], [ParseAttestationObject],
// [Attestation.VerifyAttestationStatement], [ParseAuthenticatorData],
// [ParseCOSEKey], [MarshalCOSEKey], [MarshalCOSEKeyWithAlg], [VerifySignature],
// and [RecoverPublicKey].
//
// [FakeAuthenticator] ([NewFakeAuthenticator]) simulates an authenticator in
// unit tests and examples across all supported COSE algorithms and attestation
// formats ("none", "packed", and "fido-u2f").
package webauthn
