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

//go:build js && wasm

package ssh_test

import (
	"crypto/rand"
	"encoding/pem"
	"log"

	gossh "golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/webauthn/ssh"
)

func ExampleCreate() {
	key, err := ssh.Create("my-key", true)
	if err != nil {
		log.Fatal(err)
	}
	block, err := key.MarshalPrivate("passphrase")
	if err != nil {
		log.Fatal(err)
	}

	// Placeholder storage (e.g. IndexedDB or localStorage) for the PEM key handle,
	// and placeholder communication to register the authorized_keys line on the server.
	pemBytes := pem.EncodeToMemory(block)
	authorizedKey := gossh.MarshalAuthorizedKey(key)
	_, _ = pemBytes, authorizedKey
}

func ExampleKey_Sign() {
	// Placeholder storage: load the previously saved PEM key handle,
	// and placeholder communication: receive the authentication challenge from the server.
	var pemBytes []byte
	var challenge []byte

	key, err := ssh.Unmarshal(pemBytes, "my-key", func(string) (string, error) {
		return "passphrase", nil
	})
	if err != nil {
		log.Fatal(err)
	}
	sig, err := key.Sign(rand.Reader, challenge)
	if err != nil {
		log.Fatal(err)
	}

	// Placeholder for sending the marshaled signature back to the server.
	sigBytes := gossh.Marshal(sig)
	_ = sigBytes
}
