// Copyright 2019 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
package kdf

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
)

// Usage example that expands one master secret into three other
// cryptographically secure keys using KDF2.
func Example_usage() {
	// Cryptographically secure master secret.
	seed := []byte{0x00, 0x01, 0x02, 0x03} // i.e. NOT this.

	// Non-secret context info, optional (can be nil).
	other := []byte("kdf example")

	// Generate three 128-bit/16-byte derived keys.
	kdf, err := NewKDF2(seed, other, crypto.SHA256, 48)
	if err != nil {
		panic(err)
	}

	var keys [][]byte
	for i := 0; i < 3; i++ {
		key := make([]byte, 16)
		if _, err := io.ReadFull(kdf, key); err != nil {
			panic(err)
		}
		keys = append(keys, key)
	}

	for i := range keys {
		fmt.Printf("Key #%d: %v\n", i+1, !bytes.Equal(keys[i], make([]byte, 16)))
	}

	// Output:
	// Key #1: true
	// Key #2: true
	// Key #3: true
}
