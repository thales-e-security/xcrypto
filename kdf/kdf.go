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
	"crypto"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	// Force registration of SHA1 and SHA2 families of cryptographic primitives to
	// reduce the burden on KDF consuming packages.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

var (
	// errInvalidLengthParameter the KDF length parameter is invalid
	errInvalidLengthParameter = errors.New("invalid length parameter")

	// errInvalidSeedParameter a parameter is invalid.
	errInvalidSeedParameter = errors.New("invalid input parameter")
)

// Verify KDF completely implements the io.Reader interface.
var _ io.Reader = (*KDF)(nil)

// KDF key derivation context struct
type KDF struct {
	seed       []byte
	other      []byte
	length     int
	iterations uint32
	position   int
	buffer     []byte
	digester   hash.Hash
}

// i2osp 4-byte integer marshalling.
func i2osp(i uint32) []byte {
	osp := make([]byte, 4)
	binary.BigEndian.PutUint32(osp, i)
	return osp
}

// min select the minimum value of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Divide x by divisor rounding up. This is equivalent to the math.Ceil(float64(x)/float64(divisor)) using fixed point
// integer arithmetic.
func ceil(x, divisor int64) int64 {
	return (x + (divisor - 1)) / divisor
}

// Read read the next len(p) bytes from the KDF context.
func (kdf *KDF) Read(p []byte) (int, error) {
	var n int
	// When there's no data left return EOF.
	if kdf.length-kdf.position == 0 {
		return 0, io.EOF
	}
	// Read the minimum of everything requested or whatever's left.
	toRead := min(len(p), kdf.length-kdf.position)
	// Use buffered data first to attempt to satisfy request.
	if len(kdf.buffer) > 0 {
		fromBuffer := min(len(kdf.buffer), toRead)
		copy(p, kdf.buffer[:fromBuffer])
		kdf.buffer = kdf.buffer[fromBuffer:]
		n = fromBuffer
		toRead -= fromBuffer
	}

	// If we completely satisfied the read from cache or there's no more data return.
	if toRead == 0 {
		kdf.position += n
		return n, nil
	}

	// Calculate the number of full hash outputs required to satisfy request.
	iterations := ceil(int64(toRead), int64(kdf.digester.Size()))
	for i := int64(0); i < iterations; i++ {
		osp := i2osp(kdf.iterations)
		kdf.iterations++
		if _, err := kdf.digester.Write(kdf.seed); err != nil {
			return 0, err
		}
		if _, err := kdf.digester.Write(osp); err != nil {
			return 0, err
		}
		if _, err := kdf.digester.Write(kdf.other); err != nil {
			return 0, err
		}
		t := kdf.digester.Sum(nil)
		tLen := len(t)
		// The last iteration may have some leftover data which we buffer for the next invocation of read.
		if tLen > toRead {
			kdf.buffer = t[toRead:]
			tLen = toRead
		}
		copy(p[n:], t[:tLen])
		n += tLen
		toRead -= tLen
		kdf.digester.Reset()
	}
	kdf.position += n
	return n, nil
}

func newKDF(seed, other []byte, hash crypto.Hash, offset uint32, length int) (*KDF, error) {
	if len(seed) == 0 {
		return nil, errInvalidSeedParameter
	}
	// See sections 6.2.2.2 and 6.2.3.2 of https://www.shoup.net/iso/std6.pdf.
	// The maximum length is bounded by a 32-bit unsigned counter used in each iteration of the the KDF's inner digest
	// loop. In this loop the counter is incremented by 1 and hash.Size() bytes are returned to the caller.
	k := ceil(int64(length), int64(hash.Size()))
	if k <= 0 || k > ((1<<32)-int64(offset)) {
		return nil, errInvalidLengthParameter
	}
	kdf := &KDF{
		seed:       seed,
		other:      other,
		length:     length,
		iterations: offset,
		position:   0,
		buffer:     nil,
		digester:   hash.New(),
	}
	return kdf, nil
}

// NewKDF1 create a new KDF1 context.
func NewKDF1(seed, other []byte, hash crypto.Hash, length int) (*KDF, error) {
	return newKDF(seed, other, hash, 0, length)
}

// NewKDF2 create a new KDF2 context.
func NewKDF2(seed, other []byte, hash crypto.Hash, length int) (*KDF, error) {
	return newKDF(seed, other, hash, 1, length)
}
