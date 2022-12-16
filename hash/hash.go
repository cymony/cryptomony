// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hash is a small wrapper around built-in cryptographic hash functions to make their usage easier.
package hash

import (
	"crypto"
	"crypto/hmac"
	stdHash "hash"

	// it prevent panic
	_ "crypto/sha512"
	"io"

	// it prevent panic
	_ "golang.org/x/crypto/blake2b"
	// it prevent panic
	_ "golang.org/x/crypto/blake2s"

	"golang.org/x/crypto/hkdf"
	// it prevent panic
	_ "golang.org/x/crypto/sha3"
)

// Hash interface wraps standart library's hash.Hash interface with additional functions to make usage easier.
type Hash interface {
	// Write (via the embedded io.Writer interface) adds more data to the running hash.
	// It never returns an error.
	io.Writer

	// Sum appends the current hash to b and returns the resulting slice.
	// It does not change the underlying hash state.
	Sum(b []byte) []byte

	// Reset resets the Hash to its initial state.
	Reset()

	// OutputSize returns the number of bytes Sum will return.
	OutputSize() int

	// BlockSize returns the hash's underlying block size.
	// The Write method must be able to accept any amount
	// of data, but it may operate more efficiently if all writes
	// are a multiple of the block size.
	BlockSize() int

	// MustWriteAll writes all inputs into the hash's state.
	MustWriteAll(inputs ...[]byte) error

	// MustReadFull reads exactly len(buf) bytes from hash's state.
	// It does not change the underlying hash state.
	MustReadFull(buff []byte) error

	// String returns string representation of the hash algorithm.
	String() string

	// Hmac wraps the built-in hmac.
	Hmac(message, key []byte) ([]byte, error)

	// HKDFExtract is an "extract" only HKDF, where the secret and salt are used to generate a pseudorandom key. This key
	// can then be used in multiple HKDFExpand calls to derive individual different keys.
	HKDFExtract(secret, salt []byte) []byte

	// HKDFExpand is an "expand" only HKDF, where the key should be an already random/hashed input,
	// and info specific key usage identifying information.
	HKDFExpand(pseudorandomKey, info []byte, length int) []byte
}

// Hashing is type wrapper for crypto.Hash types
type Hashing uint

const (
	SHA224      = Hashing(crypto.SHA224)      //nolint:revive // because of compatibility with crypto library
	SHA256      = Hashing(crypto.SHA256)      //nolint:revive // because of compatibility with crypto library
	SHA384      = Hashing(crypto.SHA384)      //nolint:revive // because of compatibility with crypto library
	SHA512      = Hashing(crypto.SHA512)      //nolint:revive // because of compatibility with crypto library
	SHA3_224    = Hashing(crypto.SHA3_224)    //nolint:revive,stylecheck // because of compatibility with crypto library
	SHA3_256    = Hashing(crypto.SHA3_256)    //nolint:revive,stylecheck // because of compatibility with crypto library
	SHA3_384    = Hashing(crypto.SHA3_384)    //nolint:revive,stylecheck // because of compatibility with crypto library
	SHA3_512    = Hashing(crypto.SHA3_512)    //nolint:revive,stylecheck // because of compatibility with crypto library
	SHA512_224  = Hashing(crypto.SHA512_224)  //nolint:revive,stylecheck // because of compatibility with crypto library
	SHA512_256  = Hashing(crypto.SHA512_256)  //nolint:revive,stylecheck // because of compatibility with crypto library
	BLAKE2s_256 = Hashing(crypto.BLAKE2s_256) //nolint:revive,stylecheck // because of compatibility with crypto library
	BLAKE2b_256 = Hashing(crypto.BLAKE2b_256) //nolint:revive,stylecheck // because of compatibility with crypto library
	BLAKE2b_384 = Hashing(crypto.BLAKE2b_384) //nolint:revive,stylecheck // because of compatibility with crypto library
	BLAKE2b_512 = Hashing(crypto.BLAKE2b_512) //nolint:revive,stylecheck // because of compatibility with crypto library
)

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (i Hashing) New() Hash {
	return &hashWrap{i.CryptoID().New(), i.CryptoID()}
}

// CryptoID returns the built-in crypto identifier corresponding the Hashing identifier.
func (i Hashing) CryptoID() crypto.Hash {
	return crypto.Hash(i)
}

type hashWrap struct {
	stdHash.Hash
	cryptoID crypto.Hash
}

// OutputSize returns the number of bytes Sum will return.
func (hw *hashWrap) OutputSize() int {
	return hw.Hash.Size()
}

// MustWriteAll writes all inputs into the hash's state.
func (hw *hashWrap) MustWriteAll(inputs ...[]byte) error {
	for _, in := range inputs {
		n, err := hw.Hash.Write(in)
		if err != nil {
			return err
		} else if n != len(in) {
			return ErrMismatchLengthWrite
		}
	}

	return nil
}

// MustReadFull reads exactly len(buf) bytes from hash's state.
func (hw *hashWrap) MustReadFull(buff []byte) error {
	hashed := hw.Hash.Sum(nil)
	copy(buff, hashed)

	return nil
}

// String returns string representation of the hash algorithm.
func (hw *hashWrap) String() string {
	return hw.cryptoID.String()
}

// Hmac wraps the built-in hmac.
func (hw *hashWrap) Hmac(message, key []byte) ([]byte, error) {
	hm := hmac.New(hw.cryptoID.New, key)
	n, err := hm.Write(message)

	if err != nil {
		return nil, err
	} else if n != len(message) {
		return nil, ErrMismatchLengthWrite
	}

	return hm.Sum(nil), nil
}

// HKDFExtract is an "extract" only HKDF, where the secret and salt are used to generate a pseudorandom key. This key
// can then be used in multiple HKDFExpand calls to derive individual different keys.
func (hw *hashWrap) HKDFExtract(secret, salt []byte) []byte {
	return hkdf.Extract(hw.cryptoID.New, secret, salt)
}

// HKDFExpand is an "expand" only HKDF, where the key should be an already random/hashed input,
// and info specific key usage identifying information.
func (hw *hashWrap) HKDFExpand(pseudorandomKey, info []byte, length int) []byte {
	if length == 0 {
		length = hw.OutputSize()
	}

	kdf := hkdf.Expand(hw.cryptoID.New, pseudorandomKey, info)
	dst := make([]byte, length)

	_, err := kdf.Read(dst)
	if err != nil {
		panic(err)
	}

	return dst
}
