// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

// Package ksf is a small wrapper around built-in cryptographic key strech functions to make their usage easier and safer
package ksf

type Identifier uint

const (
	// Supported algorithms' identifiers
	Argon2id Identifier = 1 + iota
	Bcrypt
	Scrypt
)

// New returns a new KSF instance of receiver identifier
func (i Identifier) New() KSF {
	switch i {
	case Argon2id:
		return newArgon2id()
	case Bcrypt:
		return newBcrypt()
	case Scrypt:
		return newScryptKSF()
	default:
		panic(ErrNotSupportedAlgorithm)
	}
}

// KSF is an interface that identifies the supported KSF algorithms
type KSF interface {
	// Harden uses default parameters (if custom option is not applied) for the key derivation function over the input password and salt
	Harden(password, salt []byte, length int) ([]byte, error)
	// SetOptions lets change the functions parameters with the new ones
	SetOptions(options ...Option) error
	// String returns the string representation with current parameters
	String() string
}
