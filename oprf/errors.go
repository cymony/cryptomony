// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

import "errors"

var (
	// ErrInvalidSuite indicates that given oprf suite is not supported
	ErrInvalidSuite = errors.New("oprf: invalid suite")
	// ErrInvalidMode indicates that given oprf mode is not supported
	ErrInvalidMode = errors.New("oprf: invalid mode")
	// ErrDeriveKeyError indicates that key derivation operation failed
	ErrDeriveKeyError = errors.New("oprf: key derivation failed")
	// ErrInvalidInput indicates that given input value produces identity element
	ErrInvalidInput = errors.New("oprf: blind input produces an invalid output element")
	// ErrVerify indicates that proof verification failed
	ErrVerify = errors.New("oprf: verifiable OPRF proof verification failed")
	// ErrInputValidation indicates that given inputs are not suitable
	ErrInputValidation = errors.New("oprf: validation of inputs failed")
	// ErrEmptyKey indicates that given key is nil or empty
	ErrEmptyKey = errors.New("oprf: empty key")

	errInverse = errors.New("oprf: a tweaked private key is invalid (has no multiplicative inverse)")
)
