// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

import "errors"

var (
	ErrInvalidSuite    = errors.New("oprf: invalid suite")
	ErrInvalidMode     = errors.New("oprf: invalid mode")
	ErrDeriveKeyError  = errors.New("oprf: key derivation failed")
	ErrInvalidInput    = errors.New("oprf: blind input produces an invalid output element")
	ErrVerify          = errors.New("oprf: verifiable OPRF proof verification failed")
	ErrInverse         = errors.New("oprf: a tweaked private key is invalid (has no multiplicative inverse)")
	ErrDeserialize     = errors.New("oprf: group element or scalar deserialization failure")
	ErrInputValidation = errors.New("oprf: validation of inputs failed")
	ErrEmptyKey        = errors.New("oprf: empty key")
)
