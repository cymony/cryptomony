// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

// Package internal wraps all nist and ristretto255 curves into interfaces
package internal

// Group interface represents the prime-order group
type Group interface {
	// NewScalar returns a new, empty, scalar.
	NewScalar() Scalar

	// NewElement returns the identity element (point at infinity).
	NewElement() Element

	// RandomScalar returns randomly generated scalar.
	RandomScalar() Scalar

	// RandomElement returns randomly generated element.
	RandomElement() Element

	// Base returns the group's base point a.k.a. canonical generator.
	Base() Element

	// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
	// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
	HashToScalar(input, dst []byte) Scalar

	// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
	// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
	HashToGroup(input, dst []byte) Element

	// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
	// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
	EncodeToGroup(input, dst []byte) Element

	// Ciphersuite returns the hash-to-curve ciphersuite identifier.
	Ciphersuite() string

	// ScalarLength returns the byte size of an encoded scalar.
	ScalarLength() uint

	// ElementLength returns the byte size of an encoded element.
	ElementLength() uint
}
