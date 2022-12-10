// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package internal

import "encoding"

// Scalar interface represents the scalar of underlying curve's scalar
type Scalar interface {
	// Zero sets the scalar to 0, and returns it.
	Zero() Scalar

	// One sets the scalar to 1, and returns it.
	One() Scalar

	// Random sets the current scalar to a new random scalar and returns it.
	// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
	Random() Scalar

	// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
	Add(s Scalar) Scalar

	// Subtract subtracts the input from the receiver, and returns the receiver.
	Subtract(s Scalar) Scalar

	// Multiply multiplies the receiver with the input, and returns the receiver.
	// If s parameter is nil, then the receiver is not modified
	Multiply(s Scalar) Scalar

	// Invert sets the receiver to the scalar's modular inverse ( 1 / scalar ), and returns it.
	Invert() Scalar

	// Equal returns 1 if the scalars are equal, and 0 otherwise.
	Equal(s Scalar) int

	// IsZero returns whether the scalar is 0.
	IsZero() bool

	// Set sets the receiver to the value of the argument scalar, and returns the receiver.
	// If s parameter is nil, then the receiver is not modified
	Set(s Scalar) Scalar

	// Copy returns a copy of the receiver.
	Copy() Scalar

	// Encode returns the compressed byte encoding of the scalar.
	Encode() []byte

	// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
	Decode(in []byte) error

	// BinaryMarshaler returns a byte representation of the element.
	encoding.BinaryMarshaler

	// BinaryUnmarshaler recovers an element from a byte representation
	// produced either by encoding.BinaryMarshaler or MarshalBinaryCompress.
	encoding.BinaryUnmarshaler

	// TextMarshaler returns a base64 standard string encoding of the element.
	encoding.TextMarshaler

	// TextUnmarshaler sets the base64 standard string encoding of the element.
	encoding.TextUnmarshaler
}
