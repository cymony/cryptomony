// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import "encoding"

// Element interface represents the element of underlying curve's element
type Element interface {
	// Base sets the element to the group's base point a.k.a. canonical generator.
	Base() Element

	// Identity sets the element to the point at infinity of the Group's underlying curve.
	Identity() Element

	// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
	Add(ee Element) Element

	// Double sets the receiver to its double, and returns it.
	Double() Element

	// Negate sets the receiver to its negation, and returns it.
	Negate() Element

	// Subtract subtracts the input from the receiver, and returns the receiver.
	Subtract(ee Element) Element

	// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
	// If s parameter is nil, then the receiver is not modified
	Multiply(s Scalar) Element

	// Equal returns 1 if the elements are equivalent, and 0 otherwise.
	Equal(ee Element) int

	// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
	IsIdentity() bool

	// Set sets the receiver to ee if not nil; else the receiver not modified; returns the receiver.
	Set(ee Element) Element

	// Copy returns a copy of the receiver.
	Copy() Element

	// Encode returns the compressed byte encoding of the element.
	Encode() []byte

	// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
	Decode(data []byte) error

	// BinaryMarshaler implementation.
	encoding.BinaryMarshaler

	// BinaryUnmarshaler implementation.
	encoding.BinaryUnmarshaler

	// TextMarshaler implementation.
	encoding.TextMarshaler

	// TextUnmarshaler implementation.
	encoding.TextUnmarshaler
}
