// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nist

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/cymony/cryptomony/eccgroup/internal"
)

// Element implements the Element interface for group elements over NIST curves.
type Element[Point nistECGenericPoint[Point]] struct {
	p   Point
	new func() Point
}

func checkElement[Point nistECGenericPoint[Point]](element internal.Element) *Element[Point] {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := element.(*Element[Point])
	if !ok {
		panic(internal.ErrCastElement)
	}

	return ec
}

// Base sets the element to the group's base point a.k.a. canonical generator.
func (e *Element[Point]) Base() internal.Element {
	e.p.SetGenerator()
	return e
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element[Point]) Identity() internal.Element {
	e.p = e.new()
	return e
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element[Point]) Add(element internal.Element) internal.Element {
	ec := checkElement[Point](element)
	e.p.Add(e.p, ec.p)

	return e
}

// Double sets the receiver to its double, and returns it.
func (e *Element[Point]) Double() internal.Element {
	e.p.Double(e.p)
	return e
}

// negateSmall returns the compressed byte encoding of the negated element e with 5 allocs in 13000 ns/op.
func (e *Element[Point]) negateSmall() []byte {
	enc := e.p.BytesCompressed()
	switch enc[0] {
	case 2: //nolint:gomnd //no need constant
		enc[0] = 0x03
	case 3: //nolint:gomnd //no need constant
		enc[0] = 0x02
	default:
		panic("invalid encoding header")
	}

	return enc
}

// Negate sets the receiver to its negation, and returns it.
func (e *Element[P]) Negate() internal.Element {
	_, err := e.p.SetBytes(e.negateSmall())
	if err != nil {
		panic(err)
	}

	return e
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (e *Element[P]) Subtract(element internal.Element) internal.Element {
	ec := checkElement[P](element).negateSmall()

	p, err := e.new().SetBytes(ec)
	if err != nil {
		panic(err)
	}

	e.p.Add(e.p, p)

	return e
}

// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
func (e *Element[P]) Multiply(scalar internal.Scalar) internal.Element {
	if _, err := e.p.ScalarMult(e.p, scalar.Encode()); err != nil {
		panic(err)
	}

	return e
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element[Point]) Equal(element internal.Element) int {
	ec := checkElement[Point](element)

	return subtle.ConstantTimeCompare(e.p.Bytes(), ec.p.Bytes())
}

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element[P]) IsIdentity() bool {
	b := e.p.BytesCompressed()
	i := e.new().BytesCompressed()

	return subtle.ConstantTimeCompare(b, i) == 1
}

// Set sets the receiver to the argument, and returns the receiver.
func (e *Element[P]) Set(element internal.Element) internal.Element {
	if element == nil {
		e.Identity()
		return e
	}

	ec, ok := element.(*Element[P])
	if !ok {
		panic(internal.ErrCastElement)
	}

	p, err := e.p.SetBytes(ec.p.Bytes())
	if err != nil {
		panic(err)
	}

	e.p = p

	return e
}

// Copy returns a copy of the receiver.
func (e *Element[P]) Copy() internal.Element {
	return &Element[P]{
		p:   e.new().Set(e.p),
		new: e.new,
	}
}

// Encode returns the compressed byte encoding of the element.
func (e *Element[P]) Encode() []byte {
	return e.p.BytesCompressed()
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element[P]) Decode(data []byte) error {
	if _, err := e.p.SetBytes(data); err != nil {
		return fmt.Errorf("nist element Decode: %w", err)
	}

	return nil
}

// MarshalBinary returns the compressed byte encoding of the element.
func (e *Element[P]) MarshalBinary() ([]byte, error) {
	return e.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (e *Element[P]) UnmarshalBinary(data []byte) error {
	return e.Decode(data)
}

// MarshalText implements the encoding.MarshalText interface.
func (e *Element[P]) MarshalText() (text []byte, err error) {
	b := e.Encode()
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements the encoding.UnmarshalText interface.
func (e *Element[P]) UnmarshalText(text []byte) error {
	eb, err := base64.StdEncoding.DecodeString(string(text))
	if err == nil {
		return e.Decode(eb)
	}

	return fmt.Errorf("nist element UnmarshalText: %w", err)
}
