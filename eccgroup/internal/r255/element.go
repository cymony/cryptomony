// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package r255

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/cymony/cryptomony/eccgroup/internal"
)

// Element represents Ristretto point
type Element struct {
	e *edwards25519.Point
}

func cvtEl(ee internal.Element) *Element {
	if ee == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := ee.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return ec
}

func newElement() internal.Element {
	return &Element{e: edwards25519.NewIdentityPoint()}
}

// Base sets the element to the group's base point a.k.a. canonical generator.
func (e *Element) Base() internal.Element {
	e.e.Set(edwards25519.NewGeneratorPoint())
	return e
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element) Identity() internal.Element {
	e.e.Set(edwards25519.NewIdentityPoint())
	return e
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element) Add(ee internal.Element) internal.Element {
	if ee == nil {
		return e
	}

	ec := cvtEl(ee)
	e.e.Add(e.e, ec.e)

	return e
}

// Double sets the receiver to its double, and returns it.
func (e *Element) Double() internal.Element {
	e.e.Add(e.e, e.e)
	return e
}

// Negate sets the receiver to its negation, and returns it.
func (e *Element) Negate() internal.Element {
	e.e.Negate(e.e)
	return e
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (e *Element) Subtract(ee internal.Element) internal.Element {
	if ee == nil {
		return e
	}

	ec := cvtEl(ee)
	e.e.Subtract(e.e, ec.e)

	return e
}

// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
// If s parameter is nil, then the receiver is not modified
func (e *Element) Multiply(s internal.Scalar) internal.Element {
	if s == nil {
		return e
	}

	sc := cvtScalar(s)
	e.e.ScalarMult(sc.s, e.e)

	return e
}

// Equal returns 1 if e is equivalent to ee, and 0 otherwise.
//
// Note that Elements must not be compared in any other way.
func (e *Element) Equal(ee internal.Element) int {
	if ee == nil {
		return 0
	}

	eee := cvtEl(ee)

	x1, y1, _, _ := e.e.ExtendedCoordinates()
	x2, y2, _, _ := eee.e.ExtendedCoordinates()

	var f0, f1 field.Element

	f0.Multiply(x1, y2) // x1 * y2
	f1.Multiply(y1, x2) // y1 * x2
	out := f0.Equal(&f1)

	f0.Multiply(y1, y2) // y1 * y2
	f1.Multiply(x1, x2) // x1 * x2

	out |= f0.Equal(&f1)

	return out
}

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element) IsIdentity() bool {
	ee := &Element{e: edwards25519.NewIdentityPoint()}
	return e.Equal(ee) == 1
}

// Set sets the receiver to ee if not nil; else the receiver not modified; returns the receiver.
func (e *Element) Set(ee internal.Element) internal.Element {
	if ee == nil {
		e.Identity()
		return e
	}

	ec := cvtEl(ee)

	if err := e.Decode(ec.Encode()); err != nil {
		panic(err)
	}

	return e
}

// Copy returns a copy of the receiver.
func (e *Element) Copy() internal.Element {
	ne := &Element{e: edwards25519.NewIdentityPoint()}

	if err := ne.Decode(e.Encode()); err != nil {
		panic(err)
	}

	return ne
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	return e.Bytes()
}

// Bytes returns the 32 bytes canonical encoding of e.
func (e *Element) Bytes() []byte {
	// Bytes is outlined to let the allocation happen on the stack of the caller.
	b := make([]byte, conanicalSize)
	return e.bytes(b)
}

func (e *Element) bytes(b []byte) []byte {
	X, Y, Z, T := e.e.ExtendedCoordinates()
	tmp := &field.Element{}

	//nolint:gocritic // it is not commented code
	// u1 = (z0 + y0) * (z0 - y0)
	u1 := &field.Element{}
	u1.Add(Z, Y).Multiply(u1, tmp.Subtract(Z, Y))

	// u2 = x0 * y0
	u2 := &field.Element{}
	u2.Multiply(X, Y)

	// Ignore was_square since this is always square
	// (_, invsqrt) = SQRT_RATIO_M1(1, u1 * u2^2)
	invSqrt := &field.Element{}
	invSqrt.SqrtRatio(one, tmp.Square(u2).Multiply(tmp, u1))

	//nolint:gocritic // it is not commented code
	// den1 = invsqrt * u1
	// den2 = invsqrt * u2
	den1, den2 := &field.Element{}, &field.Element{}
	den1.Multiply(invSqrt, u1)
	den2.Multiply(invSqrt, u2)

	//nolint:gocritic // it is not commented code
	// z_inv = den1 * den2 * t0
	zInv := &field.Element{}
	zInv.Multiply(den1, den2).Multiply(zInv, T)

	//nolint:gocritic // it is not commented code
	// ix0 = x0 * SQRT_M1
	// iy0 = y0 * SQRT_M1
	ix0, iy0 := &field.Element{}, &field.Element{}
	ix0.Multiply(X, sqrtM1)
	iy0.Multiply(Y, sqrtM1)

	//nolint:gocritic // it is not commented code
	// enchanted_denominator = den1 * INVSQRT_A_MINUS_D
	enchantedDenominator := &field.Element{}
	enchantedDenominator.Multiply(den1, invSqrtAMinusD)

	//nolint:gocritic // it is not commented code
	// rotate = IS_NEGATIVE(t0 * z_inv)
	rotate := tmp.Multiply(T, zInv).IsNegative()

	// x = CT_SELECT(iy0 IF rotate ELSE x0)
	// y = CT_SELECT(ix0 IF rotate ELSE y0)
	x, y := &field.Element{}, &field.Element{}
	x.Select(iy0, X, rotate)
	y.Select(ix0, Y, rotate)
	// z = z0
	z := Z
	// den_inv = CT_SELECT(enchanted_denominator IF rotate ELSE den2)
	denInv := &field.Element{}
	denInv.Select(enchantedDenominator, den2, rotate)

	//nolint:gocritic // it is not commented code
	// y = CT_NEG(y, IS_NEGATIVE(x * z_inv))
	isNegative := tmp.Multiply(x, zInv).IsNegative()
	y.Select(tmp.Negate(y), y, isNegative)

	//nolint:gocritic // it is not commented code
	// s = CT_ABS(den_inv * (z - y))
	s := tmp.Subtract(z, y).Multiply(tmp, denInv).Absolute(tmp)

	// Return the canonical little-endian encoding of s.
	copy(b, s.Bytes())

	return b
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element) Decode(data []byte) error {
	_, err := e.SetCanonicalBytes(data)
	return err
}

// SetCanonicalBytes sets e to the decoded value of in. If in is not a canonical
// encoding of s, SetCanonicalBytes returns nil and an error and the receiver is
// unchanged.
func (e *Element) SetCanonicalBytes(in []byte) (*Element, error) {
	if len(in) != conanicalSize {
		return nil, ErrInvalidEncoding
	}

	// First, interpret the string as an integer s in little-endian representation.
	s := &field.Element{}
	if _, err := s.SetBytes(in); err != nil {
		return nil, err
	}

	// If the resulting value is >= p, decoding fails.
	if !bytes.Equal(s.Bytes(), in) {
		return nil, ErrInvalidEncoding
	}

	// If IS_NEGATIVE(s) returns TRUE, decoding fails.
	if s.IsNegative() == 1 {
		return nil, ErrInvalidEncoding
	}

	// ss = s^2
	sSqr := &field.Element{}
	sSqr.Square(s)

	// u1 = 1 - ss
	u1 := &field.Element{}
	u1.Subtract(one, sSqr)

	// u2 = 1 + ss
	u2 := &field.Element{}
	u2.Add(one, sSqr)

	// u2_sqr = u2^2
	u2Sqr := &field.Element{}
	u2Sqr.Square(u2)

	//nolint:gocritic // it is not commented code
	// v = -(D * u1^2) - u2_sqr
	v := &field.Element{}
	v.Square(u1).Multiply(v, d).Negate(v).Subtract(v, u2Sqr)

	// (was_square, invsqrt) = SQRT_RATIO_M1(1, v * u2_sqr)
	invSqrt, tmp := &field.Element{}, &field.Element{}
	_, wasSquare := invSqrt.SqrtRatio(one, tmp.Multiply(v, u2Sqr))

	//nolint:gocritic // it is not commented code
	// den_x = invsqrt * u2
	// den_y = invsqrt * den_x * v
	denX, denY := &field.Element{}, &field.Element{}
	denX.Multiply(invSqrt, u2)
	denY.Multiply(invSqrt, denX).Multiply(denY, v)

	//nolint:gocritic // it is not commented code
	// x = CT_ABS(2 * s * den_x)
	// y = u1 * den_y
	// t = x * y
	var X, Y, Z, T field.Element

	X.Multiply(two, s).Multiply(&X, denX).Absolute(&X)
	Y.Multiply(u1, denY)
	Z.One()
	T.Multiply(&X, &Y)

	// If was_square is FALSE, or IS_NEGATIVE(t) returns TRUE, or y = 0, decoding fails.
	if wasSquare == 0 || T.IsNegative() == 1 || Y.Equal(zero) == 1 {
		return nil, ErrInvalidEncoding
	}

	// Otherwise, return the internal representation in extended coordinates (x, y, 1, t).
	if _, err := e.e.SetExtendedCoordinates(&X, &Y, &Z, &T); err != nil {
		panic("ristretto255: internal error: DECODE generated invalid coordinates")
	}

	return e, nil
}

// SetUniformBytes deterministically sets e to an uniformly distributed value
// given 64 uniformly distributed random bytes.
//
// This can be used for hash-to-group operations or to obtain a random element.
func (e *Element) SetUniformBytes(b []byte) (internal.Element, error) {
	if len(b) != uniformSize {
		return nil, errors.New("r255: SetUniformBytes input is not 64 bytes long")
	}

	f := &field.Element{}

	if _, err := f.SetBytes(b[:32]); err != nil {
		return nil, err
	}

	point1 := &Element{e: edwards25519.NewIdentityPoint()}
	mapToPoint(point1.e, f)

	if _, err := f.SetBytes(b[32:]); err != nil {
		return nil, err
	}

	point2 := &Element{e: edwards25519.NewIdentityPoint()}
	mapToPoint(point2.e, f)

	e.Set(point1)
	e.Add(point2)

	return e, nil
}

// mapToPoint implements MAP from Section 3.2.4 of draft-hdevalence-cfrg-ristretto-00.
func mapToPoint(out *edwards25519.Point, t *field.Element) {
	//nolint:gocritic // it is not commented code
	// r = SQRT_M1 * t^2
	r := &field.Element{}
	r.Multiply(sqrtM1, r.Square(t))

	//nolint:gocritic // it is not commented code
	// u = (r + 1) * ONE_MINUS_D_SQ
	u := &field.Element{}
	u.Multiply(u.Add(r, one), oneMinusDSQ)

	// c = -1
	c := &field.Element{}
	c.Set(minusOne)

	//nolint:gocritic // it is not commented code
	// v = (c - r*D) * (r + D)
	rPlusD := &field.Element{}
	rPlusD.Add(r, d)

	v := &field.Element{}
	v.Multiply(v.Subtract(c, v.Multiply(r, d)), rPlusD)

	// (was_square, s) = SQRT_RATIO_M1(u, v)
	s := &field.Element{}
	_, wasSquare := s.SqrtRatio(u, v)

	//nolint:gocritic // it is not commented code
	// s_prime = -CT_ABS(s*t)
	sPrime := &field.Element{}
	sPrime.Negate(sPrime.Absolute(sPrime.Multiply(s, t)))

	// s = CT_SELECT(s IF was_square ELSE s_prime)
	s.Select(s, sPrime, wasSquare)
	// c = CT_SELECT(c IF was_square ELSE r)
	c.Select(c, r, wasSquare)

	//nolint:gocritic // it is not commented code
	// N = c * (r - 1) * D_MINUS_ONE_SQ - v
	N := &field.Element{}
	N.Multiply(c, N.Subtract(r, one))
	N.Subtract(N.Multiply(N, dMinusOneSQ), v)

	s2 := &field.Element{}
	s2.Square(s)

	//nolint:gocritic // it is not commented code
	// w0 = 2 * s * v
	w0 := &field.Element{}
	w0.Add(w0, w0.Multiply(s, v))

	//nolint:gocritic // it is not commented code
	// w1 = N * SQRT_AD_MINUS_ONE
	w1 := &field.Element{}
	w1.Multiply(N, sqrtADMinusOne)
	// w2 = 1 - s^2
	w2 := &field.Element{}
	w2.Subtract(one, s2)
	// w3 = 1 + s^2
	w3 := &field.Element{}
	w3.Add(one, s2)

	// return (w0*w3, w2*w1, w1*w3, w0*w2)
	var X, Y, Z, T field.Element

	X.Multiply(w0, w3)
	Y.Multiply(w2, w1)
	Z.Multiply(w1, w3)
	T.Multiply(w0, w2)

	if _, err := out.SetExtendedCoordinates(&X, &Y, &Z, &T); err != nil {
		panic("ristretto255: internal error: MAP generated invalid coordinates")
	}
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (e *Element) MarshalBinary() ([]byte, error) {
	return e.Encode(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (e *Element) UnmarshalBinary(data []byte) error {
	return e.Decode(data)
}

// MarshalText implements the encoding.TextMarshaler interface.
func (e *Element) MarshalText() (text []byte, err error) {
	b := e.Encode()
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (e *Element) UnmarshalText(text []byte) error {
	sb, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("r255: %w", err)
	}

	return e.Decode(sb)
}
