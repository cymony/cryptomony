// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nist

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/cymony/cryptomony/eccgroup/internal"
)

var (
	errParamNegScalar    = errors.New("negative scalar")
	errParamScalarTooBig = errors.New("scalar too big")
)

// Scalar implements the Scalar interface for group scalars.
type Scalar struct {
	field *field
	s     big.Int
}

func newScalar(field *field) *Scalar {
	s := &Scalar{field: field}
	s.s.Set(zero)

	return s
}

func (s *Scalar) assert(scalar internal.Scalar) *Scalar {
	_sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	if !s.field.isEqualPrime(_sc.field) {
		panic(internal.ErrWrongField)
	}

	return _sc
}

// Zero sets the scalar to 0, and returns it.
func (s *Scalar) Zero() internal.Scalar {
	s.s.Set(zero)
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	s.s.Set(one)
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	for {
		s.field.random(&s.s)

		if !s.IsZero() {
			return s
		}
	}
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	s.field.add(&s.s, &s.s, &sc.s)

	return s
}

// Subtract returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	s.field.sub(&s.s, &s.s, &sc.s)

	return s
}

// Multiply returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := s.assert(scalar)
	s.field.mul(&s.s, &s.s, &sc.s)

	return s
}

// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
func (s *Scalar) Invert() internal.Scalar {
	s.field.inv(&s.s, &s.s)
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := s.assert(scalar)

	switch s.s.Cmp(&sc.s) {
	case 0:
		return 1
	default:
		return 0
	}
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.field.areEqual(&s.s, zero)
}

func (s *Scalar) set(scalar *Scalar) *Scalar {
	*s = *scalar
	return s
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.set(nil)
	}

	ec := s.assert(scalar)
	s.s.Set(&ec.s)

	return s
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() internal.Scalar {
	cpy := &Scalar{field: s.field}
	cpy.s.Set(&s.s)

	return cpy
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	byteLen := (s.field.bitLen() + 7) / 8
	scalar := make([]byte, byteLen)

	return s.s.FillBytes(scalar)
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(data []byte) error {
	if len(data) == 0 {
		return internal.ErrParamNilScalar
	}

	// warning - SetBytes interprets the input as a non-signed integer, so this will always be false
	tmp := new(big.Int).SetBytes(data)
	if tmp.Sign() < 0 {
		return errParamNegScalar
	}

	if s.field.order().Cmp(tmp) <= 0 {
		return errParamScalarTooBig
	}

	s.s.Set(tmp)

	return nil
}

// MarshalBinary returns the compressed byte encoding of the scalar.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded scalar.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	return s.Decode(data)
}

// MarshalText implements the encoding.MarshalText interface.
func (s *Scalar) MarshalText() (text []byte, err error) {
	b := s.Encode()
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements the encoding.UnmarshalText interface.
func (s *Scalar) UnmarshalText(text []byte) error {
	sb, err := base64.StdEncoding.DecodeString(string(text))
	if err == nil {
		return s.Decode(sb)
	}

	return fmt.Errorf("nist scalar UnmarshalText: %w", err)
}
