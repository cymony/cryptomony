// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package r255

import (
	"encoding/base64"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/cymony/cryptomony/eccgroup/internal"
	"github.com/cymony/cryptomony/utils"
)

// Scalar represents the Ristretto255 curve Scalar point
type Scalar struct {
	s *edwards25519.Scalar
}

func cvtScalar(s internal.Scalar) *Scalar {
	sc, ok := s.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	return sc
}

func newScalar() internal.Scalar {
	return &Scalar{s: edwards25519.NewScalar()}
}

// Zero sets the scalar to 0, and returns it.
func (s *Scalar) Zero() internal.Scalar {
	s.s = &edwards25519.Scalar{}
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	// 32-byte little endian value of "1"
	scOne := make([]byte, conanicalSize)
	scOne[0] = 0x01

	if _, err := s.s.SetCanonicalBytes(scOne); err != nil {
		panic(err)
	}

	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	for {
		random := utils.RandomBytes(uniformSize)

		if _, err := s.s.SetUniformBytes(random); err != nil {
			panic(err.Error())
		}

		if !s.IsZero() {
			return s
		}
	}
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (s *Scalar) Add(ss internal.Scalar) internal.Scalar {
	if ss == nil {
		return s
	}

	sc := cvtScalar(ss)
	s.s.Add(s.s, sc.s)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(ss internal.Scalar) internal.Scalar {
	if ss == nil {
		return s
	}

	sc := cvtScalar(ss)
	s.s.Subtract(s.s, sc.s)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
// If s parameter is nil, then the receiver is not modified
func (s *Scalar) Multiply(ss internal.Scalar) internal.Scalar {
	if ss == nil {
		s.Zero()
		return s
	}

	sc := cvtScalar(ss)
	s.s.Multiply(s.s, sc.s)

	return s
}

// Invert sets the receiver to the scalar's modular inverse ( 1 / scalar ), and returns it.
func (s *Scalar) Invert() internal.Scalar {
	s.s.Invert(s.s)
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(ss internal.Scalar) int {
	if ss == nil {
		return 0
	}

	sc := cvtScalar(ss)

	return s.s.Equal(sc.s)
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.s.Equal(edwards25519.NewScalar()) == 1
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(ss internal.Scalar) internal.Scalar {
	if ss == nil {
		s.Zero()
		return s
	}

	if err := s.Decode(ss.Encode()); err != nil {
		panic(err)
	}

	return s
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() internal.Scalar {
	return &Scalar{
		s: edwards25519.NewScalar().Set(s.s),
	}
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	return s.s.Bytes()
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(in []byte) error {
	_, err := s.SetCanonicalBytes(in)
	return err
}

// SetUniformBytes sets s to an uniformly distributed value given 64 uniformly
// distributed random bytes. If x is not of the right length, SetUniformBytes
// returns nil and an error, and the receiver is unchanged.
func (s *Scalar) SetUniformBytes(x []byte) (*Scalar, error) {
	if _, err := s.s.SetUniformBytes(x); err != nil {
		return nil, errors.New("r255: SetUniformBytes input is not 64 bytes long")
	}

	return s, nil
}

// SetCanonicalBytes sets s = x, where x is a 32 bytes little-endian encoding of
// s. If x is not a canonical encoding of s, SetCanonicalBytes returns nil and
// an error and the receiver is unchanged.
func (s *Scalar) SetCanonicalBytes(x []byte) (*Scalar, error) {
	if _, err := s.s.SetCanonicalBytes(x); err != nil {
		return nil, errors.New("r255: " + err.Error())
	}

	return s, nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Encode(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	return s.Decode(data)
}

// MarshalText implements the encoding.TextMarshaler interface.
func (s *Scalar) MarshalText() (text []byte, err error) {
	b := s.Encode()
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (s *Scalar) UnmarshalText(text []byte) error {
	sb, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("r255: %w", err)
	}

	return s.Decode(sb)
}
