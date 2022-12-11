// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

import (
	"math/big"

	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/utils"
)

// PrivateKey identify the private key according to group
type PrivateKey struct {
	s   Suite
	k   *eccgroup.Scalar
	pub *PublicKey
}

// MarshalBinary marshals the private key to bytes
func (priv *PrivateKey) MarshalBinary() ([]byte, error) {
	return priv.k.MarshalBinary()
}

// MarshalText marshals the private key to base64 encoded bytes
func (priv *PrivateKey) MarshalText() ([]byte, error) {
	return priv.k.MarshalText()
}

// UnmarshalBinary unmarshals given data to PrivateKey struct according to given suite
func (priv *PrivateKey) UnmarshalBinary(s Suite, data []byte) error {
	if !isSuiteAvailable(s) {
		return ErrInvalidSuite
	}

	priv.s = s
	priv.k = s.Group().NewScalar()

	return priv.k.UnmarshalBinary(data)
}

// UnmarshalText unmarshals given data to PrivateKey struct according to given suite
func (priv *PrivateKey) UnmarshalText(s Suite, text []byte) error {
	if !isSuiteAvailable(s) {
		return ErrInvalidSuite
	}

	priv.s = s
	priv.k = s.Group().NewScalar()

	return priv.k.UnmarshalText(text)
}

// Public returns corresponding public key
func (priv *PrivateKey) Public() *PublicKey {
	if priv.pub == nil {
		priv.pub = &PublicKey{priv.s, priv.s.Group().NewElement().Base().Multiply(priv.k)}
	}

	return priv.pub
}

// PublicKey identify the public key according to group
type PublicKey struct {
	s Suite
	e *eccgroup.Element
}

// MarshalBinary marshals the public key to bytes
func (pub *PublicKey) MarshalBinary() ([]byte, error) {
	return pub.e.MarshalBinary()
}

// MarshalText marshals the public key to base64 encoded bytes
func (pub *PublicKey) MarshalText() ([]byte, error) {
	return pub.e.MarshalText()
}

// UnmarshalBinary unmarshals given data to PublicKey struct according to given suite
func (pub *PublicKey) UnmarshalBinary(s Suite, data []byte) error {
	if !isSuiteAvailable(s) {
		return ErrInvalidSuite
	}

	pub.s = s
	pub.e = s.Group().NewElement()

	return pub.e.UnmarshalBinary(data)
}

// UnmarshalText unmarshals given data to PublicKey struct according to given suite
func (pub *PublicKey) UnmarshalText(s Suite, text []byte) error {
	if !isSuiteAvailable(s) {
		return ErrInvalidSuite
	}

	pub.s = s
	pub.e = s.Group().NewElement()

	return pub.e.UnmarshalText(text)
}

// GenerateKey generates a private key compatible with the suite.
func GenerateKey(s Suite) (*PrivateKey, error) {
	if !isSuiteAvailable(s) {
		return nil, ErrInvalidSuite
	}

	privKey := s.Group().RandomScalar()

	return &PrivateKey{s, privKey, nil}, nil
}

// DeriveKey generates a private key from a given seed and optional info string.
func DeriveKey(s Suite, mode ModeType, seed, info []byte) (*PrivateKey, error) {
	if !isSuiteAvailable(s) {
		return nil, ErrInvalidSuite
	}

	if !isModeAvailable(mode) {
		return nil, ErrInvalidMode
	}

	//nolint:gocritic // it is not commented code
	// deriveInput = seed || I2OSP(len(info), 2) || info
	i2ospLenInfo2, err := utils.I2osp(big.NewInt(int64(len(info))), 2)

	if err != nil {
		return nil, err
	}

	deriveInput := utils.Concat(seed, i2ospLenInfo2, info)

	//nolint:gocritic // it is not commented code
	// DST = "DeriveKeyPair" || contextString
	dst := createDeriveKeyDST(mode, s)

	// skS = 0
	skS := s.Group().NewScalar().Zero()
	// while skS == 0:
	for counter := 0; skS.IsZero(); counter++ {
		// if counter > 255: raise DeriveKeyPairError
		if counter > 255 {
			return nil, ErrDeriveKeyError
		}

		counterI2osp1, err := utils.I2osp(big.NewInt(int64(counter)), 1)
		if err != nil {
			return nil, err
		}
		// skS = G.HashToScalar(deriveInput || I2OSP(counter, 1), DST = "DeriveKeyPair" || contextString)
		input := utils.Concat(deriveInput, counterI2osp1)
		skS = s.Group().HashToScalar(input, dst)
	}

	return &PrivateKey{s, skS, nil}, nil
}
