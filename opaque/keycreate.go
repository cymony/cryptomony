// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/oprf"
	"github.com/cymony/cryptomony/utils"
)

type PrivateKey struct {
	privKey *oprf.PrivateKey
}

func (pk *PrivateKey) MarshalBinary() ([]byte, error) {
	if pk.privKey == nil {
		return nil, ErrPrivateKeyInitialization
	}

	return pk.privKey.MarshalBinary()
}

func (pk *PrivateKey) MarshalText() ([]byte, error) {
	if pk.privKey == nil {
		return nil, ErrPrivateKeyInitialization
	}

	return pk.privKey.MarshalText()
}

func (pk *PrivateKey) UnmarshalBinary(s Suite, data []byte) error {
	pk.privKey = &oprf.PrivateKey{}
	return pk.privKey.UnmarshalBinary(s.OPRF(), data)
}

func (pk *PrivateKey) UnmarshalText(s Suite, text []byte) error {
	pk.privKey = &oprf.PrivateKey{}
	return pk.privKey.UnmarshalText(s.OPRF(), text)
}

func (pk *PrivateKey) Public() *PublicKey {
	if pk.privKey == nil {
		panic(ErrPrivateKeyInitialization)
	}

	return &PublicKey{pubKey: pk.privKey.Public()}
}

type PublicKey struct {
	pubKey *oprf.PublicKey
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	if pk.pubKey == nil {
		return nil, ErrPublicKeyInitialization
	}

	return pk.pubKey.MarshalBinary()
}

func (pk *PublicKey) MarshalText() ([]byte, error) {
	if pk.pubKey == nil {
		return nil, ErrPublicKeyInitialization
	}

	return pk.pubKey.MarshalText()
}

func (pk *PublicKey) UnmarshalBinary(s Suite, data []byte) error {
	pk.pubKey = &oprf.PublicKey{}
	return pk.pubKey.UnmarshalBinary(s.OPRF(), data)
}

func (pk *PublicKey) UnmarshalText(s Suite, text []byte) error {
	pk.pubKey = &oprf.PublicKey{}
	return pk.pubKey.UnmarshalText(s.OPRF(), text)
}

func (os *opaqueSuite) DeriveKeyPair(seed []byte) (*PrivateKey, error) {
	if len(seed) != os.Nseed() {
		return nil, ErrSeedLength
	}

	orpfPriv, err := oprf.DeriveKey(os.OPRF(), oprf.ModeOPRF, seed, []byte(labelOPAQUEDeriveKeyPair))
	if err != nil {
		return nil, err
	}

	return &PrivateKey{privKey: orpfPriv}, nil
}

func (os *opaqueSuite) GenerateKeyPair() (*PrivateKey, error) {
	seed := utils.RandomBytes(os.Nseed())
	return os.DeriveKeyPair(seed)
}

func (os *opaqueSuite) DeriveAuthKeyPair(seed []byte) (*PrivateKey, error) {
	if len(seed) != os.Nseed() {
		return nil, ErrSeedLength
	}

	privKey, err := oprf.DeriveKey(os.OPRF(), oprf.ModeOPRF, seed, []byte(labelOPAQUEDeriveAuthKeyPair))
	if err != nil {
		return nil, err
	}

	return &PrivateKey{privKey: privKey}, nil
}

func (os *opaqueSuite) GenerateAuthKeyPair() (*PrivateKey, error) {
	rndSeed := utils.RandomBytes(os.Nseed())
	return os.DeriveAuthKeyPair(rndSeed)
}
