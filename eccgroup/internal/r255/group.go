// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package r255

import (
	"github.com/cymony/cryptomony/eccgroup/internal"
	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/msgexpand"
)

// Group represents the Ristretto255 group. It exposes a prime-order group API with hash-to-curve operations.
type Group struct{}

// R255 returns a new instantiation of the Ristretto255 Group.
func R255() internal.Group {
	return &Group{}
}

// NewScalar returns a new, empty, scalar.
func (g *Group) NewScalar() internal.Scalar {
	return newScalar()
}

// NewElement returns the identity element (point at infinity).
func (g *Group) NewElement() internal.Element {
	return newElement()
}

// RandomScalar returns randomly generated scalar.
func (g *Group) RandomScalar() internal.Scalar {
	return g.NewScalar().Random()
}

// RandomElement returns randomly generated element.
func (g *Group) RandomElement() internal.Element {
	return g.NewElement().Base().Multiply(g.RandomScalar())
}

// Base returns the group's base point a.k.a. canonical generator.
func (g *Group) Base() internal.Element {
	return g.NewElement().Base()
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g *Group) HashToScalar(input, dst []byte) internal.Scalar {
	xmd := msgexpand.NewMessageExpandXMD(hash.SHA512)

	uniform, err := xmd.Expand(input, dst, uniformSize)
	if err != nil {
		panic(err)
	}

	sc, err := cvtScalar(newScalar()).SetUniformBytes(uniform)
	if err != nil {
		panic(err)
	}

	return sc
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g *Group) HashToGroup(input, dst []byte) internal.Element {
	xmd := msgexpand.NewMessageExpandXMD(hash.SHA512)

	uniform, err := xmd.Expand(input, dst, uniformSize)
	if err != nil {
		panic(err)
	}

	el, err := cvtEl(newElement()).SetUniformBytes(uniform)
	if err != nil {
		panic(err)
	}

	return el
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g *Group) EncodeToGroup(input, dst []byte) internal.Element {
	return g.HashToGroup(input, dst)
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func (g *Group) Ciphersuite() string {
	return H2C
}

// ScalarLength returns the byte size of an encoded scalar.
func (g *Group) ScalarLength() uint {
	return conanicalSize
}

// ElementLength returns the byte size of an encoded element.
func (g *Group) ElementLength() uint {
	return conanicalSize
}
