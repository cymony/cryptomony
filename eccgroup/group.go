// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package eccgroup implements prime-order group supported elliptic curves with hash-to-curve operations.

Supported Curves;
  - Ristretto255
  - P256
  - P384
  - P521
*/
package eccgroup

import (
	"errors"
	"sync"

	"github.com/cymony/cryptomony/eccgroup/internal"
	"github.com/cymony/cryptomony/eccgroup/internal/nist"
	"github.com/cymony/cryptomony/eccgroup/internal/r255"
)

// Group identifies prime-order groups over elliptic curves with hash-to-curve operations
type Group byte

const (
	// Ristretto255Sha512 identifies the Ristretto255 group with SHA2-512 hash-to-group hashing
	Ristretto255Sha512 Group = 1 + iota

	// P256Sha256 identifies a group over P256 with SHA2-512 hash-to-group hashing
	P256Sha256

	// P384Sha384 identifies a group over P384 with SHA2-384 hash-to-group hashing
	P384Sha384

	// P521Sha512 identifies a group over P521 with SHA2-512 hash-to-group hashing
	P521Sha512

	maxID

	dstfmt               = "%s-V%02d-CS%02d-%s"
	minLength            = 0
	recommendedMinLength = 16
)

var (
	once          [maxID - 1]sync.Once
	groups        [maxID - 1]internal.Group
	errInvalidID  = errors.New("invalid group identifier")
	errZeroLenDST = errors.New("zero-length DST")
)

// Available reports whether the given Group is linked into the binary.
func (g Group) Available() bool {
	return 0 < g && g < maxID
}

func (g Group) get() internal.Group {
	if !g.Available() {
		panic(errInvalidID)
	}

	once[g-1].Do(g.init)

	return groups[g-1]
}

// String returns the hash-to-curve string identifier of the ciphersuite.
func (g Group) String() string {
	return g.get().Ciphersuite()
}

// NewScalar returns a new, empty, scalar.
func (g Group) NewScalar() *Scalar {
	return newScalar(g.get().NewScalar())
}

// NewElement returns the identity element (point at infinity).
func (g Group) NewElement() *Element {
	return newPoint(g.get().NewElement())
}

// RandomScalar returns randomly generated scalar.
func (g Group) RandomScalar() *Scalar {
	return newScalar(g.get().RandomScalar())
}

// RandomElement returns randomly generated element.
func (g Group) RandomElement() *Element {
	return newPoint(g.get().RandomElement())
}

// Base returns the group's base point a.k.a. canonical generator.
func (g Group) Base() *Element {
	return newPoint(g.get().Base())
}

func checkDST(dst []byte) {
	if len(dst) == minLength {
		panic(errZeroLenDST)
	}
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToScalar(input, dst []byte) *Scalar {
	checkDST(dst)
	return newScalar(g.get().HashToScalar(input, dst))
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToGroup(input, dst []byte) *Element {
	checkDST(dst)
	return newPoint(g.get().HashToGroup(input, dst))
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) EncodeToGroup(input, dst []byte) *Element {
	checkDST(dst)
	return newPoint(g.get().EncodeToGroup(input, dst))
}

// ScalarLength returns the byte size of an encoded scalar.
func (g Group) ScalarLength() uint {
	return g.get().ScalarLength()
}

// ElementLength returns the byte size of an encoded element.
func (g Group) ElementLength() uint {
	return g.get().ElementLength()
}

func (g Group) initGroup(get func() internal.Group) {
	groups[g-1] = get()
}

func (g Group) init() {
	switch g {
	case Ristretto255Sha512:
		g.initGroup(r255.R255)
	case P256Sha256:
		g.initGroup(nist.P256)
	case P384Sha384:
		g.initGroup(nist.P384)
	case P521Sha512:
		g.initGroup(nist.P521)
	case maxID:
		panic("group not recognized")
	default:
		panic("group not recognized")
	}
}
