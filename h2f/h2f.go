// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package h2f implements https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-hash_to_field-implementatio
package h2f

import (
	"math/big"

	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/msgexpand"
	"github.com/cymony/cryptomony/xof"
)

// Hash2Field hashes the input with the domain separation tag (dst) to an integer under modulo, using an
// merkle-damgard based expander (e.g. SHA256).
// See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-hash_to_field-implementatio
func hash2Field(uniform []byte, count, securityLength int, modulo *big.Int) []*big.Int {
	res := make([]*big.Int, count)

	for i := 0; i < count; i++ {
		offset := i * securityLength
		ii := new(big.Int).SetBytes(uniform[offset : offset+securityLength])
		ii.Mod(ii, modulo)
		res[i] = ii
	}

	return res
}

// Hash2FieldXMD hashes the input with the domain separation tag (dst) to an integer under modulo, using an
// merkle-damgard based expander (e.g. SHA256).
func Hash2FieldXMD(h hash.Hashing, in, dst []byte, count, ext, securityLength int, modulo *big.Int) ([]*big.Int, error) {
	lenInBytes := count * ext * securityLength

	xmd := msgexpand.NewMessageExpandXMD(h)

	uniform, err := xmd.Expand(in, dst, lenInBytes)
	if err != nil {
		return nil, err
	}

	u := hash2Field(uniform, count, securityLength, modulo)

	return u, nil
}

// Hash2FieldXOF hashes the input with the domain separation tag (dst) to an integer under modulo, using an
// extensible output function (e.g. SHAKE).
func Hash2FieldXOF(h xof.Extendable, in, dst []byte, count, ext, securityLength int, modulo *big.Int) ([]*big.Int, error) {
	lenInBytes := count * ext * securityLength

	xxof := msgexpand.NewMessageExpandXOF(h, securityLength)

	uniform, err := xxof.Expand(in, dst, lenInBytes)
	if err != nil {
		return nil, err
	}

	u := hash2Field(uniform, count, securityLength, modulo)

	return u, nil
}
