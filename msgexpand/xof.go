// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package msgexpand

import (
	"math"
	"math/big"

	"github.com/cymony/cryptomony/utils"
	"github.com/cymony/cryptomony/xof"
)

type messageExpandXOF struct {
	id xof.Extendable
	k  int
}

// NewExpanderXOF returns an expander based on an extendable output functions.
// The kSecLevel parameter is the target security level in bits.
func NewMessageExpandXOF(id xof.Extendable, secLevel int) MessageExpand {
	return &messageExpandXOF{id: id, k: secLevel}
}

func (me *messageExpandXOF) Expand(msg, dst []byte, lenInBytes int) ([]byte, error) {
	if err := checkDST(dst); err != nil {
		return nil, err
	}

	return me.expandXOF(msg, dst, lenInBytes, me.k)
}

// See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-expand_message_xof
func (me *messageExpandXOF) expandXOF(msg, dst []byte, lenInBytes, k int) ([]byte, error) {
	// process DST > 255 case
	newDST, err := processDSTXOF(me.id, k, dst)
	if err != nil {
		return nil, err
	}

	dst = newDST

	// ABORT if len_in_bytes > 65535 or len(DST) > 255
	if lenInBytes > math.MaxUint16 || len(dst) > 255 {
		return nil, ErrLengthTooHigh
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(DST), 1)
	lenDST1i2osp, err := utils.I2osp(big.NewInt(int64(len(dst))), 1)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len_in_bytes, 2)
	lenLenInBytes2i2osp, err := utils.I2osp(big.NewInt(int64(lenInBytes)), 2)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// DST_prime = DST || I2OSP(len(DST), 1)
	// msg_prime = msg || I2OSP(len_in_bytes, 2) || DST_prime
	h := me.id.New()
	if err := h.MustWriteAll(msg, lenLenInBytes2i2osp, dst, lenDST1i2osp); err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// uniform_bytes = H(msg_prime, len_in_bytes)
	uniformBytes := make([]byte, lenInBytes)
	if err := h.MustReadFull(uniformBytes); err != nil {
		return nil, err
	}

	return uniformBytes, nil
}

// Prepend H2C-OVERSIZE-DST- to dst if longer than 255.
// See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-using-dsts-longer-than-255-
func processDSTXOF(h xof.Extendable, k int, dst []byte) ([]byte, error) {
	if len(dst) <= maxDstLen {
		return dst, nil
	}

	hsh := h.New()
	if err := hsh.MustWriteAll(longDSTPrefixXMD[:], dst); err != nil {
		return nil, err
	}

	// Calculate hash out size
	x2k := 2 * k
	max := math.Ceil(float64(x2k) / 8)

	newDST := make([]byte, int(max))
	if err := hsh.MustReadFull(newDST); err != nil {
		return nil, err
	}

	return newDST, nil
}
