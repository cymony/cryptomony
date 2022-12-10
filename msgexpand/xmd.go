// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package msgexpand

import (
	"math"
	"math/big"

	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/utils"
)

type messageExpandXMD struct {
	h hash.Hashing
}

// NewMessageExpandXMD returns a expander interface based on a Merkle-Damgård hash functions.
func NewMessageExpandXMD(h hash.Hashing) MessageExpand {
	return &messageExpandXMD{h: h}
}

func (me *messageExpandXMD) Expand(msg, dst []byte, lenInBytes int) ([]byte, error) {
	if err := checkDST(dst); err != nil {
		return nil, err
	}

	return me.expandXMD(msg, dst, lenInBytes)
}

// See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-expand_message_xmd
func (me *messageExpandXMD) expandXMD(msg, dst []byte, lenInBytes int) ([]byte, error) { //nolint:gocyclo //complexity 18 acceptable
	// fix DST length. See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-using-dsts-longer-than-255-
	newDst, err := processDSTXMD(me.h, dst)
	if err != nil {
		return nil, err
	}

	dst = newDst

	// H, a hash function (see requirements above).
	h := me.h.New()

	// b_in_bytes, b / 8 for b the output size of H in bits.
	bInBytes := uint(h.OutputSize())
	// s_in_bytes, the input block size of H, measured in bytes
	sInBytes := uint(h.BlockSize())

	//nolint:gocritic //not a commented code
	// ell = ceil(len_in_bytes / b_in_bytes)
	ell := math.Ceil(float64(lenInBytes) / float64(bInBytes))

	// ABORT if ell > 255 or len_in_bytes > 65535 or len(DST) > 255
	if uint(ell) > 255 || lenInBytes > math.MaxUint16 || len(dst) > 255 {
		return nil, ErrLengthTooHigh
	}

	//nolint:gocritic //not a commented code
	// I2OSP(len(DST), 1)
	dstPrimeLenDstI2osp1, err := utils.I2osp(big.NewInt(int64(len(dst))), 1)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := append(dst, dstPrimeLenDstI2osp1...)

	//nolint:gocritic //not a commented code
	// Z_pad = I2OSP(0, s_in_bytes)
	zPad, err := utils.I2osp(big.NewInt(0), int(sInBytes))
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// l_i_b_str = I2OSP(len_in_bytes, 2)
	libStr, err := utils.I2osp(big.NewInt(int64(lenInBytes)), 2)
	if err != nil {
		return nil, err
	}

	// I2OSP(0, 1)
	i2osp01, err := utils.I2osp(big.NewInt(0), 1)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
	// b_0 = H(msg_prime)
	h.Reset()

	err = h.MustWriteAll(zPad, msg, libStr, i2osp01, dstPrime)
	if err != nil {
		return nil, err
	}

	b0 := make([]byte, h.OutputSize())

	err = h.MustReadFull(b0)
	if err != nil {
		return nil, err
	}

	// I2OSP(1, 1)
	i2osp11, err := utils.I2osp(big.NewInt(1), 1)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()

	err = h.MustWriteAll(b0, i2osp11, dstPrime)
	if err != nil {
		return nil, err
	}

	b1 := make([]byte, h.OutputSize())

	err = h.MustReadFull(b1)
	if err != nil {
		return nil, err
	}

	// for i in (2, ..., ell):
	// 	b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
	uniformBytes := make([]byte, 0, lenInBytes)
	uniformBytes = append(uniformBytes, b1...)
	bi := make([]byte, len(b1))
	copy(bi, b1)

	for i := uint(2); i <= uint(ell); i++ {
		for i := range b0 {
			bi[i] ^= b0[i]
		}

		i2ospi1, err := utils.I2osp(big.NewInt(int64(i)), 1)
		if err != nil {
			return nil, err
		}

		h.Reset()

		err = h.MustWriteAll(bi, i2ospi1, dstPrime)
		if err != nil {
			return nil, err
		}

		bi = h.Sum(nil)

		uniformBytes = append(uniformBytes, bi...)
	}

	return uniformBytes[0:lenInBytes], nil
}

// It implements https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html Section 5.3.3.
func processDSTXMD(h hash.Hashing, dst []byte) ([]byte, error) {
	if len(dst) <= maxDstLen {
		return dst, nil
	}

	hh := h.New()
	if err := hh.MustWriteAll(longDSTPrefixXMD[:], dst); err != nil {
		return nil, err
	}

	out := make([]byte, hh.OutputSize())
	if err := hh.MustReadFull(out); err != nil {
		return nil, err
	}

	return out, nil
}
