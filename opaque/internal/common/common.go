// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package common implements commonly used functions on the opaque package.
package common

import (
	"errors"
	"math/big"

	"github.com/cymony/cryptomony/utils"
)

// I2ospLenX returns concat(I2OSP(len(data), x), data)
func I2ospLenX(data []byte, x int) ([]byte, error) {
	i2ospLenXData, err := utils.I2osp(big.NewInt(int64(len(data))), x)
	if err != nil {
		return nil, err
	}

	return utils.Concat(i2ospLenXData, data), nil
}

// Encoder automatically encodes the data with x length descriptors
func Encoder(x int, inputs ...[]byte) ([]byte, error) {
	var out []byte

	for i := 0; i < len(inputs); i++ {
		leni2osp, err := I2ospLenX(inputs[i], x)
		if err != nil {
			return nil, err
		}

		out = utils.Concat(out, leni2osp)
	}

	return out, nil
}

// Decoder automatically decodes data by assuming,
// Each data has x length descriptors
// Also, data consists of dataLen separate data
func Decoder(data []byte, dataLen, x int) ([][]byte, error) {
	out := make([][]byte, dataLen)

	remainingSlice := data
	for i := 0; i < dataLen; i++ {
		if len(remainingSlice) < x {
			return nil, errors.New("decode error")
		}

		i2ospLen := remainingSlice[:x]
		lenInput := utils.Os2ip(i2ospLen)

		if len(remainingSlice) < x+lenInput {
			return nil, errors.New("decode error")
		}

		input := remainingSlice[x : x+lenInput]
		remainingSlice = remainingSlice[x+lenInput:]

		out[i] = input
	}

	return out, nil
}
