// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package utils

import (
	"math/big"
)

// I2osp converts a nonnegative integer to an octet string of a specified length.
//
// Reference: (https://datatracker.ietf.org/doc/html/rfc8017#section-4.1)
func I2osp(x *big.Int, xLen int) ([]byte, error) {
	if x.Sign() < 0 {
		return nil, ErrI2OSPIntegerNegative
	}

	if x.BitLen() > xLen*8 {
		return nil, ErrI2OSPIntegerTooLarge
	}

	ret := make([]byte, xLen)
	x.FillBytes(ret)

	return ret, nil
}

// Os2ip converts an octet string to a nonnegative integer.
//
// Reference: (https://datatracker.ietf.org/doc/html/rfc8017#section-4.2)
func Os2ip(x []byte) int {
	return int(new(big.Int).SetBytes(x).Int64())
}
