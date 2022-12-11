// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package utils

import "errors"

var (
	// ErrI2OSPIntegerTooLarge returns when integer's bit length larger than requested length
	ErrI2OSPIntegerTooLarge = errors.New("i2osp: integer too large")
	// ErrI2OSPIntegerNegative returns when given integer is negative
	ErrI2OSPIntegerNegative = errors.New("i2osp: negative integer")
)
