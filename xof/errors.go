// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package xof

import "errors"

var (
	ErrMismatchLengthWrite = errors.New("hash: mismatch requested data and written data lengths")
	ErrMismatchLengthRead  = errors.New("hash: mismatch requested data and read data lengths")
)
