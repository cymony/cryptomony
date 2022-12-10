// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package r255

import "errors"

var (
	ErrNotValidDecimal = errors.New("r255: not a valid decimal")
	ErrInvalidEncoding = errors.New("r255: invalid element encoding")
)
