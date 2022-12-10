// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package hash

import "errors"

var (
	// ErrMismatchLengthWrite returns when hash's write operation writes wrong length of data
	ErrMismatchLengthWrite = errors.New("hash: mismatch requested data and written data lengths")
)
