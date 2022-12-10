// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package hash

import "errors"

var (
	ErrMismatchLengthWrite = errors.New("hash: mismatch requested data and written data lengths")
	ErrHmacKeySize         = errors.New("hash: hmac key length is larger than hash output size")
)
