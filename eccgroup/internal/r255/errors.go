// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package r255

import "errors"

var (
	// ErrInvalidEncoding returns when passed unsuitable data for unmarshaling
	ErrInvalidEncoding = errors.New("r255: invalid element encoding")
)
