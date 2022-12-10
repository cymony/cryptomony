// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package dleq

import "errors"

var (
	// ErrUnsupportedGroup raises when unsupported group passed to Configuration struct
	ErrUnsupportedGroup = errors.New("dleq: unsupported group")
)
