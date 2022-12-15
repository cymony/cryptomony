// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal

import "errors"

var (
	// ErrParamNilPoint indicated a forbidden nil or empty point.
	ErrParamNilPoint = errors.New("nil or empty point")

	// ErrParamNilScalar indicates a forbidden nil or empty scalar.
	ErrParamNilScalar = errors.New("nil or empty scalar")

	// ErrCastElement indicates a failed attempt to cast to a point.
	ErrCastElement = errors.New("could not cast to same group element (you should not use different group e.g. P224 and P256)")

	// ErrCastScalar indicates a failed attempt to cast to a scalar.
	ErrCastScalar = errors.New("could not cast to same group scalar (you should not use different group e.g. P224 and P256)")

	// ErrWrongField indicates an incompatible field has been encountered.
	ErrWrongField = errors.New("incompatible field (different prime)")
)
