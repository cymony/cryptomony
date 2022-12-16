// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package msgexpand

import (
	"errors"
	"fmt"
)

var (
	// ErrZeroLengthDST indicates that given dst has zero value
	ErrZeroLengthDST = errors.New("msgexpand: zero-length dst")
	// ErrRecommendedDSTLen indicates that given dst length shorter than recommended size
	ErrRecommendedDSTLen = fmt.Errorf("msgexpand: dst length shorter than recommended length (%d)", recommendedDSTLen)
	errLengthTooHigh     = errors.New("msgexpand: requested byte length is too high")
)
