// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package msgexpand

import (
	"errors"
	"fmt"
)

var (
	ErrLengthTooHigh     = errors.New("msgexpand: requested byte length is too high")
	ErrZeroLengthDST     = errors.New("msgexpand: zero-length dst")
	ErrRecommendedDSTLen = fmt.Errorf("msgexpand: dst length shorter than recommended length (%d)", recommendedDSTLen)
)
