// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package ksf

import "errors"

var (
	ErrNotArgon2             = errors.New("ksf: instance is not argon2")
	ErrNotBcrypt             = errors.New("ksf: instance is not bcrypt")
	ErrNotScrypt             = errors.New("ksf: instance is not scrypt")
	ErrNotSupportedAlgorithm = errors.New("ksf: algorithm not supported")
)
