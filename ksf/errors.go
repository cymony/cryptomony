// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package ksf

import "errors"

var (
	// ErrNotArgon2 returns when non argon2 option passed to SetOptions function.
	ErrNotArgon2 = errors.New("ksf: instance is not argon2")
	// ErrNotBcrypt returns when non bcrypt option passed to SetOptions function.
	ErrNotBcrypt = errors.New("ksf: instance is not bcrypt")
	// ErrNotScrypt returns when non scrypt option passed to SetOptions function.
	ErrNotScrypt = errors.New("ksf: instance is not scrypt")
	// ErrNotSupportedAlgorithm returns non supported ksf algorithm selected.
	ErrNotSupportedAlgorithm = errors.New("ksf: algorithm not supported")
)
