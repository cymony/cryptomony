// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ksf

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	argon2idStr = "Argon2id"

	defaultArgon2idTime    = 3
	defaultArgon2idMemory  = 64 * 1024
	defaultArgon2idThreads = 4
)

type argon2KSF struct {
	str                   string
	time, memory, threads int
}

func newArgon2id() KSF {
	return &argon2KSF{
		str:     argon2idStr,
		time:    defaultArgon2idTime,
		memory:  defaultArgon2idMemory,
		threads: defaultArgon2idThreads,
	}
}

func (a *argon2KSF) Harden(password, salt []byte, length int) ([]byte, error) {
	return argon2.IDKey(password, salt, uint32(a.time), uint32(a.memory), uint8(a.threads), uint32(length)), nil
}

func (a *argon2KSF) SetOptions(options ...Option) error {
	for _, option := range options {
		if err := option(a); err != nil {
			return err
		}
	}

	return nil
}

func (a *argon2KSF) String() string {
	return fmt.Sprintf("%s(%d,%d,%d)", a.str, a.time, a.memory, a.threads)
}
