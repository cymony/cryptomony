// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package ksf

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptStr = "Bcrypt"

	defaultBcryptCost = 10
)

type bcryptKSF struct {
	str  string
	cost int
}

func newBcrypt() KSF {
	return &bcryptKSF{
		str:  bcryptStr,
		cost: defaultBcryptCost,
	}
}

func (b *bcryptKSF) Harden(password, _ []byte, _ int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, b.cost)
}

func (b *bcryptKSF) SetOptions(options ...Option) error {
	for _, option := range options {
		if err := option(b); err != nil {
			return err
		}
	}

	return nil
}

func (b *bcryptKSF) String() string {
	return fmt.Sprintf("%s(%d)", b.str, b.cost)
}
