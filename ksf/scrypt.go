// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ksf

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptStr      = "Scrypt"
	defaultScryptn = 32768
	defaultScryptr = 8
	defaultScryptp = 1
)

type scryptKSF struct {
	str     string
	n, r, p int
}

func newScryptKSF() KSF {
	return &scryptKSF{
		str: scryptStr,
		n:   defaultScryptn,
		r:   defaultScryptr,
		p:   defaultScryptp,
	}
}

func (s *scryptKSF) Harden(password, salt []byte, length int) ([]byte, error) {
	return scrypt.Key(password, salt, s.n, s.r, s.p, length)
}

func (s *scryptKSF) SetOptions(options ...Option) error {
	for _, option := range options {
		if err := option(s); err != nil {
			return err
		}
	}

	return nil
}

func (s *scryptKSF) String() string {
	return fmt.Sprintf("%s(%d,%d,%d)", scryptStr, s.n, s.r, s.p)
}
