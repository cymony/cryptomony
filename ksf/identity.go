// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ksf

import (
	"fmt"
)

const (
	identityStr = "Identity"
)

type identity struct {
	str string
}

func newIdentity() KSF {
	return &identity{
		str: identityStr,
	}
}

func (i *identity) Harden(password, salt []byte, length int) ([]byte, error) {
	return password, nil
}

func (i *identity) SetOptions(options ...Option) error {
	return nil
}

func (i *identity) String() string {
	return fmt.Sprintf("%s()", i.str)
}
