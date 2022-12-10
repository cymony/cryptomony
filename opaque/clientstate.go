// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import "github.com/cymony/cryptomony/eccgroup"

type ClientRegistrationState struct {
	Blind    *eccgroup.Scalar
	Password []byte
}

type ClientLoginState struct {
	Blind        *eccgroup.Scalar
	ClientSecret *PrivateKey
	KE1          *KE1
	Password     []byte
}
