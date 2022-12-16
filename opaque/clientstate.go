// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

import "github.com/cymony/cryptomony/eccgroup"

// ClientRegistrationState represents the client's registration state
// to give FinalizeRegistrationRequest function as parameter.
// This library does not manage the state internally.
type ClientRegistrationState struct {
	Blind    *eccgroup.Scalar
	Password []byte
}

// ClientLoginState represents the client's ake state
// to give ClientFinish function as parameter.
// This library does not manage the state internally.
type ClientLoginState struct {
	Blind        *eccgroup.Scalar
	ClientSecret *PrivateKey
	KE1          *KE1
	Password     []byte
}
