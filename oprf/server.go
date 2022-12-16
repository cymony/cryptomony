// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oprf

type server struct {
	privKey *PrivateKey
	s       Suite
	mode    ModeType
}

func (s server) PublicKey() *PublicKey { return s.privKey.Public() }
