// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import "github.com/cymony/cryptomony/eccgroup"

func getScalarFromPrivKey(group eccgroup.Group, privKey *PrivateKey) (*eccgroup.Scalar, error) {
	serialized, err := privKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	sc := group.NewScalar()
	if err := sc.UnmarshalBinary(serialized); err != nil {
		return nil, err
	}

	return sc, nil
}

func getElementFromPublicKey(group eccgroup.Group, publicKey *PublicKey) (*eccgroup.Element, error) {
	serialized, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	el := group.NewElement()
	if err := el.UnmarshalBinary(serialized); err != nil {
		return nil, err
	}

	return el, nil
}

func xor(a, b []byte) []byte {
	dst := make([]byte, len(a))
	for i, r := range a {
		dst[i] = r ^ b[i]
	}

	return dst
}
