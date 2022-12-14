// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"bytes"
	"testing"

	"github.com/cymony/cryptomony/internal/test"
)

func TestCleartextCredsEncodeDecode(t *testing.T) {
	priv, err := Ristretto255Suite.New().GenerateKeyPair()
	test.CheckNoErr(t, err, "key generate err")

	pub := priv.Public()

	encodedPub, err := pub.MarshalBinary()
	test.CheckNoErr(t, err, "pub marshal err")

	tstCred := &CleartextCredentials{
		ServerPublicKey: encodedPub,
		ServerIdentity:  []byte("this is server identity"),
		ClientIdentity:  []byte("this is client identity"),
	}

	encoded, err := tstCred.Encode()
	test.CheckNoErr(t, err, "encode err")

	newCred := &CleartextCredentials{}
	err = newCred.Decode(Ristretto255Suite.New(), encoded)
	test.CheckNoErr(t, err, "decode err")

	if !bytes.Equal(tstCred.ServerPublicKey, newCred.ServerPublicKey) ||
		!bytes.Equal(tstCred.ServerIdentity, newCred.ServerIdentity) ||
		!bytes.Equal(tstCred.ClientIdentity, newCred.ClientIdentity) {
		test.Report(t, newCred, tstCred)
	}
}
