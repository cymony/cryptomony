// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/opaque/internal/common"
	"github.com/cymony/cryptomony/utils"
)

type CleartextCredentials struct {
	ServerPublicKey []byte
	ServerIdentity  []byte
	ClientIdentity  []byte
}

func CreateCleartextCredentials(sPubKey, cPubKey, serverIdentity, clientIdentity []byte) *CleartextCredentials {
	if len(serverIdentity) == 0 {
		serverIdentity = sPubKey
	}

	if len(clientIdentity) == 0 {
		clientIdentity = cPubKey
	}

	return &CleartextCredentials{
		ServerPublicKey: sPubKey,
		ServerIdentity:  serverIdentity,
		ClientIdentity:  clientIdentity,
	}
}

// Encode encodes server public key, server identity and client identity to byte array.
// To Decode, use the Decode function only
func (cc *CleartextCredentials) Encode() ([]byte, error) {
	encoded, err := common.Encoder(2, cc.ServerIdentity, cc.ClientIdentity)
	if err != nil {
		return nil, err
	}

	return utils.Concat(cc.ServerPublicKey, encoded), nil
}

// Decode decodes given data into the struct.
// Given data must be output of Encode function
func (cc *CleartextCredentials) Decode(suite Suite, data []byte) error {
	serverPubKey := data[:suite.OPRF().Group().ScalarLength()]
	cc.ServerPublicKey = serverPubKey

	decoded, err := common.Decoder(data[suite.OPRF().Group().ScalarLength():], 2, 2)
	if err != nil {
		return err
	}

	for i, val := range decoded {
		switch i {
		case 0:
			cc.ServerIdentity = val
		case 1:
			cc.ClientIdentity = val
		}
	}

	return nil
}
