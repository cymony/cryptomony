// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/opaque/internal/common"
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
	return common.Encoder(2, cc.ServerPublicKey, cc.ServerIdentity, cc.ClientIdentity)
}

// Decode decodes given data into the struct.
// Given data must be output of Encode function
func (cc *CleartextCredentials) Decode(data []byte) error {
	decoded, err := common.Decoder(data, 3, 2)
	if err != nil {
		return err
	}

	for i, val := range decoded {
		switch i {
		case 0:
			cc.ServerPublicKey = val
		case 1:
			cc.ServerIdentity = val
		case 2:
			cc.ClientIdentity = val
		}
	}

	return nil
}
