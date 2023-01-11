// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/opaque/internal/common"
	"github.com/cymony/cryptomony/utils"
)

// ServerLoginState represents the server's ake state
// to give ServerFinish function as parameter.
// This library does not manage the state internally.
type ServerLoginState struct {
	ExpectedClientMac []byte
	SessionKey        []byte
}

// Serialize serializes the ServerLoginState to bytes
func (sls *ServerLoginState) Serialize() ([]byte, error) {
	if len(sls.ExpectedClientMac) == 0 || len(sls.SessionKey) == 0 {
		return nil, ErrSerializationFailed
	}

	return utils.Concat(sls.ExpectedClientMac, sls.SessionKey), nil
}

// Deserialize deserializes bytes into the ServerLoginState struct
func (sls *ServerLoginState) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Nm()+suite.Nx() {
		return ErrDeserializationFailed
	}

	sls.ExpectedClientMac = data[:suite.Nm()]
	sls.SessionKey = data[suite.Nm():]

	return nil
}

// Encode serializes the ServerLoginState into bytes but with 2 byte length descriptors.
func (sls *ServerLoginState) Encode() ([]byte, error) {
	if len(sls.ExpectedClientMac) == 0 || len(sls.SessionKey) == 0 {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, sls.ExpectedClientMac, sls.SessionKey)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the ServerLoginState struct.
func (sls *ServerLoginState) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 2, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return sls.Deserialize(suite, utils.Concat(decoded...))
}
