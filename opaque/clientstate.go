// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/opaque/internal/common"
	"github.com/cymony/cryptomony/utils"
)

// ClientRegistrationState represents the client's registration state
// to give FinalizeRegistrationRequest function as parameter.
// This library does not manage the state internally.
type ClientRegistrationState struct {
	Blind    *eccgroup.Scalar
	Password []byte
}

// Serialize serializes the ClientRegistrationState to bytes
func (crs *ClientRegistrationState) Serialize() ([]byte, error) {
	if crs.Blind == nil || len(crs.Password) == 0 {
		return nil, ErrSerializationFailed
	}

	return utils.Concat(crs.Blind.Encode(), crs.Password), nil
}

// Deserialize deserializes bytes into the ClientRegistrationState struct
func (crs *ClientRegistrationState) Deserialize(suite Suite, data []byte) error {
	if len(data) <= int(suite.Group().ScalarLength()) {
		return ErrDeserializationFailed
	}

	crs.Blind = suite.Group().NewScalar()
	if err := crs.Blind.Decode(data[:suite.Group().ScalarLength()]); err != nil {
		return err
	}

	crs.Password = data[suite.Group().ScalarLength():]

	return nil
}

// Encode serializes the ClientRegistrationState into bytes but with 2 byte length descriptors.
func (crs *ClientRegistrationState) Encode() ([]byte, error) {
	if crs.Blind == nil || len(crs.Password) == 0 {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, crs.Blind.Encode(), crs.Password)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the ClientRegistrationState struct.
func (crs *ClientRegistrationState) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 2, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return crs.Deserialize(suite, utils.Concat(decoded...))
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

// Serialize serializes the ClientLoginState to bytes
func (cls *ClientLoginState) Serialize() ([]byte, error) {
	if cls.Blind == nil || cls.ClientSecret == nil || cls.KE1 == nil || len(cls.Password) == 0 {
		return nil, ErrSerializationFailed
	}

	encodedClientSecret, err := cls.ClientSecret.MarshalBinary()
	if err != nil {
		return nil, ErrSerializationFailed
	}

	serializedKE1, err := cls.KE1.Serialize()
	if err != nil {
		return nil, err
	}

	return utils.Concat(cls.Blind.Encode(), encodedClientSecret, serializedKE1, cls.Password), nil
}

// Deserialize deserializes bytes into the ClientLoginState struct
func (cls *ClientLoginState) Deserialize(suite Suite, data []byte) error {
	ke1Len := suite.Noe() + suite.Nn() + suite.Npk()
	blindLen := int(suite.Group().ScalarLength())

	if len(data) <= blindLen+suite.Nsk()+ke1Len {
		return ErrDeserializationFailed
	}

	cls.Blind = suite.Group().NewScalar()
	if err := cls.Blind.Decode(data[:blindLen]); err != nil {
		return ErrDeserializationFailed
	}

	cls.ClientSecret = &PrivateKey{}
	if err := cls.ClientSecret.UnmarshalBinary(suite, data[blindLen:blindLen+suite.Nsk()]); err != nil {
		return ErrDeserializationFailed
	}

	cls.KE1 = &KE1{}
	if err := cls.KE1.Deserialize(suite, data[blindLen+suite.Nsk():blindLen+suite.Nsk()+ke1Len]); err != nil {
		return err
	}

	cls.Password = data[blindLen+suite.Nsk()+ke1Len:]

	return nil
}

// Encode serializes the ClientLoginState into bytes but with 2 byte length descriptors.
func (cls *ClientLoginState) Encode() ([]byte, error) {
	if cls.Blind == nil || cls.ClientSecret == nil || cls.KE1 == nil || len(cls.Password) == 0 {
		return nil, ErrEncodingFailed
	}

	serializedClientSecret, err := cls.ClientSecret.MarshalBinary()
	if err != nil {
		return nil, ErrEncodingFailed
	}

	serializedKE1, err := cls.KE1.Serialize()
	if err != nil {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, cls.Blind.Encode(), serializedClientSecret, serializedKE1, cls.Password)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the ClientLoginState struct.
func (cls *ClientLoginState) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 4, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return cls.Deserialize(suite, utils.Concat(decoded...))
}
