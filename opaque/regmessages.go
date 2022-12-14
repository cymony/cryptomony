// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/opaque/internal/common"
	"github.com/cymony/cryptomony/utils"
)

// RegistrationRequest represents the first message sent from client to server on registration.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-registration-messages
type RegistrationRequest struct {
	BlindedMessage *eccgroup.Element // blinded_message[Noe]
}

// Serialize serializes the RegistrationRequest to bytes
func (rr *RegistrationRequest) Serialize() ([]byte, error) {
	return rr.BlindedMessage.MarshalBinary()
}

// Deserialize deserializes bytes into the RegistrationRequest struct
func (rr *RegistrationRequest) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Noe() {
		return ErrDeserializationFailed
	}

	rr.BlindedMessage = suite.OPRF().Group().NewElement()
	if err := rr.BlindedMessage.Decode(data); err != nil {
		return ErrDeserializationFailed
	}

	if rr.BlindedMessage.IsIdentity() {
		return ErrDeserializationFailed
	}

	return nil
}

// Encode serializes the RegistrationRequest into bytes but with 2 byte length descriptors.
func (rr *RegistrationRequest) Encode() ([]byte, error) {
	if rr.BlindedMessage == nil {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, rr.BlindedMessage.Encode())
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the RegistrationRequest struct.
func (rr *RegistrationRequest) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 1, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return rr.Deserialize(suite, utils.Concat(decoded...))
}

// RegistrationResponse represents the second message sent from server to client on registration.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-registration-messages
type RegistrationResponse struct {
	EvaluatedMessage *eccgroup.Element // evaluated_message[Noe]
	ServerPublicKey  *PublicKey        // server_public_key[Npk]
}

// Serialize serializes the RegistrationResponse to bytes
func (rr *RegistrationResponse) Serialize() ([]byte, error) {
	eEl, err := rr.EvaluatedMessage.MarshalBinary()
	if err != nil {
		return nil, err
	}

	sPub, err := rr.ServerPublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return utils.Concat(eEl, sPub), nil
}

// Deserialize deserializes bytes into the RegistrationResponse struct
func (rr *RegistrationResponse) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Noe()+suite.Npk() {
		return ErrDeserializationFailed
	}

	rr.EvaluatedMessage = suite.OPRF().Group().NewElement()
	rr.ServerPublicKey = &PublicKey{}

	if err := rr.EvaluatedMessage.Decode(data[:suite.Noe()]); err != nil {
		return ErrDeserializationFailed
	}

	if err := rr.ServerPublicKey.UnmarshalBinary(suite, data[suite.Noe():]); err != nil {
		return ErrDeserializationFailed
	}

	return nil
}

// Encode serializes the RegistrationResponse into bytes but with 2 byte length descriptors.
func (rr *RegistrationResponse) Encode() ([]byte, error) {
	if rr.EvaluatedMessage == nil || rr.ServerPublicKey == nil {
		return nil, ErrEncodingFailed
	}

	encodedSPubKey, err := rr.ServerPublicKey.MarshalBinary()
	if err != nil {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, rr.EvaluatedMessage.Encode(), encodedSPubKey)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the RegistrationResponse struct.
func (rr *RegistrationResponse) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 2, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return rr.Deserialize(suite, utils.Concat(decoded...))
}

// RegistrationRecord represents the third message sent from client to server on registration.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-registration-messages
type RegistrationRecord struct {
	Envelope     *Envelope  // envelope[Ne]
	ClientPubKey *PublicKey // client_public_key[Npk]
	MaskingKey   []byte     // masking_key[Nh]

}

// Serialize serializes the RegistrationRecord to bytes
func (rr *RegistrationRecord) Serialize() ([]byte, error) {
	serializedClientPubKey, err := rr.ClientPubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	serializedEnvelope, err := rr.Envelope.Serialize()
	if err != nil {
		return nil, err
	}

	return utils.Concat(serializedClientPubKey, rr.MaskingKey, serializedEnvelope), nil
}

// Deserialize deserializes bytes into the RegistrationRecord struct
func (rr *RegistrationRecord) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Npk()+suite.Nh()+suite.Ne() {
		return ErrDeserializationFailed
	}

	rr.Envelope = &Envelope{}
	rr.ClientPubKey = &PublicKey{}

	if err := rr.ClientPubKey.UnmarshalBinary(suite, data[:suite.Npk()]); err != nil {
		return ErrDeserializationFailed
	}

	rr.MaskingKey = data[suite.Npk() : suite.Npk()+suite.Nh()]

	return rr.Envelope.Deserialize(suite, data[suite.Npk()+suite.Nh():])
}

// Encode serializes the RegistrationRecord into bytes but with 2 byte length descriptors.
func (rr *RegistrationRecord) Encode() ([]byte, error) {
	if rr.ClientPubKey == nil || rr.Envelope == nil || len(rr.MaskingKey) == 0 {
		return nil, ErrEncodingFailed
	}

	serializedCPubKey, err := rr.ClientPubKey.MarshalBinary()
	if err != nil {
		return nil, ErrEncodingFailed
	}

	encodedEnvelope, err := rr.Envelope.Encode()
	if err != nil {
		return nil, err
	}

	encoded, err := common.Encoder(2, serializedCPubKey, rr.MaskingKey)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return utils.Concat(encoded, encodedEnvelope), nil
}

// Decode deserializes encoded data into the RegistrationRecord struct.
func (rr *RegistrationRecord) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 4, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return rr.Deserialize(suite, utils.Concat(decoded...))
}
