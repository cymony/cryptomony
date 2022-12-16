// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/opaque/internal/common"
	"github.com/cymony/cryptomony/utils"
)

// CredentialRequest represents the CredentialRequest struct on the draft.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-credential-retrieval-messag
type CredentialRequest struct {
	BlindedMessage *eccgroup.Element // blinded_message[Noe]
}

// Serialize serializes the CredentialRequest to bytes
func (cr *CredentialRequest) Serialize() ([]byte, error) {
	if cr.BlindedMessage == nil {
		return nil, ErrSerializationFailed
	}

	return cr.BlindedMessage.Encode(), nil
}

// Deserialize deserializes bytes into the CredentialRequest struct
func (cr *CredentialRequest) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Noe() {
		return ErrDeserializationFailed
	}

	cr.BlindedMessage = suite.OPRF().Group().NewElement()
	if err := cr.BlindedMessage.Decode(data); err != nil {
		return ErrDeserializationFailed
	}
	// Always check is identity deserialized
	if cr.BlindedMessage.IsIdentity() {
		return ErrDeserializationFailed
	}

	return nil
}

// Encode serializes the CredentialRequest into bytes but with 2 byte length descriptors.
func (cr *CredentialRequest) Encode() ([]byte, error) {
	if cr.BlindedMessage == nil {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, cr.BlindedMessage.Encode())
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the CredentialRequest struct.
func (cr *CredentialRequest) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 1, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return cr.Deserialize(suite, utils.Concat(decoded...))
}

// AuthRequest represents the AuthRequest struct on the draft.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type AuthRequest struct {
	ClientKeyshare *PublicKey // client_keyshare[Npk]
	ClientNonce    []byte     // client_nonce[Nn]
}

// Serialize serializes the AuthRequest to bytes
func (ar *AuthRequest) Serialize() ([]byte, error) {
	if ar.ClientKeyshare == nil {
		return nil, ErrSerializationFailed
	}

	encodedKeyshare, err := ar.ClientKeyshare.MarshalBinary()
	if err != nil {
		return nil, ErrSerializationFailed
	}

	return utils.Concat(ar.ClientNonce, encodedKeyshare), nil
}

// Deserialize deserializes bytes into the AuthRequest struct
func (ar *AuthRequest) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Nn()+suite.Npk() {
		return ErrDeserializationFailed
	}

	ar.ClientNonce = data[:suite.Nn()]
	ar.ClientKeyshare = &PublicKey{}

	if err := ar.ClientKeyshare.UnmarshalBinary(suite, data[suite.Nn():]); err != nil {
		return ErrDeserializationFailed
	}

	return nil
}

// Encode serializes the AuthRequest into bytes but with 2 byte length descriptors.
func (ar *AuthRequest) Encode() ([]byte, error) {
	if ar.ClientKeyshare == nil {
		return nil, ErrEncodingFailed
	}

	encodedKeyshare, err := ar.ClientKeyshare.MarshalBinary()
	if err != nil {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, ar.ClientNonce, encodedKeyshare)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the AuthRequest struct.
func (ar *AuthRequest) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 2, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return ar.Deserialize(suite, utils.Concat(decoded...))
}

// KE1 represents the first message sent from client to server on login.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type KE1 struct {
	CredentialRequest *CredentialRequest // credential_request[Noe]
	AuthRequest       *AuthRequest       // auth_request[Nn+Npk]
}

// Serialize serializes the KE1 to bytes
func (ke *KE1) Serialize() ([]byte, error) {
	credSerialized, err := ke.CredentialRequest.Serialize()
	if err != nil {
		return nil, err
	}

	authSerialized, err := ke.AuthRequest.Serialize()
	if err != nil {
		return nil, err
	}

	return utils.Concat(credSerialized, authSerialized), nil
}

// Deserialize deserializes bytes into the KE1 struct
func (ke *KE1) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Noe()+suite.Nn()+suite.Npk() {
		return ErrDeserializationFailed
	}

	ke.CredentialRequest = &CredentialRequest{}
	ke.AuthRequest = &AuthRequest{}

	if err := ke.CredentialRequest.Deserialize(suite, data[:suite.Noe()]); err != nil {
		return err
	}

	return ke.AuthRequest.Deserialize(suite, data[suite.Noe():])
}

// Encode serializes the KE1 into bytes but with 2 byte length descriptors.
func (ke *KE1) Encode() ([]byte, error) {
	if ke.CredentialRequest == nil || ke.AuthRequest == nil {
		return nil, ErrEncodingFailed
	}

	encoded1, err := ke.CredentialRequest.Encode()
	if err != nil {
		return nil, err
	}

	encoded2, err := ke.AuthRequest.Encode()
	if err != nil {
		return nil, err
	}

	return utils.Concat(encoded1, encoded2), nil
}

// Decode deserializes encoded data into the KE1 struct.
func (ke *KE1) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 3, 2)
	if err != nil {
		return nil
	}

	return ke.Deserialize(suite, utils.Concat(decoded...))
}

// CredentialResponse represents the CredentialResponse struct on the draft.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-credential-retrieval-messag
type CredentialResponse struct {
	EvaluatedMessage *eccgroup.Element // evaluated_message[Noe]
	MaskingNonce     []byte            // masking_nonce[Nn]
	MaskedResponse   []byte            // masked_response[Npk + Ne]
}

// Serialize serializes the CredentialResponse to bytes
func (cr *CredentialResponse) Serialize() ([]byte, error) {
	if cr.EvaluatedMessage == nil {
		return nil, ErrSerializationFailed
	}

	return utils.Concat(cr.EvaluatedMessage.Encode(), cr.MaskingNonce, cr.MaskedResponse), nil
}

// Deserialize deserializes bytes into the CredentialResponse struct
func (cr *CredentialResponse) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Noe()+suite.Nn()+suite.Npk()+suite.Ne() {
		return ErrDeserializationFailed
	}

	cr.EvaluatedMessage = suite.OPRF().Group().NewElement()
	if err := cr.EvaluatedMessage.Decode(data[:suite.Noe()]); err != nil {
		return ErrDeserializationFailed
	}

	if cr.EvaluatedMessage.IsIdentity() {
		return ErrDeserializationFailed
	}

	cr.MaskingNonce = data[suite.Noe() : suite.Noe()+suite.Nn()]
	cr.MaskedResponse = data[suite.Noe()+suite.Nn():]

	return nil
}

// Encode serializes the CredentialResponse into bytes but with 2 byte length descriptors.
func (cr *CredentialResponse) Encode() ([]byte, error) {
	if cr.EvaluatedMessage == nil {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, cr.EvaluatedMessage.Encode(), cr.MaskingNonce, cr.MaskedResponse)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the CredentialResponse struct.
func (cr *CredentialResponse) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 3, 2)
	if err != nil {
		return nil
	}

	return cr.Deserialize(suite, utils.Concat(decoded...))
}

// AuthResponse represents the AuthResponse struct on the draft.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type AuthResponse struct {
	ServerNonce    []byte     // server_nonce[Nn]
	ServerKeyshare *PublicKey // server_keyshare[Npk]
	ServerMAC      []byte     // server_mac[Nm]
}

// Serialize serializes the AuthResponse to bytes
func (ar *AuthResponse) Serialize() ([]byte, error) {
	if ar.ServerKeyshare == nil {
		return nil, ErrSerializationFailed
	}

	encodedKeyshare, err := ar.ServerKeyshare.MarshalBinary()
	if err != nil {
		return nil, ErrSerializationFailed
	}

	return utils.Concat(ar.ServerNonce, encodedKeyshare, ar.ServerMAC), nil
}

// Deserialize deserializes bytes into the AuthResponse struct
func (ar *AuthResponse) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Nn()+suite.Npk()+suite.Nm() {
		return ErrDeserializationFailed
	}

	ar.ServerKeyshare = &PublicKey{}
	ar.ServerNonce = data[:suite.Nn()]

	if err := ar.ServerKeyshare.UnmarshalBinary(suite, data[suite.Nn():suite.Nn()+suite.Npk()]); err != nil {
		return ErrDeserializationFailed
	}

	ar.ServerMAC = data[suite.Nn()+suite.Npk():]

	return nil
}

// Encode serializes the AuthResponse into bytes but with 2 byte length descriptors.
func (ar *AuthResponse) Encode() ([]byte, error) {
	if ar.ServerKeyshare == nil {
		return nil, ErrEncodingFailed
	}

	encodedKeyshare, err := ar.ServerKeyshare.MarshalBinary()
	if err != nil {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, ar.ServerNonce, encodedKeyshare, ar.ServerMAC)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the AuthResponse struct.
func (ar *AuthResponse) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 3, 2)
	if err != nil {
		return nil
	}

	return ar.Deserialize(suite, utils.Concat(decoded...))
}

// KE2 represents the second message sent from server to client on login.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type KE2 struct {
	CredentialResponse *CredentialResponse // credential_response[Noe+Nn+Npk+Ne]
	AuthResponse       *AuthResponse       // auth_response[Nn+Npk+Nm]
}

// Serialize serializes the KE2 to bytes
func (ke *KE2) Serialize() ([]byte, error) {
	credSerialized, err := ke.CredentialResponse.Serialize()
	if err != nil {
		return nil, err
	}

	authSerialized, err := ke.AuthResponse.Serialize()
	if err != nil {
		return nil, err
	}

	return utils.Concat(credSerialized, authSerialized), nil
}

// Deserialize deserializes bytes into the KE2 struct
func (ke *KE2) Deserialize(suite Suite, data []byte) error {
	lenCredRes := suite.Noe() + suite.Nn() + suite.Npk() + suite.Ne()
	lenAuthRes := suite.Nn() + suite.Npk() + suite.Nm()

	if len(data) != lenCredRes+lenAuthRes {
		return ErrDeserializationFailed
	}

	ke.CredentialResponse = &CredentialResponse{}
	ke.AuthResponse = &AuthResponse{}

	if err := ke.CredentialResponse.Deserialize(suite, data[:lenCredRes]); err != nil {
		return err
	}

	return ke.AuthResponse.Deserialize(suite, data[lenCredRes:])
}

// Encode serializes the KE2 into bytes but with 2 byte length descriptors.
func (ke *KE2) Encode() ([]byte, error) {
	if ke.CredentialResponse == nil || ke.AuthResponse == nil {
		return nil, ErrEncodingFailed
	}

	encoded1, err := ke.CredentialResponse.Encode()
	if err != nil {
		return nil, err
	}

	encoded2, err := ke.AuthResponse.Encode()
	if err != nil {
		return nil, err
	}

	return utils.Concat(encoded1, encoded2), nil
}

// Decode deserializes encoded data into the KE2 struct.
func (ke *KE2) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 6, 2)
	if err != nil {
		return nil
	}

	return ke.Deserialize(suite, utils.Concat(decoded...))
}

// KE3 represents the third message sent from client to server on login.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type KE3 struct {
	ClientMAC []byte // client_mac[Nm]
}

// Serialize serializes the KE3 to bytes
func (ke *KE3) Serialize() ([]byte, error) {
	return ke.ClientMAC, nil
}

// Deserialize deserializes bytes into the KE3 struct
func (ke *KE3) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Nm() {
		return ErrDeserializationFailed
	}

	ke.ClientMAC = data

	return nil
}

// Encode serializes the KE3 into bytes but with 2 byte length descriptors.
func (ke *KE3) Encode() ([]byte, error) {
	encoded, err := common.Encoder(2, ke.ClientMAC)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the KE3 struct.
func (ke *KE3) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 1, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return ke.Deserialize(suite, utils.Concat(decoded...))
}
