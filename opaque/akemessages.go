// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/opaque/internal/common"
	"github.com/cymony/cryptomony/utils"
)

// CredentialRequest struct. Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-credential-retrieval-messag
type CredentialRequest struct {
	BlindedMessage *eccgroup.Element // blinded_message[Noe]
}

func (cr *CredentialRequest) serialize() ([]byte, error) {
	if cr.BlindedMessage == nil {
		return nil, ErrSerializationFailed
	}

	return cr.BlindedMessage.Encode(), nil
}

func (cr *CredentialRequest) deserialize(suite Suite, data []byte) error {
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

func (cr *CredentialRequest) encode() ([]byte, error) {
	if cr.BlindedMessage == nil {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, cr.BlindedMessage.Encode())
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// AuthRequest struct. Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type AuthRequest struct {
	ClientKeyshare *PublicKey // client_keyshare[Npk]
	ClientNonce    []byte     // client_nonce[Nn]
}

func (ar *AuthRequest) serialize() ([]byte, error) {
	if ar.ClientKeyshare == nil {
		return nil, ErrSerializationFailed
	}

	encodedKeyshare, err := ar.ClientKeyshare.MarshalBinary()
	if err != nil {
		return nil, ErrSerializationFailed
	}

	return utils.Concat(ar.ClientNonce, encodedKeyshare), nil
}

func (ar *AuthRequest) deserialize(suite Suite, data []byte) error {
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

func (ar *AuthRequest) encode() ([]byte, error) {
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

// KE1 struct. Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type KE1 struct {
	CredentialRequest *CredentialRequest // credential_request[Noe]
	AuthRequest       *AuthRequest       // auth_request[Nn+Npk]
}

func (ke *KE1) Serialize() ([]byte, error) {
	credSerialized, err := ke.CredentialRequest.serialize()
	if err != nil {
		return nil, err
	}

	authSerialized, err := ke.AuthRequest.serialize()
	if err != nil {
		return nil, err
	}

	return utils.Concat(credSerialized, authSerialized), nil
}

func (ke *KE1) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Noe()+suite.Nn()+suite.Npk() {
		return ErrDeserializationFailed
	}

	ke.CredentialRequest = &CredentialRequest{}
	ke.AuthRequest = &AuthRequest{}

	if err := ke.CredentialRequest.deserialize(suite, data[:suite.Noe()]); err != nil {
		return err
	}

	return ke.AuthRequest.deserialize(suite, data[suite.Noe():])
}

func (ke *KE1) Encode() ([]byte, error) {
	if ke.CredentialRequest == nil || ke.AuthRequest == nil {
		return nil, ErrEncodingFailed
	}

	encoded1, err := ke.CredentialRequest.encode()
	if err != nil {
		return nil, err
	}

	encoded2, err := ke.AuthRequest.encode()
	if err != nil {
		return nil, err
	}

	return utils.Concat(encoded1, encoded2), nil
}

func (ke *KE1) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 3, 2)
	if err != nil {
		return nil
	}

	return ke.Deserialize(suite, utils.Concat(decoded...))
}

// CredentialResponse struct. Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-credential-retrieval-messag
type CredentialResponse struct {
	EvaluatedMessage *eccgroup.Element // evaluated_message[Noe]
	MaskingNonce     []byte            // masking_nonce[Nn]
	MaskedResponse   []byte            // masked_response[Npk + Ne]
}

func (cr *CredentialResponse) serialize() ([]byte, error) {
	if cr.EvaluatedMessage == nil {
		return nil, ErrSerializationFailed
	}

	return utils.Concat(cr.EvaluatedMessage.Encode(), cr.MaskingNonce, cr.MaskedResponse), nil
}

func (cr *CredentialResponse) deserialize(suite Suite, data []byte) error {
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

func (cr *CredentialResponse) encode() ([]byte, error) {
	if cr.EvaluatedMessage == nil {
		return nil, ErrEncodingFailed
	}

	encoded, err := common.Encoder(2, cr.EvaluatedMessage.Encode(), cr.MaskingNonce, cr.MaskedResponse)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// AuthResponse struct. Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type AuthResponse struct {
	ServerNonce    []byte     // server_nonce[Nn]
	ServerKeyshare *PublicKey // server_keyshare[Npk]
	ServerMAC      []byte     // server_mac[Nm]
}

func (ar *AuthResponse) serialize() ([]byte, error) {
	if ar.ServerKeyshare == nil {
		return nil, ErrSerializationFailed
	}

	encodedKeyshare, err := ar.ServerKeyshare.MarshalBinary()
	if err != nil {
		return nil, ErrSerializationFailed
	}

	return utils.Concat(ar.ServerNonce, encodedKeyshare, ar.ServerMAC), nil
}

func (ar *AuthResponse) deserialize(suite Suite, data []byte) error {
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

func (ar *AuthResponse) encode() ([]byte, error) {
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

// KE2 Message. Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type KE2 struct {
	CredentialResponse *CredentialResponse // credential_response[Noe+Nn+Npk+Ne]
	AuthResponse       *AuthResponse       // auth_response[Nn+Npk+Nm]
}

func (ke *KE2) Serialize() ([]byte, error) {
	credSerialized, err := ke.CredentialResponse.serialize()
	if err != nil {
		return nil, err
	}

	authSerialized, err := ke.AuthResponse.serialize()
	if err != nil {
		return nil, err
	}

	return utils.Concat(credSerialized, authSerialized), nil
}

func (ke *KE2) Deserialize(suite Suite, data []byte) error {
	lenCredRes := suite.Noe() + suite.Nn() + suite.Npk() + suite.Ne()
	lenAuthRes := suite.Nn() + suite.Npk() + suite.Nm()

	if len(data) != lenCredRes+lenAuthRes {
		return ErrDeserializationFailed
	}

	ke.CredentialResponse = &CredentialResponse{}
	ke.AuthResponse = &AuthResponse{}

	if err := ke.CredentialResponse.deserialize(suite, data[:lenCredRes]); err != nil {
		return err
	}

	return ke.AuthResponse.deserialize(suite, data[lenCredRes:])
}

func (ke *KE2) Encode() ([]byte, error) {
	if ke.CredentialResponse == nil || ke.AuthResponse == nil {
		return nil, ErrEncodingFailed
	}

	encoded1, err := ke.CredentialResponse.encode()
	if err != nil {
		return nil, err
	}

	encoded2, err := ke.AuthResponse.encode()
	if err != nil {
		return nil, err
	}

	return utils.Concat(encoded1, encoded2), nil
}

func (ke *KE2) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 6, 2)
	if err != nil {
		return nil
	}

	return ke.Deserialize(suite, utils.Concat(decoded...))
}

// KE3 Message. Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-ake-messages
type KE3 struct {
	ClientMAC []byte // client_mac[Nm]
}

func (ke *KE3) Serialize() ([]byte, error) {
	return ke.ClientMAC, nil
}

func (ke *KE3) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Nm() {
		return ErrDeserializationFailed
	}

	ke.ClientMAC = data

	return nil
}

func (ke *KE3) Encode() ([]byte, error) {
	encoded, err := common.Encoder(2, ke.ClientMAC)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

func (ke *KE3) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 1, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return ke.Deserialize(suite, utils.Concat(decoded...))
}
