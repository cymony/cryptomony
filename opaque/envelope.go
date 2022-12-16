// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

import (
	"crypto/hmac"

	"github.com/cymony/cryptomony/opaque/internal/common"
	"github.com/cymony/cryptomony/utils"
)

// Envelope represents the envelope struct on the draft.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-envelope-structure
type Envelope struct {
	Nonce   []byte // nonce[Nn]
	AuthTag []byte // auth_tag[Nm]
}

// Serialize serializes the Envelope to bytes
func (e *Envelope) Serialize() ([]byte, error) {
	return utils.Concat(e.Nonce, e.AuthTag), nil
}

// Deserialize deserializes bytes into the Envelope struct
func (e *Envelope) Deserialize(suite Suite, data []byte) error {
	if len(data) != suite.Nn()+suite.Nm() {
		return ErrDeserializationFailed
	}

	e.Nonce = data[:suite.Nn()]
	e.AuthTag = data[suite.Nn():]

	return nil
}

// Encode serializes the Envelope into bytes but with 2 byte length descriptors.
func (e *Envelope) Encode() ([]byte, error) {
	encoded, err := common.Encoder(2, e.Nonce, e.AuthTag)
	if err != nil {
		return nil, ErrEncodingFailed
	}

	return encoded, nil
}

// Decode deserializes encoded data into the Envelope struct.
func (e *Envelope) Decode(suite Suite, data []byte) error {
	decoded, err := common.Decoder(data, 2, 2)
	if err != nil {
		return ErrDecodingFailed
	}

	return e.Deserialize(suite, utils.Concat(decoded...))
}

func (os *opaqueSuite) Store(randomizedPwd []byte, sPubKey *PublicKey, serverIdentity, clientIdentity []byte) (*Envelope, *PublicKey, []byte, []byte, error) {
	//nolint:gocritic //not a commented code
	// envelope_nonce = random(Nn)
	envelopeNonce := utils.RandomBytes(os.Nn())

	return os.store(randomizedPwd, sPubKey, serverIdentity, clientIdentity, envelopeNonce)
}

func (os *opaqueSuite) store(randomizedPwd []byte, sPubKey *PublicKey, serverIdentity, clientIdentity, envelopeNonce []byte) (*Envelope, *PublicKey, []byte, []byte, error) {
	Nh := os.Nh()

	//nolint:gocritic //not a commented code
	//  masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
	maskingKey := os.Expand(randomizedPwd, []byte(labelMaskingKey), Nh)

	//nolint:gocritic //not a commented code
	// auth_key = Expand(randomized_pwd, concat(envelope_nonce, "AuthKey"), Nh)
	authKey := os.Expand(randomizedPwd, utils.Concat(envelopeNonce, []byte(labelAuthKey)), Nh)

	//nolint:gocritic //not a commented code
	// export_key = Expand(randomized_pwd, concat(envelope_nonce, "ExportKey"), Nh)
	exportKey := os.Expand(randomizedPwd, utils.Concat(envelopeNonce, []byte(labelExportKey)), Nh)

	//nolint:gocritic //not a commented code
	// seed = Expand(randomized_pwd, concat(envelope_nonce, "PrivateKey"), Nseed)
	seed := os.Expand(randomizedPwd, utils.Concat(envelopeNonce, []byte(labelPrivateKey)), os.Nseed())

	// (_, client_public_key) = DeriveAuthKeyPair(seed)
	cPrivKey, err := os.DeriveAuthKeyPair(seed)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cPubKey := cPrivKey.Public()

	sPubEncoded, err := sPubKey.MarshalBinary()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// client_public_key
	cPubEncoded, err := cPubKey.MarshalBinary()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
	cleartextCreds := CreateCleartextCredentials(sPubEncoded, cPubEncoded, serverIdentity, clientIdentity)

	encodedCreds, err := cleartextCreds.Encode()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// auth_tag = MAC(auth_key, concat(envelope_nonce, cleartext_creds))
	authTag, err := os.MAC(authKey, utils.Concat(envelopeNonce, encodedCreds))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create Envelope envelope with (envelope_nonce, auth_tag)
	envelope := &Envelope{
		Nonce:   envelopeNonce,
		AuthTag: authTag,
	}

	// return (envelope, client_public_key, masking_key, export_key)
	return envelope, cPubKey, maskingKey, exportKey, nil
}

func (os *opaqueSuite) Recover(randomizedPwd []byte, sPubKey *PublicKey, envelope *Envelope, serverIdentity, clientIdentity []byte) (*PrivateKey, []byte, error) {
	Nh := os.Nh()

	//nolint:gocritic //not a commented code
	// auth_key = Expand(randomized_pwd, concat(envelope.nonce, "AuthKey"), Nh)
	authKey := os.Expand(randomizedPwd, utils.Concat(envelope.Nonce, []byte(labelAuthKey)), Nh)

	// export_key = Expand(randomized_pwd, concat(envelope.nonce, "ExportKey", Nh)
	exportKey := os.Expand(randomizedPwd, utils.Concat(envelope.Nonce, []byte(labelExportKey)), Nh)

	//nolint:gocritic //not a commented code
	// seed = Expand(randomized_pwd, concat(envelope.nonce, "PrivateKey"), Nseed)
	seed := os.Expand(randomizedPwd, utils.Concat(envelope.Nonce, []byte(labelPrivateKey)), os.Nseed())

	cPrivKey, err := os.DeriveAuthKeyPair(seed)
	if err != nil {
		return nil, nil, err
	}

	sPubEncoded, err := sPubKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	cPubEncoded, err := cPrivKey.Public().MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// cleartext_creds = CreateCleartextCredentials(server_public_key, client_public_key, server_identity, client_identity)
	cleartextCreds := CreateCleartextCredentials(sPubEncoded, cPubEncoded, serverIdentity, clientIdentity)

	encodedCreds, err := cleartextCreds.Encode()
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// expected_tag = MAC(auth_key, concat(envelope.nonce, cleartext_creds))
	expectedTag, err := os.MAC(authKey, utils.Concat(envelope.Nonce, encodedCreds))
	if err != nil {
		return nil, nil, err
	}

	if !hmac.Equal(envelope.AuthTag, expectedTag) {
		return nil, nil, ErrEnvelopeRecovery
	}

	return cPrivKey, exportKey, nil
}
