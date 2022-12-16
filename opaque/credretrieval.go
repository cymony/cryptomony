// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/utils"
)

func (os *opaqueSuite) CreateCredentialRequest(password []byte, chosenBlind *eccgroup.Scalar) (*CredentialRequest, *eccgroup.Scalar, error) {
	blind, blindedEl, err := os.deterministicBlind(password, chosenBlind)
	if err != nil {
		return nil, nil, err
	}

	return &CredentialRequest{
		BlindedMessage: blindedEl,
	}, blind, nil
}

func (os *opaqueSuite) CreateCredentialResponse(credReq *CredentialRequest,
	serverPubKey *PublicKey,
	record *RegistrationRecord,
	credIdentifier []byte,
	oprfSeed []byte,
	maskingNonce []byte) (*CredentialResponse, error) {
	if len(oprfSeed) != os.Nh() {
		return nil, ErrOPRFSeedLength
	}

	//nolint:gocritic //not a commented code
	// seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
	seed := os.Expand(oprfSeed, utils.Concat(credIdentifier, []byte(labelOprfKey)), os.Nok())
	// (oprf_key, _) = DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
	oprfKey, err := os.DeriveKeyPair(seed)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// blinded_element = DeserializeElement(request.blinded_message)
	// evaluated_element = Evaluate(oprf_key, blinded_element)
	evaluatedEl, err := os.evaluate(credReq.BlindedMessage, oprfKey)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// credential_response_pad = Expand(record.masking_key, concat(masking_nonce, "CredentialResponsePad"), Npk+Ne)
	credResPad := os.Expand(record.MaskingKey, utils.Concat(maskingNonce, []byte(labelCredentialResponsePad)), os.Npk()+os.Ne())

	//nolint:gocritic //not a commented code
	// masked_response = xor(credential_response_pad, concat(server_public_key, record.envelope))
	serializedServerPubKey, err := serverPubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	serializedEnvelope, err := record.Envelope.Serialize()
	if err != nil {
		return nil, err
	}

	maskedResponse := xor(credResPad, utils.Concat(serializedServerPubKey, serializedEnvelope))

	// Create CredentialResponse response with (evaluated_message, masking_nonce, masked_response)
	return &CredentialResponse{
		EvaluatedMessage: evaluatedEl,
		MaskingNonce:     maskingNonce,
		MaskedResponse:   maskedResponse,
	}, nil
}

func (os *opaqueSuite) RecoverCredentials(password []byte, blind *eccgroup.Scalar, credRes *CredentialResponse, serverIdentity, clientIdentity []byte) (*PrivateKey, *PublicKey, []byte, error) {
	//nolint:gocritic //not a commented code
	// oprf_output = Finalize(password, blind, evaluated_element)
	oprfOut, err := os.finalize(credRes.EvaluatedMessage, password, blind)
	if err != nil {
		return nil, nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// stretched_oprf_output = Stretch(oprf_output, params)
	stretchedOprfOut, err := os.Stretch(oprfOut, int(os.OPRF().Group().ElementLength()))
	if err != nil {
		return nil, nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// randomized_pwd = Extract("", concat(oprf_output, stretched_oprf_output))
	randomizedPwd := os.Extract(nil, utils.Concat(oprfOut, stretchedOprfOut))

	//nolint:gocritic //not a commented code
	// masking_key = Expand(randomized_pwd, "MaskingKey", Nh)
	maskingKey := os.Expand(randomizedPwd, []byte(labelMaskingKey), os.Nh())

	//nolint:gocritic //not a commented code
	// credential_response_pad = Expand(masking_key, concat(response.masking_nonce, "CredentialResponsePad"), Npk + Ne)
	credResPad := os.Expand(maskingKey, utils.Concat(credRes.MaskingNonce, []byte(labelCredentialResponsePad)), os.Npk()+os.Ne())

	//nolint:gocritic //not a commented code
	// concat(server_public_key, envelope) = xor(credential_response_pad, response.masked_response)
	sPubAndEnvelope := xor(credResPad, credRes.MaskedResponse)
	if len(sPubAndEnvelope) != os.Npk()+os.Ne() {
		return nil, nil, nil, ErrRecoverCredentialsFailed
	}

	serializedSPubKey := sPubAndEnvelope[:os.Npk()]
	serializedEnvelope := sPubAndEnvelope[os.Npk():]

	// (client_private_key, export_key) = Recover(randomized_pwd, server_public_key, envelope, server_identity, client_identity)
	sPubKey := &PublicKey{}

	err = sPubKey.UnmarshalBinary(os, serializedSPubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	envelope := &Envelope{}

	err = envelope.Deserialize(os, serializedEnvelope)
	if err != nil {
		return nil, nil, nil, err
	}

	clientPrivKey, exportKey, err := os.Recover(randomizedPwd, sPubKey, envelope, serverIdentity, clientIdentity)
	if err != nil {
		return nil, nil, nil, err
	}

	return clientPrivKey, sPubKey, exportKey, nil
}
