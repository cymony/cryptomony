// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/utils"
)

func (os *opaqueSuite) CreateRegistrationRequest(password []byte) (*RegistrationRequest, *eccgroup.Scalar, error) {
	chosenBlind := os.Group().RandomScalar()

	return os.createRegistrationRequest(password, chosenBlind)
}

func (os *opaqueSuite) createRegistrationRequest(password []byte, chosenBlind *eccgroup.Scalar) (*RegistrationRequest, *eccgroup.Scalar, error) {
	blind, blindedEl, err := os.deterministicBlind(password, chosenBlind)
	if err != nil {
		return nil, nil, err
	}

	return &RegistrationRequest{
		BlindedMessage: blindedEl,
	}, blind, nil
}

func (os *opaqueSuite) FinalizeRegistrationRequest(password, serverIdentity, clientIdentity []byte, blind *eccgroup.Scalar, regRes *RegistrationResponse) (*RegistrationRecord, []byte, error) {
	return os.finalizeRegistrationRequest(password, serverIdentity, clientIdentity, blind, regRes, nil)
}

func (os *opaqueSuite) finalizeRegistrationRequest(password, serverIdentity, clientIdentity []byte, blind *eccgroup.Scalar, regRes *RegistrationResponse, envelopeNonce []byte) (*RegistrationRecord, []byte, error) {
	//nolint:gocritic //not a commented code
	// evaluated_element = DeserializeElement(response.evaluated_message)
	// oprf_output = Finalize(password, blind, evaluated_element)
	oprfOutput, err := os.finalize(regRes.EvaluatedMessage, password, blind)
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// stretched_oprf_output = Stretch(oprf_output, params)
	stretchedOprfOutput, err := os.Stretch(oprfOutput, int(os.OPRF().Group().ElementLength()))
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// randomized_pwd = Extract("", concat(oprf_output, stretched_oprf_output))
	randomizedPwd := os.Extract(nil, utils.Concat(oprfOutput, stretchedOprfOutput))

	// (envelope, client_public_key, masking_key, export_key) = Store(randomized_pwd, response.server_public_key, server_identity, client_identity)
	var envelope *Envelope

	var cPubKey *PublicKey

	var maskingKey, exportKey []byte

	if envelopeNonce == nil {
		envelope, cPubKey, maskingKey, exportKey, err = os.Store(randomizedPwd, regRes.ServerPublicKey, serverIdentity, clientIdentity)
	} else {
		envelope, cPubKey, maskingKey, exportKey, err = os.store(randomizedPwd, regRes.ServerPublicKey, serverIdentity, clientIdentity, envelopeNonce)
	}

	if err != nil {
		return nil, nil, err
	}

	// Create RegistrationRecord record with (client_public_key, masking_key, envelope)
	// return (record, export_key)
	return &RegistrationRecord{
		ClientPubKey: cPubKey,
		MaskingKey:   maskingKey,
		Envelope:     envelope,
	}, exportKey, nil
}
