// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import "github.com/cymony/cryptomony/utils"

func (os *opaqueSuite) GenerateOprfSeed() []byte {
	return utils.RandomBytes(os.Nh())
}

func (os *opaqueSuite) CreateRegistrationResponse(regReq *RegistrationRequest, serverPubKey *PublicKey, credentialIdentifier, oprfSeed []byte) (*RegistrationResponse, error) {
	//nolint:gocritic //not a commented code
	// seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
	seed := os.Expand(oprfSeed, utils.Concat(credentialIdentifier, []byte(labelOprfKey)), os.Nok())
	// (oprf_key, _) = DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
	oprfKey, err := os.DeriveKeyPair(seed)
	if err != nil {
		return nil, err
	}

	//nolint:gocritic //not a commented code
	// blinded_element = DeserializeElement(request.blinded_message)
	// evaluated_element = Evaluate(oprf_key, blinded_element)
	evaluatedEl, err := os.evaluate(regReq.BlindedMessage, oprfKey)
	if err != nil {
		return nil, err
	}

	// Create RegistrationResponse response with (evaluated_message, server_public_key)
	return &RegistrationResponse{
		EvaluatedMessage: evaluatedEl,
		ServerPublicKey:  serverPubKey,
	}, nil
}
