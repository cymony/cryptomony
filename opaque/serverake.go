// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import "github.com/cymony/cryptomony/utils"

func (os *opaqueSuite) ServerInit(serverPrivKey *PrivateKey,
	serverPubKey *PublicKey,
	record *RegistrationRecord,
	ke1 *KE1,
	credIdentifier, clientIdentity, serverIdentity, oprfSeed []byte) (*ServerLoginState, *KE2, error) {
	//nolint:gocritic //not a commented code
	//   masking_nonce = random(Nn)
	chosenMaskingNonce := utils.RandomBytes(os.Nn())

	//nolint:gocritic //not a commented code
	// server_nonce = random(Nn)
	chosenServerNonce := utils.RandomBytes(os.Nn())

	// (server_private_keyshare, server_keyshare) = GenerateAuthKeyPair()
	chosenServerPrivateKeyshare, err := os.GenerateAuthKeyPair()
	if err != nil {
		return nil, nil, err
	}

	return os.serverInit(serverPrivKey,
		serverPubKey,
		record,
		ke1,
		credIdentifier, clientIdentity, serverIdentity, oprfSeed, chosenMaskingNonce, chosenServerNonce,
		chosenServerPrivateKeyshare)
}

func (os *opaqueSuite) serverInit(serverPrivKey *PrivateKey,
	serverPubKey *PublicKey,
	record *RegistrationRecord,
	ke1 *KE1,
	credIdentifier, clientIdentity, serverIdentity, oprfSeed, maskingNonce, serverNonce []byte,
	serverPrivateKeyshare *PrivateKey,
) (*ServerLoginState, *KE2, error) {
	//nolint:gocritic //not a commented code
	// credential_response = CreateCredentialResponse(ke1.request, server_public_key, record, credential_identifier, oprf_seed)
	credRes, err := os.CreateCredentialResponse(ke1.CredentialRequest, serverPubKey, record, credIdentifier, oprfSeed, maskingNonce)
	if err != nil {
		return nil, nil, err
	}

	if clientIdentity == nil {
		encodedCPubKey, err := record.ClientPubKey.MarshalBinary() //nolint:govet //fp
		if err != nil {
			return nil, nil, err
		}

		clientIdentity = encodedCPubKey
	}

	if serverIdentity == nil {
		encodedSPubkey, err := serverPubKey.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}

		serverIdentity = encodedSPubkey
	}

	//nolint:gocritic //not a commented code
	// auth_response = AuthServerRespond(server_identity, server_private_key, client_identity, record.client_public_key, ke1, credential_response)
	state, authRes, err := os.AuthServerRespond(serverPrivKey, serverIdentity, clientIdentity, serverNonce, record.ClientPubKey, ke1, credRes, serverPrivateKeyshare)
	if err != nil {
		return nil, nil, err
	}

	return state, &KE2{
		CredentialResponse: credRes,
		AuthResponse:       authRes,
	}, nil
}

func (os *opaqueSuite) ServerFinish(state *ServerLoginState, ke3 *KE3) ([]byte, error) {
	return os.AuthServerFinalize(state, ke3)
}
