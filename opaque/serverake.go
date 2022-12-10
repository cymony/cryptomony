// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

func (os *opaqueSuite) ServerInit(serverPrivKey *PrivateKey,
	serverPubKey *PublicKey,
	record *RegistrationRecord,
	ke1 *KE1,
	credIdentifier, clientIdentity, serverIdentity, oprfSeed []byte) (*ServerLoginState, *KE2, error) {
	//nolint:gocritic //not a commented code
	// credential_response = CreateCredentialResponse(ke1.request, server_public_key, record, credential_identifier, oprf_seed)
	credRes, err := os.CreateCredentialResponse(ke1.CredentialRequest, serverPubKey, record, credIdentifier, oprfSeed)
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// auth_response = AuthServerRespond(server_identity, server_private_key, client_identity, record.client_public_key, ke1, credential_response)
	state, authRes, err := os.AuthServerRespond(serverPrivKey, serverIdentity, clientIdentity, record.ClientPubKey, ke1, credRes)
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
