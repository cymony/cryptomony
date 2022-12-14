// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/utils"
)

func (os *opaqueSuite) ClientInit(password []byte) (*ClientLoginState, *KE1, error) {
	chosenBlind := os.OPRF().Group().RandomScalar()

	//nolint:gocritic // not a commented code
	// client_nonce = random(Nn)
	chosenClientNonce := utils.RandomBytes(os.Nn())

	// (client_secret, client_keyshare) = GenerateAuthKeyPair()
	chosenClientSecret, err := os.GenerateAuthKeyPair()
	if err != nil {
		return nil, nil, err
	}

	return os.clientInit(password, chosenClientNonce, chosenBlind, chosenClientSecret)
}

func (os *opaqueSuite) clientInit(password, chosenClientNonce []byte, chosenBlind *eccgroup.Scalar, chosenClientSecret *PrivateKey) (*ClientLoginState, *KE1, error) {
	credReq, blind, err := os.CreateCredentialRequest(password, chosenBlind)
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	//  ke1 = AuthClientStart(request)
	state, ke1, err := os.AuthClientStart(credReq, chosenClientNonce, chosenClientSecret)
	if err != nil {
		return nil, nil, err
	}

	return &ClientLoginState{
		Password:     password,
		Blind:        blind,
		ClientSecret: state.ClientSecret,
		KE1:          state.KE1,
	}, ke1, nil
}

func (os *opaqueSuite) ClientFinish(state *ClientLoginState, clientIdentity, serverIdentity []byte, ke2 *KE2) (*KE3, []byte, []byte, error) {
	clientPrivKey, serverPubKey, exportKey, err := os.RecoverCredentials(state.Password, state.Blind, ke2.CredentialResponse, serverIdentity, clientIdentity)
	if err != nil {
		return nil, nil, nil, err
	}

	if clientIdentity == nil {
		clientSerializedPublicKey, err := clientPrivKey.Public().MarshalBinary() //nolint:govet //fp
		if err != nil {
			return nil, nil, nil, err
		}

		clientIdentity = clientSerializedPublicKey
	}

	if serverIdentity == nil {
		serverSerializedPublicKey, err := serverPubKey.MarshalBinary() //nolint:govet //fp
		if err != nil {
			return nil, nil, nil, err
		}

		serverIdentity = serverSerializedPublicKey
	}

	ke3, sessionKey, err := os.AuthClientFinalize(state, clientIdentity, serverIdentity, clientPrivKey, serverPubKey, ke2)
	if err != nil {
		return nil, nil, nil, err
	}

	return ke3, sessionKey, exportKey, nil
}
