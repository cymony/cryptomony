// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

func (os *opaqueSuite) ClientInit(password []byte) (*ClientLoginState, *KE1, error) {
	//nolint:gocritic //not a commented code
	// credential_request, blind = CreateCredentialRequest(password)
	credReq, blind, err := os.CreateCredentialRequest(password)
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	//  ke1 = AuthClientStart(request)
	state, ke1, err := os.AuthClientStart(credReq)
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

	ke3, sessionKey, err := os.AuthClientFinalize(state, clientIdentity, serverIdentity, clientPrivKey, serverPubKey, ke2)
	if err != nil {
		return nil, nil, nil, err
	}

	return ke3, sessionKey, exportKey, nil
}
