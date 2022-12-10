// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"crypto/hmac"

	"github.com/cymony/cryptomony/utils"
)

// The function AuthServerRespond implements OPAQUE-3DH AuthServerRespond function.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-3dh-server-functions.
// Unlike draft implementation, this function returns server state instead of managing it internally.
func (os *opaqueSuite) AuthServerRespond(serverPrivKey *PrivateKey,
	serverIdentity, clientIdentity []byte,
	clientPubKey *PublicKey,
	ke1 *KE1,
	credentialRes *CredentialResponse) (*ServerLoginState, *AuthResponse, error) {
	g := os.OPRF().Group()

	//nolint:gocritic //not a commented code
	// server_nonce = random(Nn)
	serverNonce := utils.RandomBytes(os.Nn())

	// (server_private_keyshare, server_keyshare) = GenerateAuthKeyPair()
	serverPrivateKeyshare, err := os.GenerateAuthKeyPair()
	if err != nil {
		return nil, nil, err
	}

	serverKeyshare := serverPrivateKeyshare.Public()

	//nolint:gocritic //not a commented code
	// preamble = Preamble(client_identity,
	// 	ke1,
	// 	server_identity,
	// 	credential_response,
	// 	server_nonce,
	// 	server_keyshare)
	prmbl, err := preamble(clientIdentity, ke1, serverIdentity, credentialRes, serverNonce, serverKeyshare)
	if err != nil {
		return nil, nil, err
	}

	clientShareEl, err := getElementFromPublicKey(g, ke1.AuthRequest.ClientKeyshare)
	if err != nil {
		return nil, nil, err
	}

	serverPrivKeyshareSc, err := getScalarFromPrivKey(g, serverPrivateKeyshare)
	if err != nil {
		return nil, nil, err
	}

	serverPrivSc, err := getScalarFromPrivKey(g, serverPrivKey)
	if err != nil {
		return nil, nil, err
	}

	clientPubEl, err := getElementFromPublicKey(g, clientPubKey)
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// dh1 = SerializeElement(server_private_keyshare * ke1.auth_request.client_keyshare)
	dh1 := g.NewElement().Add(clientShareEl).Multiply(serverPrivKeyshareSc).Encode()

	//nolint:gocritic //not a commented code
	// dh2 = SerializeElement(server_private_key * ke1.auth_request.client_keyshare)
	dh2 := g.NewElement().Add(clientShareEl).Multiply(serverPrivSc).Encode()

	//nolint:gocritic //not a commented code
	// dh3 = SerializeElement(server_private_keyshare * client_public_key)
	dh3 := g.NewElement().Add(clientPubEl).Multiply(serverPrivKeyshareSc).Encode()

	//nolint:gocritic //not a commented code
	// ikm = concat(dh1, dh2, dh3)
	ikm := utils.Concat(dh1, dh2, dh3)

	//nolint:gocritic //not a commented code
	// Km2, Km3, session_key = DeriveKeys(ikm, preamble)
	km2, km3, sessionKey, err := deriveKeys(os, ikm, prmbl)
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// server_mac = MAC(Km2, Hash(preamble))
	H := os.Hash()

	err = H.MustWriteAll(prmbl)
	if err != nil {
		return nil, nil, err
	}

	serverMAC, err := os.MAC(km2, H.Sum(nil))
	if err != nil {
		return nil, nil, err
	}

	// expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
	H.Reset()

	err = H.MustWriteAll(utils.Concat(prmbl, serverMAC))
	if err != nil {
		return nil, nil, err
	}

	expectedClientMac, err := os.MAC(km3, H.Sum(nil))
	if err != nil {
		return nil, nil, err
	}

	// state.expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac))
	// state.session_key = session_key
	serverState := &ServerLoginState{
		ExpectedClientMac: expectedClientMac,
		SessionKey:        sessionKey,
	}

	return serverState, &AuthResponse{
		ServerNonce:    serverNonce,
		ServerKeyshare: serverKeyshare,
		ServerMAC:      serverMAC,
	}, nil
}

// The function AuthServerFinalize implements OPAQUE-3DH AuthServerFinalize function.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-3dh-server-functions.
func (os *opaqueSuite) AuthServerFinalize(state *ServerLoginState, ke3 *KE3) ([]byte, error) {
	if !hmac.Equal(ke3.ClientMAC, state.ExpectedClientMac) {
		return nil, ErrClientAuthentication
	}

	return state.SessionKey, nil
}
