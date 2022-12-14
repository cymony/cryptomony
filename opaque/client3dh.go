// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"crypto/hmac"

	"github.com/cymony/cryptomony/utils"
)

// The function AuthClientStart implements OPAQUE-3DH AuthClientStart function.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-3dh-client-functions
// Unlike draft implementation, this function returns client state instead of managing it internally.
func (os *opaqueSuite) AuthClientStart(credentialReq *CredentialRequest, clientNonce []byte, clientSecret *PrivateKey) (*ClientLoginState, *KE1, error) {
	clientKeyshare := clientSecret.Public()

	authRequest := &AuthRequest{
		ClientNonce:    clientNonce,
		ClientKeyshare: clientKeyshare,
	}

	// Create KE1 ke1 with (credential_request, auth_request)
	ke1 := &KE1{
		CredentialRequest: credentialReq,
		AuthRequest:       authRequest,
	}

	return &ClientLoginState{
		ClientSecret: clientSecret,
		KE1:          ke1,
	}, ke1, nil
}

// The function AuthClientFinalize implements OPAQUE-3DH AuthClientFinalize function.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-3dh-client-functions
func (os *opaqueSuite) AuthClientFinalize(state *ClientLoginState,
	clientIdentity, serverIdentity []byte,
	cPrivKey *PrivateKey,
	sPubKey *PublicKey,
	ke2 *KE2) (*KE3, []byte, error) {
	g := os.OPRF().Group()

	clientSecretSc, err := getScalarFromPrivKey(g, state.ClientSecret)
	if err != nil {
		return nil, nil, err
	}

	serverKeyshareEl, err := getElementFromPublicKey(g, ke2.AuthResponse.ServerKeyshare)
	if err != nil {
		return nil, nil, err
	}

	serverPubEl, err := getElementFromPublicKey(g, sPubKey)
	if err != nil {
		return nil, nil, err
	}

	clientPrivSc, err := getScalarFromPrivKey(g, cPrivKey)
	if err != nil {
		return nil, nil, err
	}
	//nolint:gocritic // not a commented code
	// dh1 = SerializeElement(state.client_secret * ke2.auth_response.server_keyshare)
	dh1 := g.NewElement().Add(serverKeyshareEl).Multiply(clientSecretSc).Encode()
	//nolint:gocritic // not a commented code
	// dh2 = SerializeElement(state.client_secret * server_public_key)
	dh2 := g.NewElement().Add(serverPubEl).Multiply(clientSecretSc).Encode()
	//nolint:gocritic // not a commented code
	// dh3 = SerializeElement(client_private_key  * ke2.auth_response.server_keyshare)
	dh3 := g.NewElement().Add(serverKeyshareEl).Multiply(clientPrivSc).Encode()
	//nolint:gocritic // not a commented code
	// ikm = concat(dh1, dh2, dh3)
	ikm := utils.Concat(dh1, dh2, dh3)

	prmbl, err := preamble(clientIdentity, state.KE1, serverIdentity, ke2.CredentialResponse, ke2.AuthResponse.ServerNonce, ke2.AuthResponse.ServerKeyshare, os.context)
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic // not a commented code
	// Km2, Km3, session_key = DeriveKeys(ikm, preamble)
	km2, km3, sessionKey, err := deriveKeys(os, ikm, prmbl)
	if err != nil {
		return nil, nil, err
	}

	//nolint:gocritic // not a commented code
	// expected_server_mac = MAC(Km2, Hash(preamble))
	H := os.Hash()

	err = H.MustWriteAll(prmbl)
	if err != nil {
		return nil, nil, err
	}

	expectedServerMAC, err := os.MAC(km2, H.Sum(nil))
	if err != nil {
		return nil, nil, err
	}

	// if !ct_equal(ke2.server_mac, expected_server_mac): raise ServerAuthenticationError
	if !hmac.Equal(ke2.AuthResponse.ServerMAC, expectedServerMAC) {
		return nil, nil, ErrServerAuthentication
	}

	// client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac))
	H.Reset()

	err = H.MustWriteAll(utils.Concat(prmbl, expectedServerMAC))
	if err != nil {
		return nil, nil, err
	}

	clientMAC, err := os.MAC(km3, H.Sum(nil))
	if err != nil {
		return nil, nil, err
	}

	ke3 := &KE3{
		ClientMAC: clientMAC,
	}

	return ke3, sessionKey, nil
}
