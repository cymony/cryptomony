// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

type Client interface {
	CreateRegistrationRequest(password []byte) (clRegState *ClientRegistrationState, regReq *RegistrationRequest, err error)
	FinalizeRegistrationRequest(clRegState *ClientRegistrationState, clientIdentity, regRes []byte) (regRec *RegistrationRecord, exportKey []byte, err error)

	ClientInit(password []byte) (clLoginState *ClientLoginState, ke1Message *KE1, err error)
	ClientFinish(clLoginState *ClientLoginState, clientIdentity []byte, ke2 []byte) (ke3Message *KE3, sessionKey []byte, exportKey []byte, err error)
}

type ClientConfiguration struct {
	OpaqueSuite Suite  // Chosen Opaque Suite
	ServerID    []byte // Server Identity. Usually, domain name
}

type client struct {
	suite          Suite
	serverIdentity []byte
}

func NewClient(conf *ClientConfiguration) Client {
	return &client{
		serverIdentity: conf.ServerID,
		suite:          conf.OpaqueSuite,
	}
}

func (c *client) CreateRegistrationRequest(password []byte) (*ClientRegistrationState, *RegistrationRequest, error) {
	regReq, blind, err := c.suite.CreateRegistrationRequest(password)
	if err != nil {
		return nil, nil, err
	}

	return &ClientRegistrationState{
		Blind:    blind,
		Password: password,
	}, regReq, nil
}

func (c *client) FinalizeRegistrationRequest(clRegState *ClientRegistrationState, clientIdentity, regRes []byte) (*RegistrationRecord, []byte, error) {
	decodedRegRes := &RegistrationResponse{}
	if err := decodedRegRes.Decode(c.suite, regRes); err != nil {
		return nil, nil, err
	}

	regRec, exportKey, err := c.suite.FinalizeRegistrationRequest(clRegState.Password, c.serverIdentity, clientIdentity, clRegState.Blind, decodedRegRes)
	if err != nil {
		return nil, nil, err
	}

	return regRec, exportKey, nil
}

func (c *client) ClientInit(password []byte) (*ClientLoginState, *KE1, error) {
	return c.suite.ClientInit(password)
}

func (c *client) ClientFinish(clLoginState *ClientLoginState, clientIdentity, ke2 []byte) (ke3 *KE3, sessionKey, exportKey []byte, err error) {
	decodedKE2 := &KE2{}
	if err := decodedKE2.Decode(c.suite, ke2); err != nil {
		return nil, nil, nil, err
	}

	return c.suite.ClientFinish(clLoginState, clientIdentity, c.serverIdentity, decodedKE2)
}
