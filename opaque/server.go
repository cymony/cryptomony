// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

type Server interface {
	CreateRegistrationResponse(regReq []byte, credentialIdentifier, oprfSeed []byte) (*RegistrationResponse, error)
	ServerInit(clRecord []byte, ke1Message []byte, credentialIdentifier []byte, clientIdentity []byte, oprfSeed []byte) (*ServerLoginState, *KE2, error)
	ServerFinish(svLoginState *ServerLoginState, ke3Message []byte) ([]byte, error)
	GenerateOprfSeed() []byte
}

type ServerConfiguration struct {
	OpaqueSuite      Suite  // Chosen Opaque Suite
	ServerID         []byte // Server Identity. Usually, domain name
	ServerPrivateKey []byte // Serialized server private key value
}

type server struct {
	suite           Suite
	serverPrivKey   *PrivateKey
	serverPublicKey *PublicKey
	serverIdentity  []byte
}

func NewServer(conf *ServerConfiguration) (Server, error) {
	var serverPriv *PrivateKey

	if len(conf.ServerPrivateKey) == 0 {
		priv, err := conf.OpaqueSuite.GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		serverPriv = priv
	} else {
		if err := serverPriv.UnmarshalBinary(conf.OpaqueSuite, conf.ServerPrivateKey); err != nil {
			return nil, err
		}
	}

	serverPub := serverPriv.Public()

	return &server{
		serverIdentity:  conf.ServerID,
		serverPrivKey:   serverPriv,
		serverPublicKey: serverPub,
		suite:           conf.OpaqueSuite,
	}, nil
}

func (s *server) CreateRegistrationResponse(regReq, credentialIdentifier, oprfSeed []byte) (*RegistrationResponse, error) {
	decodedRegReq := &RegistrationRequest{}
	if err := decodedRegReq.Decode(s.suite, regReq); err != nil {
		return nil, err
	}

	return s.suite.CreateRegistrationResponse(decodedRegReq, s.serverPublicKey, credentialIdentifier, oprfSeed)
}

func (s *server) ServerInit(clRecord, ke1Message, credentialIdentifier, clientIdentity, oprfSeed []byte) (*ServerLoginState, *KE2, error) {
	decodedRecord := &RegistrationRecord{}
	if err := decodedRecord.Decode(s.suite, clRecord); err != nil {
		return nil, nil, err
	}

	decodedKE1 := &KE1{}
	if err := decodedKE1.Decode(s.suite, ke1Message); err != nil {
		return nil, nil, err
	}

	return s.suite.ServerInit(s.serverPrivKey, s.serverPublicKey, decodedRecord, decodedKE1, credentialIdentifier, clientIdentity, s.serverIdentity, oprfSeed)
}

func (s *server) ServerFinish(svLoginState *ServerLoginState, ke3Message []byte) ([]byte, error) {
	decodedKE3 := &KE3{}
	if err := decodedKE3.Decode(s.suite, ke3Message); err != nil {
		return nil, err
	}

	return s.suite.ServerFinish(svLoginState, decodedKE3)
}

func (s *server) GenerateOprfSeed() []byte {
	return s.suite.GenerateOprfSeed()
}
