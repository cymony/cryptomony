// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

// Server interface represents the server instance.
type Server interface {
	// CreateRegistrationResponse evaluates the RegistrationRequest and returns RegistrationResponse
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-createregistrationresponse
	CreateRegistrationResponse(regReq []byte, credentialIdentifier, oprfSeed []byte) (*RegistrationResponse, error)
	// ServerInit function continues the AKE protocol by processing the client's KE1 message and producing the server's KE2 output.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-serverinit
	ServerInit(clRecord []byte, ke1Message []byte, credentialIdentifier []byte, clientIdentity []byte, oprfSeed []byte) (*ServerLoginState, *KE2, error)
	// The ServerFinish function completes the AKE protocol for the server, yielding the session_key.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-serverfinish
	ServerFinish(svLoginState *ServerLoginState, ke3Message []byte) ([]byte, error)
	// GenerateOprfSeed generates randomly secure oprf seed with suitable length
	GenerateOprfSeed() []byte
}

// ServerConfiguration contains configurations to initialize server instance
type ServerConfiguration struct {
	ServerID         []byte     // Server Identity. Usually, domain name
	ServerPrivateKey []byte     // Serialized server private key value
	OpaqueSuite      Identifier // Chosen Opaque Suite
}

type server struct {
	suite           Suite
	serverPrivKey   *PrivateKey
	serverPublicKey *PublicKey
	serverIdentity  []byte
}

// NewServer initializes the server instance according to configuration
func NewServer(conf *ServerConfiguration) (Server, error) {
	var serverPriv *PrivateKey

	suite := conf.OpaqueSuite.New()

	if len(conf.ServerPrivateKey) == 0 {
		priv, err := suite.GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		serverPriv = priv
	} else {
		if err := serverPriv.UnmarshalBinary(suite, conf.ServerPrivateKey); err != nil {
			return nil, err
		}
	}

	serverPub := serverPriv.Public()

	return &server{
		serverIdentity:  conf.ServerID,
		serverPrivKey:   serverPriv,
		serverPublicKey: serverPub,
		suite:           suite,
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
