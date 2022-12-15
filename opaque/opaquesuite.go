// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package opaque implements OPAQUE, an asymmetric password-authenticated key exchange protocol
// that is secure against pre-computation attacks.
// It enables a client to authenticate to a server without ever revealing its password to the
// server.
// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html
package opaque

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/ksf"
	"github.com/cymony/cryptomony/oprf"
)

// Identifier is the type constant for supported suites
type Identifier uint

const (
	// Ristretto255Suite is the identifier for recommended opaque suite -> OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512, Scrypt(32768,8,1), internal, ristretto255
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-configurations
	Ristretto255Suite Identifier = 1 + iota
	// P256Suite is the identifier for recommended opaque suite -> OPRF(P-256, SHA-256), HKDF-SHA-256, HMAC-SHA-256, SHA-256, Scrypt(32768,8,1), internal, P-256
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-configurations
	P256Suite
)

// New initialize new suite instance and returns it.
func (i Identifier) New() Suite {
	switch i {
	case Ristretto255Suite:
		return &opaqueSuite{oprf: oprf.SuiteRistretto255Sha512, group: eccgroup.Ristretto255Sha512, ksf: ksf.Scrypt, kdf: hash.SHA512, mac: hash.SHA512, hsh: hash.SHA512, context: []byte(libContext)}
	case P256Suite:
		return &opaqueSuite{oprf: oprf.SuiteP256Sha256, group: eccgroup.P256Sha256, ksf: ksf.Scrypt, kdf: hash.SHA256, mac: hash.SHA256, hsh: hash.SHA256, context: []byte(libContext)}
	default:
		panic("unsupported suite")
	}
}

// Suite interface identifies the opaque protocol and required functions
type Suite interface {
	// OPRF function returns the oprf suite used by opaque suite.
	OPRF() oprf.Suite
	// Group function returns the prime-order group used by opaque suite.
	Group() eccgroup.Group
	// Hash	function returns the hash interface used by opaque suite.
	Hash() hash.Hash
	// Expand function executes HKDF Expand according to opaque suite's hash algorithm.
	Expand(pseudorandomKey []byte, info []byte, length int) []byte
	// Extract function executes HKDF Extract according to opaque suite's hash algorithm.
	Extract(salt, secret []byte) []byte
	// MAC function executes Hmac according to opaque suite's hash algorithm.
	MAC(key, message []byte) ([]byte, error)
	// Stretch function performs key stretching according to opaque suite's ksf algorithm.
	Stretch(password []byte, length int) ([]byte, error)
	// Store implements opaque protocol's Envelope Creation step.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-envelope-creation.
	Store(randomizedPwd []byte, sPubKey *PublicKey, serverIdentity, clientIdentity []byte) (*Envelope, *PublicKey, []byte, []byte, error)
	// Recover implements opaque protocol's Envelope Recovery step.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-envelope-recovery.
	Recover(randomizedPwd []byte, sPubKey *PublicKey, envelope *Envelope, serverIdentity, clientIdentity []byte) (*PrivateKey, []byte, error)
	// GenerateOPRFSeed generates random Nh bytes to use as oprf seed.
	GenerateOprfSeed() []byte

	// Registration Functions
	//
	// CreateRegistrationRequest computes blinded message and returns (RegistrationRequest, blind).
	// Returned blind is client private value to be use in FinalizeRegistrationRequest and it must not send to server.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-createregistrationrequest
	CreateRegistrationRequest(password []byte) (*RegistrationRequest, *eccgroup.Scalar, error)
	// CreateRegistrationResponse evaluates the RegistrationRequest and returns RegistrationResponse
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-createregistrationresponse
	CreateRegistrationResponse(regReq *RegistrationRequest, serverPubKey *PublicKey, credentialIdentifier, oprfSeed []byte) (*RegistrationResponse, error)
	// FinalizeRegistrationRequest generates RegistrationRecord to store on server side.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-finalizeregistrationrequest
	FinalizeRegistrationRequest(password, serverIdentity, clientIdentity []byte, blind *eccgroup.Scalar, regRes *RegistrationResponse) (*RegistrationRecord, []byte, error)

	// AKE Functions
	//
	// ClientInit function begins the AKE protocol and produces the client's KE1 output for the server.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-clientinit
	ClientInit(password []byte) (*ClientLoginState, *KE1, error)
	// ServerInit function continues the AKE protocol by processing the client's KE1 message and producing the server's KE2 output.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-serverinit
	ServerInit(serverPrivKey *PrivateKey, serverPubKey *PublicKey, record *RegistrationRecord, ke1 *KE1, credIdentifier, clientIdentity, serverIdentity, oprfSeed []byte) (*ServerLoginState, *KE2, error)
	// The ClientFinish function completes the AKE protocol for the client and produces the client's KE3 output for the server, as well as the session_key and export_key outputs from the AKE.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-clientfinish
	ClientFinish(state *ClientLoginState, clientIdentity, serverIdentity []byte, ke2 *KE2) (*KE3, []byte, []byte, error)
	// The ServerFinish function completes the AKE protocol for the server, yielding the session_key.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-serverfinish
	ServerFinish(state *ServerLoginState, ke3 *KE3) ([]byte, error)

	// Credential Retrieval Functions
	//
	// The CreateCredentialRequest is used by the client to initiate the credential retrieval process, and it produces a CredentialRequest message and OPRF state.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-createcredentialrequest.
	CreateCredentialRequest(password []byte, chosenBlind *eccgroup.Scalar) (*CredentialRequest, *eccgroup.Scalar, error)
	// The CreateCredentialResponse function is used by the server to process the client's CredentialRequest message and complete the credential retrieval process, producing a CredentialResponse.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-createcredentialresponse.
	CreateCredentialResponse(credReq *CredentialRequest, serverPubKey *PublicKey, record *RegistrationRecord, credIdentifier, oprfSeed, maskingNonce []byte) (*CredentialResponse, error)
	// The RecoverCredentials function is used by the client to process the server's CredentialResponse message and produce the client's private key, server public key, and the export_key.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-recovercredentials.
	RecoverCredentials(password []byte, blind *eccgroup.Scalar, credRes *CredentialResponse, serverIdentity, clientIdentity []byte) (*PrivateKey, *PublicKey, []byte, error)

	// Key Creation Functions
	//
	// DeriveKeyPair wraps the DeriveKeyPair functionality of the OPRF suite used by opaque suite.
	DeriveKeyPair(seed []byte) (*PrivateKey, error)
	// GenerateKeyPair wraps the GenerateKeyPair functionality of the OPRF suite used by opaque suite.
	GenerateKeyPair() (*PrivateKey, error)
	// DeriveAuthKeyPair implements the steps found at https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-key-creation.
	DeriveAuthKeyPair(seed []byte) (*PrivateKey, error)
	// GenerateAuthKeyPair implements the steps found at https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-key-creation.
	GenerateAuthKeyPair() (*PrivateKey, error)

	// AKE 3DH Functions
	//
	// The function AuthClientStart implements OPAQUE-3DH AuthClientStart function.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-3dh-client-functions.
	// Unlike draft implementation, this function returns client state instead of managing it internally.
	AuthClientStart(credentialReq *CredentialRequest, clientNonce []byte, clientSecret *PrivateKey) (*ClientLoginState, *KE1, error)
	// The function AuthClientFinalize implements OPAQUE-3DH AuthClientFinalize function.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-3dh-client-functions.
	AuthClientFinalize(state *ClientLoginState, clientIdentity, serverIdentity []byte, cPrivKey *PrivateKey, sPubKey *PublicKey, ke2 *KE2) (*KE3, []byte, error)
	// The function AuthServerRespond implements OPAQUE-3DH AuthServerRespond function.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-3dh-server-functions.
	// Unlike draft implementation, this function returns server state instead of managing it internally.
	AuthServerRespond(serverPrivKey *PrivateKey, serverIdentity, clientIdentity, serverNonce []byte, clientPubKey *PublicKey, ke1 *KE1, credentialRes *CredentialResponse, serverPrivateKeyshare *PrivateKey) (*ServerLoginState, *AuthResponse, error)
	// The function AuthServerFinalize implements OPAQUE-3DH AuthServerFinalize function.
	// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-3dh-server-functions.
	AuthServerFinalize(state *ServerLoginState, ke3 *KE3) ([]byte, error)

	// Dynamic Length Functions
	//
	// Output length of the Hash function used by opaque suite. (in byte)
	Nh() int
	// Output length of the public key generated by GenerateAuthKeyPair or DeriveAuthKeyPair functions. (in byte)
	Npk() int
	// Output length of the private key generated by GenerateAuthKeyPair or DeriveAuthKeyPair functions. (in byte)
	Nsk() int
	// Output length of MAC function. (in byte)
	Nm() int
	// Output length of Extract function. (in byte)
	Nx() int
	// Output length of serialized group element of the OPRF suite used by opaque suite.
	// In other words, output length of the public key generated by GenerateKeyPair or DeriveKeyPair functions. (in byte)
	Noe() int
	// Output length of serialized group scalar of the OPRF suite used by opaque suite.
	// In other words, output length of the private key generated by GenerateKeyPair or DeriveKeyPair functions. (in byte)
	Nok() int
	// Nonce length used in opaque protocol. (in byte)
	Nn() int
	// Seed length used in opaque protocol. (in byte)
	Nseed() int
	// Length of Envelope struct. (in byte)
	Ne() int
}

type opaqueSuite struct {
	oprf    oprf.Suite
	context []byte
	group   eccgroup.Group
	ksf     ksf.Identifier
	kdf     hash.Hashing
	mac     hash.Hashing
	hsh     hash.Hashing
}

func (os *opaqueSuite) OPRF() oprf.Suite {
	return os.oprf
}

func (os *opaqueSuite) Group() eccgroup.Group {
	return os.group
}

func (os *opaqueSuite) Hash() hash.Hash {
	return os.hsh.New()
}

func (os *opaqueSuite) Expand(pseudorandomKey, info []byte, length int) []byte {
	return os.kdf.New().HKDFExpand(pseudorandomKey, info, length)
}

func (os *opaqueSuite) Extract(salt, secret []byte) []byte {
	return os.kdf.New().HKDFExtract(secret, salt)
}

func (os *opaqueSuite) MAC(key, message []byte) ([]byte, error) {
	return os.mac.New().Hmac(message, key)
}

func (os *opaqueSuite) Stretch(password []byte, length int) ([]byte, error) {
	return os.ksf.New().Harden(password, nil, length)
}

func (os *opaqueSuite) Nh() int {
	return os.hsh.New().OutputSize()
}

func (os *opaqueSuite) Npk() int {
	return int(os.oprf.Group().ElementLength())
}

func (os *opaqueSuite) Nsk() int {
	return int(os.oprf.Group().ScalarLength())
}

func (os *opaqueSuite) Nm() int {
	return os.mac.CryptoID().Size()
}

func (os *opaqueSuite) Nx() int {
	return os.kdf.CryptoID().Size()
}

func (os *opaqueSuite) Noe() int {
	return int(os.oprf.Group().ElementLength())
}

func (os *opaqueSuite) Nok() int {
	return int(os.oprf.Group().ScalarLength())
}

func (os *opaqueSuite) Nn() int {
	return 32
}

func (os *opaqueSuite) Nseed() int {
	return 32
}

func (os *opaqueSuite) Ne() int {
	return os.Nn() + os.Nm()
}
