// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

//nolint:govet //test
package opaque

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/ksf"
	"github.com/cymony/cryptomony/oprf"
	"github.com/cymony/cryptomony/utils"
)

type HexByte []byte

func (j HexByte) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(j))
}

func (j *HexByte) UnmarshalJSON(data []byte) error {
	bs := strings.Trim(string(data), "\"")

	dst, err := hex.DecodeString(bs)
	if err != nil {
		return err
	}

	*j = dst

	return nil
}

type config struct {
	Context HexByte `json:"Context"`
	Fake    string  `json:"Fake"`
	Group   string  `json:"Group"`
	Hash    string  `json:"Hash"`
	KDF     string  `json:"KDF"`
	KSF     string  `json:"KSF"`
	MAC     string  `json:"MAC"`
	Name    string  `json:"Name"`
	Nh      int     `json:"Nh,string"`
	Nm      int     `json:"Nm,string"`
	Nok     int     `json:"Nok,string"`
	Npk     int     `json:"Npk,string"`
	Nsk     int     `json:"Nsk,string"`
	Nx      int     `json:"Nx,string"`
	OPRF    HexByte `json:"OPRF"`
}

type inputs struct {
	ServerIdentity        HexByte `json:"server_identity,omitempty"`
	ClientIdentity        HexByte `json:"client_identity,omitempty"`
	BlindLogin            HexByte `json:"blind_login"`
	BlindRegistration     HexByte `json:"blind_registration"`
	ClientKeyshare        HexByte `json:"client_keyshare"`
	ClientNonce           HexByte `json:"client_nonce"`
	ClientPrivateKeyshare HexByte `json:"client_private_keyshare"`
	CredentialIdentifier  HexByte `json:"credential_identifier"`
	EnvelopeNonce         HexByte `json:"envelope_nonce"`
	MaskingNonce          HexByte `json:"masking_nonce"`
	OprfSeed              HexByte `json:"oprf_seed"`
	Password              HexByte `json:"password"`
	ServerKeyshare        HexByte `json:"server_keyshare"`
	ServerNonce           HexByte `json:"server_nonce"`
	ServerPrivateKey      HexByte `json:"server_private_key"`
	ServerPrivateKeyshare HexByte `json:"server_private_keyshare"`
	ServerPublicKey       HexByte `json:"server_public_key"`
	KE1                   HexByte `json:"KE1,omitempty"`
	ClientPublicKey       HexByte `json:"client_public_key,omitempty"`
	MaskingKey            HexByte `json:"masking_key,omitempty"`
}

type intermediates struct {
	AuthKey         HexByte `json:"auth_key"`
	ClientMacKey    HexByte `json:"client_mac_key"`
	ClientPublicKey HexByte `json:"client_public_key"`
	Envelope        HexByte `json:"envelope"`
	HandshakeSecret HexByte `json:"handshake_secret"`
	MaskingKey      HexByte `json:"masking_key"`
	OPRFKey         HexByte `json:"oprf_key"`
	RandomPWD       HexByte `json:"randomized_pwd"`
	ServerMacKey    HexByte `json:"server_mac_key"`
}

type outputs struct {
	KE1                  HexByte `json:"KE1"`
	KE2                  HexByte `json:"KE2"`
	KE3                  HexByte `json:"KE3"`
	ExportKey            HexByte `json:"export_key"`
	RegistrationRequest  HexByte `json:"registration_request"`
	RegistrationResponse HexByte `json:"registration_response"`
	RegistrationRecord   HexByte `json:"registration_upload"`
	SessionKey           HexByte `json:"session_key"`
}

type vector struct {
	Config        config        `json:"config"`
	Inputs        inputs        `json:"inputs"`
	Intermediates intermediates `json:"intermediates"`
	Outputs       outputs       `json:"outputs"`
}

func (v *vector) execTest(t *testing.T) {
	oSuite := makeOpaqueSuite(t, &v.Config)

	// Check lengths true
	if v.Config.Nh != oSuite.Nh() {
		test.Report(t, oSuite.Nh(), v.Config.Nh)
	}

	if v.Config.Nm != oSuite.Nm() {
		test.Report(t, oSuite.Nm(), v.Config.Nm)
	}

	if v.Config.Nok != oSuite.Nok() {
		test.Report(t, oSuite.Nok(), v.Config.Nok)
	}

	if v.Config.Npk != oSuite.Npk() {
		test.Report(t, oSuite.Npk(), v.Config.Npk)
	}

	if v.Config.Nsk != oSuite.Nsk() {
		test.Report(t, oSuite.Nsk(), v.Config.Nsk)
	}

	if v.Config.Nx != oSuite.Nx() {
		test.Report(t, oSuite.Nx(), v.Config.Nx)
	}

	suite, ok := oSuite.(*opaqueSuite)
	test.CheckOk(t, ok, "opaque suite type conversion")

	if !bytes.Equal(v.Config.Context, suite.context) {
		test.Report(t, suite.context, v.Config.Context, "contexts not equal")
	}

	if !isFake(t, v.Config.Fake) {
		// Do Registration
		v.testRegistration(t, oSuite)
	}

	// Do Login
	v.testLogin(t, oSuite)
}

func getFakeEnvelope(oSuite Suite) []byte {
	return make([]byte, oSuite.Ne())
}

func (v *vector) testLogin(t *testing.T, oSuite Suite) {
	t.Helper()

	suite, ok := oSuite.(*opaqueSuite)
	test.CheckOk(t, ok, "opaque suite type conversion")

	var clLoginState *ClientLoginState

	KE1Message := &KE1{}

	if !isFake(t, v.Config.Fake) {
		blindLogin := suite.OPRF().Group().NewScalar()

		err := blindLogin.Decode(v.Inputs.BlindLogin)
		test.CheckNoErr(t, err, "login blind decode err")

		clientPrivateKeyshare := &PrivateKey{}

		err = clientPrivateKeyshare.UnmarshalBinary(suite, v.Inputs.ClientPrivateKeyshare)
		test.CheckNoErr(t, err, "client private keyshare decode err")

		clLoginState, KE1Message, err = suite.clientInit(v.Inputs.Password, v.Inputs.ClientNonce, blindLogin, clientPrivateKeyshare)
		test.CheckNoErr(t, err, "client init err")

		marshaledClientKeyshare, err := KE1Message.AuthRequest.ClientKeyshare.MarshalBinary()
		test.CheckNoErr(t, err, "client keyshare marshal err")

		if !bytes.Equal(v.Inputs.ClientKeyshare, marshaledClientKeyshare) {
			test.Report(t, marshaledClientKeyshare, v.Inputs.ClientKeyshare, "client keyshares not equal")
		}

		serializedKE1, err := KE1Message.Serialize()
		test.CheckNoErr(t, err, "ke1 serialization err")

		if !bytes.Equal(v.Outputs.KE1, serializedKE1) {
			test.Report(t, serializedKE1, v.Outputs.KE1, "ke1 messages not equal")
		}
	} else {
		err := KE1Message.Deserialize(suite, v.Inputs.KE1)
		test.CheckNoErr(t, err, "KE1 message deserialization err")
	}

	record := &RegistrationRecord{}
	if !isFake(t, v.Config.Fake) {
		err := record.deserialize(suite, v.Outputs.RegistrationRecord)
		test.CheckNoErr(t, err, "registration record deserialization err")
	} else {
		fakeEnvelope := getFakeEnvelope(oSuite)
		fakeRecord := utils.Concat(v.Inputs.ClientPublicKey, v.Inputs.MaskingKey, fakeEnvelope)
		err := record.deserialize(suite, fakeRecord)
		test.CheckNoErr(t, err, "fake record deserialization err")
	}

	serverPrivKey := &PrivateKey{}

	err := serverPrivKey.UnmarshalBinary(suite, v.Inputs.ServerPrivateKey)
	test.CheckNoErr(t, err, "server priv key deserialization")

	serverPubKey := serverPrivKey.Public()

	serializedServerPubKey, err := serverPubKey.MarshalBinary()
	test.CheckNoErr(t, err, "server pubkey marshal err")

	if !bytes.Equal(v.Inputs.ServerPublicKey, serializedServerPubKey) {
		test.Report(t, serializedServerPubKey, v.Inputs.ServerPublicKey, "server public keys not equal")
	}

	serverPrivateKeyshare := &PrivateKey{}

	err = serverPrivateKeyshare.UnmarshalBinary(suite, v.Inputs.ServerPrivateKeyshare)
	test.CheckNoErr(t, err, "server private keyshare unmarshal err")

	svLoginState, KE2Message, err := suite.serverInit(serverPrivKey,
		serverPubKey,
		record,
		KE1Message,
		v.Inputs.CredentialIdentifier,
		v.Inputs.ClientIdentity,
		v.Inputs.ServerIdentity,
		v.Inputs.OprfSeed,
		v.Inputs.MaskingNonce,
		v.Inputs.ServerNonce,
		serverPrivateKeyshare,
	)

	KE2Vector := &KE2{}

	err = KE2Vector.Deserialize(suite, v.Outputs.KE2)
	test.CheckNoErr(t, err, "KE2 vector deserialization err")

	marshaledServerKeyshare, err := KE2Message.AuthResponse.ServerKeyshare.MarshalBinary()
	test.CheckNoErr(t, err, "server keyshare marshal err")

	if !bytes.Equal(v.Inputs.ServerKeyshare, marshaledServerKeyshare) {
		test.Report(t, marshaledServerKeyshare, v.Inputs.ServerKeyshare, "server keyshares not equal")
	}

	if !bytes.Equal(KE2Vector.CredentialResponse.EvaluatedMessage.Encode(), KE2Message.CredentialResponse.EvaluatedMessage.Encode()) {
		test.Report(t, KE2Message.CredentialResponse.EvaluatedMessage.Encode(), KE2Vector.CredentialResponse.EvaluatedMessage.Encode(), "KE2.CredentialResponse.EvaluatedMessage not equal")
	}

	if !bytes.Equal(KE2Vector.CredentialResponse.MaskingNonce, KE2Message.CredentialResponse.MaskingNonce) {
		test.Report(t, KE2Message.CredentialResponse.MaskingNonce, KE2Vector.CredentialResponse.MaskingNonce, "KE2.CredentialResponse.MaskingNonce not equal")
	}

	if !bytes.Equal(KE2Vector.CredentialResponse.MaskedResponse, KE2Message.CredentialResponse.MaskedResponse) {
		test.Report(t, KE2Message.CredentialResponse.MaskedResponse, KE2Vector.CredentialResponse.MaskedResponse, "KE2.CredentialResponse.MaskedResponse not equal")
	}

	if !bytes.Equal(KE2Vector.AuthResponse.ServerNonce, KE2Message.AuthResponse.ServerNonce) {
		test.Report(t, KE2Message.AuthResponse.ServerNonce, KE2Vector.AuthResponse.ServerNonce, "KE2.AuthResponse.ServerNonce not equal")
	}

	if !bytes.Equal(KE2Vector.AuthResponse.ServerMAC, KE2Message.AuthResponse.ServerMAC) {
		test.Report(t, KE2Message.AuthResponse.ServerMAC, KE2Vector.AuthResponse.ServerMAC, "KE2.AuthResponse.ServerMAC not equal")
	}

	serializedKE2, err := KE2Message.Serialize()
	test.CheckNoErr(t, err, "ke2 messages serialization err")

	if !bytes.Equal(v.Outputs.KE2, serializedKE2) {
		test.Report(t, serializedKE2, v.Outputs.KE2, "ke2 messages not equal")
	}

	if !isFake(t, v.Config.Fake) && !bytes.Equal(v.Outputs.SessionKey, svLoginState.SessionKey) {
		test.Report(t, svLoginState.SessionKey, v.Outputs.SessionKey, "session keys not equal")
	}

	if isFake(t, v.Config.Fake) {
		return
	}

	KE3Message, clSessionKey, exportKey, err := suite.ClientFinish(clLoginState, v.Inputs.ClientIdentity, v.Inputs.ServerIdentity, KE2Message)
	test.CheckNoErr(t, err, "client finish err")

	if !bytes.Equal(v.Outputs.ExportKey, exportKey) {
		test.Report(t, exportKey, v.Outputs.ExportKey, "export keys not equal")
	}

	if !bytes.Equal(v.Outputs.SessionKey, clSessionKey) {
		test.Report(t, clSessionKey, v.Outputs.SessionKey, "client session keys not equal")
	}

	serializedKE3, err := KE3Message.Serialize()
	test.CheckNoErr(t, err, "ke3 message serialization err")

	if !bytes.Equal(v.Outputs.KE3, serializedKE3) {
		test.Report(t, serializedKE3, v.Outputs.KE3, "ke3 messages not equal")
	}

	svSessionKey, err := suite.ServerFinish(svLoginState, KE3Message)
	test.CheckNoErr(t, err, "server finish err")

	if !bytes.Equal(v.Outputs.SessionKey, svSessionKey) {
		test.Report(t, svSessionKey, v.Outputs.SessionKey, "server session keys not equal")
	}
}

func (v *vector) testRegistration(t *testing.T, oSuite Suite) {
	t.Helper()

	suite, ok := oSuite.(*opaqueSuite)
	test.CheckOk(t, ok, "opaque suite type conversion")

	regBlind := suite.Group().NewScalar()

	err := regBlind.Decode(v.Inputs.BlindRegistration)
	test.CheckNoErr(t, err, "registration blind decode err")

	regReq, _, err := suite.createRegistrationRequest(v.Inputs.Password, regBlind)
	test.CheckNoErr(t, err, "create registration req err")

	serializedRegReq, err := regReq.serialize()
	test.CheckNoErr(t, err, "registration req serialization err")

	if !bytes.Equal(v.Outputs.RegistrationRequest, serializedRegReq) {
		test.Report(t, serializedRegReq, v.Outputs.RegistrationRequest, "create registration request outputs not equal")
	}

	sPubKey := &PublicKey{}
	err = sPubKey.UnmarshalBinary(suite, v.Inputs.ServerPublicKey)
	test.CheckNoErr(t, err, "server public key unmarshaling err")

	regRes, err := suite.CreateRegistrationResponse(regReq, sPubKey, v.Inputs.CredentialIdentifier, v.Inputs.OprfSeed)
	test.CheckNoErr(t, err, "create registration res err")

	serializedRegRes, err := regRes.serialize()
	test.CheckNoErr(t, err, "registration res serialization err")

	if !bytes.Equal(v.Outputs.RegistrationResponse, serializedRegRes) {
		test.Report(t, serializedRegRes, v.Outputs.RegistrationResponse, "create registration response outputs not equal")
	}

	regRecord, exportKey, err := suite.finalizeRegistrationRequest(v.Inputs.Password, v.Inputs.ServerIdentity, v.Inputs.ClientIdentity, regBlind, regRes, v.Inputs.EnvelopeNonce)
	test.CheckNoErr(t, err, "finalize registration request err")

	if !bytes.Equal(v.Outputs.ExportKey, exportKey) {
		test.Report(t, exportKey, v.Outputs.ExportKey, "finalize registration export keys not equal")
	}

	serializedEnvelope, err := regRecord.Envelope.Serialize()
	test.CheckNoErr(t, err, "envelope serialization err")

	if !bytes.Equal(v.Intermediates.Envelope, serializedEnvelope) {
		test.Report(t, serializedEnvelope, v.Intermediates.Envelope, "finalize registration envelopes not equal")
	}

	serializedRegRecord, err := regRecord.serialize()
	test.CheckNoErr(t, err, "registration record serialization err")

	if !bytes.Equal(v.Outputs.RegistrationRecord, serializedRegRecord) {
		test.Report(t, serializedRegRecord, v.Outputs.RegistrationRecord, "registration records not equal")
	}
}

func isFake(t *testing.T, f string) bool {
	t.Helper()

	switch f {
	case "True":
		return true
	case "False":
		return false
	default:
		t.Fatalf("Unrecognized fake string: %s", f)
	}

	panic("wrong fake string")
}

func makeOpaqueSuite(t *testing.T, c *config) Suite {
	t.Helper()

	oprfSuite := getOPRFSuite(t, c.OPRF)
	suiteKDF := getKDF(t, c.KDF)
	suiteKSF := getKSF(t, c.KSF)
	suiteMAC := getMAC(t, c.MAC)
	suiteHash := getHash(t, c.Hash)
	suiteGroup := getGroup(t, c.Group)

	s := opaqueSuite{oprf: oprfSuite, kdf: suiteKDF, ksf: suiteKSF, mac: suiteMAC, group: suiteGroup, hsh: suiteHash, context: c.Context}

	return &s
}

func getGroup(t *testing.T, g string) eccgroup.Group {
	t.Helper()

	switch g {
	case "ristretto255":
		return eccgroup.Ristretto255Sha512
	case "P256_XMD:SHA-256_SSWU_RO_":
		return eccgroup.P256Sha256
	default:
		t.Fatalf("Unrecognized group string: %s", g)
	}

	return 0
}

func getOPRFSuite(t *testing.T, id []byte) oprf.Suite {
	t.Helper()

	switch {
	case bytes.Equal(id, []byte{0, 1}):
		return oprf.SuiteRistretto255Sha512
	case bytes.Equal(id, []byte{0, 3}):
		return oprf.SuiteP256Sha256
	default:
		t.Fatalf("Unrecognized oprf bytes: %v", id)
	}

	return nil
}

func getKDF(t *testing.T, k string) hash.Hashing {
	t.Helper()

	switch k {
	case "HKDF-SHA256":
		return hash.SHA256
	case "HKDF-SHA512":
		return hash.SHA512
	default:
		t.Fatalf("Unrecognized kdf string: %s", k)
	}

	return 0
}

func getKSF(t *testing.T, k string) ksf.Identifier {
	t.Helper()

	switch k {
	case "Identity":
		return ksf.Identity
	case "Scrypt":
		return ksf.Scrypt
	default:
		t.Fatalf("Unrecognized ksf string: %s", k)
	}

	return 0
}

func getMAC(t *testing.T, m string) hash.Hashing {
	t.Helper()

	switch m {
	case "HMAC-SHA256":
		return hash.SHA256
	case "HMAC-SHA512":
		return hash.SHA512
	default:
		t.Fatalf("Uncognized mac string: %s", m)
	}

	return 0
}

func getHash(t *testing.T, h string) hash.Hashing {
	t.Helper()

	switch h {
	case "SHA256":
		return hash.SHA256
	case "SHA512":
		return hash.SHA512
	default:
		t.Fatalf("Unrecognized hash strign: %s", h)
	}

	return 0
}

type vectors []*vector

func getVectors(t *testing.T, path string) vectors {
	t.Helper()

	data, err := os.ReadFile(path)
	test.CheckNoErr(t, err, "read file err")

	var vs vectors
	err = json.Unmarshal(data, &vs)
	test.CheckNoErr(t, err, "json unmarshal err")

	return vs
}

func TestVectors(t *testing.T) {
	fPath := "testdata/vectors.json"
	vs := getVectors(t, fPath)

	for i, v := range vs {
		t.Run(fmt.Sprintf("%s/%s/Fake:%s#%d", v.Config.Name, v.Config.Group, v.Config.Fake, i), v.execTest)
	}
}
