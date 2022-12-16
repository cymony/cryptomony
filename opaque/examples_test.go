// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/cymony/cryptomony/opaque"
)

func logFatalln(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func Example_registration() {
	// Must be initialize server on the server side.
	// Server's private and public keys should not be changed on every run.
	// Oprf seed must be client specific. So the application should have oprf seed per client.
	serverConf := opaque.ServerConfiguration{
		ServerID:         []byte("example.com"),    // Server Identifier. Must be same on client
		ServerPrivateKey: nil,                      // If private key is nil, generates a new key automatically
		OpaqueSuite:      opaque.Ristretto255Suite, // Suite with recommended setup. Must be same on client
	}

	server, err := opaque.NewServer(&serverConf)
	logFatalln(err)

	// Must be initialized client on the client side.
	clientConf := opaque.ClientConfiguration{
		ServerID:    []byte("example.com"),          // Server Identifier. Must be same on server
		OpaqueSuite: opaque.Ristretto255Suite.New(), // Suite with recommended setup. Must be same on server
	}

	client := opaque.NewClient(&clientConf)

	// chosenUserID is the email address for registration
	chosenUserID := []byte("anemail@domain.com")
	// chosenPassword is the password for registration
	chosenPassword := []byte("SuperSecretPass")

	// The client creates Registration Request with chosen password
	// regReq looks like this;
	// {
	// 	"BlindedMessage": "Encoded Blinded Password"
	// }
	// Client must be store blind and should not send to server.
	// Only regReq should be sent to the server
	clRegState, regReq, err := client.CreateRegistrationRequest(chosenPassword)
	logFatalln(err)
	encodedRegReq, err := regReq.Encode()
	logFatalln(err)

	// Then server received the Registration Request. Now it will generate Registration Response.
	// In this step, server generates credential identifier and oprf seed. It must be unique among clients of the server.
	// regRes looks like this;
	// {
	// 	"EvaluatedMessage": "Encoded Evaluted Message",
	// 	"ServerPublicKey": "Encoded Server Public Key"
	// }

	// Server must generate Nh size Oprf seed per client. And must be stored it only for that client.
	// To generate Nh size Oprf seed you can use GenerateOprfSeed function safely.
	oprfSeed := server.GenerateOprfSeed()
	credentialIdentifier := []byte("can_be_database_identifier_must_be_uniq_per_client")

	regRes, err := server.CreateRegistrationResponse(encodedRegReq, credentialIdentifier, oprfSeed)
	logFatalln(err)
	encodedRegRes, err := regRes.Encode()
	logFatalln(err)

	// Then client receives the regRes. Now it will generate record to be stored on server side.
	// If client identity is nil, the client public key will be used automatically. Usually, email address is used as client identity.
	// Only regRecord should send to the server.
	regRecord, regExportKey, err := client.FinalizeRegistrationRequest(clRegState, chosenUserID, encodedRegRes)
	logFatalln(err)
	// Registration Finished !!

	// Login Start
	// Firstly, Client executes ClientInit function with the password to generate KE1 Message.
	// Client should send only ke1 message to the server.
	clLoginState, ke1Message, err := client.ClientInit(chosenPassword)
	logFatalln(err)
	encodedKE1Message, err := ke1Message.Encode()
	logFatalln(err)

	// Server already know record, credential identifier, chosen user id and oprf seed generated on registration.
	encodedRecord, err := regRecord.Encode()
	logFatalln(err)

	// Now server executes ServerInit function with ke1 message. And generates KE2 Message.
	// Server should send only ke2 message to the client.
	svLoginState, ke2Message, err := server.ServerInit(encodedRecord, encodedKE1Message, credentialIdentifier, chosenUserID, oprfSeed)
	logFatalln(err)
	encodedKE2Message, err := ke2Message.Encode()
	logFatalln(err)

	// Than, client executes ClientFinish function to generate KE3 Message and to collect export key.
	ke3Message, clSessionKey, lgnExportKey, err := client.ClientFinish(clLoginState, chosenUserID, encodedKE2Message)
	logFatalln(err)
	encodedKE3Message, err := ke3Message.Encode()
	logFatalln(err)

	// Finally, server executes ServerFinish. If this function is not returns an error, than you can authenticate the client.
	svSessionKey, err := server.ServerFinish(svLoginState, encodedKE3Message)
	logFatalln(err)

	log.Println("ClientSessionKey: ", clSessionKey)
	log.Println("ServerSessionKey: ", svSessionKey)
	log.Println("Registration Export Key: ", regExportKey)
	log.Println("Login Export Key: ", lgnExportKey)

	if !bytes.Equal(clSessionKey, svSessionKey) {
		log.Fatalln("Collected session keys are different !!")
	}

	if !bytes.Equal(regExportKey, lgnExportKey) {
		log.Fatalln("Collected export keys are different !!")
	}

	fmt.Println("OPAQUE registration and login")
	// Output: OPAQUE registration and login
}
