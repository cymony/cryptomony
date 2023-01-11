// Copyright (c) 2023 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

import (
	"bytes"
	"testing"

	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/utils"
)

func getRandomClientRegistrationState(t *testing.T, suite Suite) *ClientRegistrationState {
	t.Helper()

	clState := &ClientRegistrationState{}
	clState.Blind = suite.Group().RandomScalar()
	clState.Password = utils.RandomBytes(10)

	return clState
}

func getRandomClientLoginState(t *testing.T, suite Suite) *ClientLoginState {
	t.Helper()

	clSecret, err := suite.GenerateAuthKeyPair()
	test.CheckNoErr(t, err, "GenerateAuthKeyPair err")

	state := &ClientLoginState{}

	state.Blind = suite.Group().RandomScalar()

	state.ClientSecret = clSecret

	ke1 := &KE1{}
	ke1.AuthRequest = &AuthRequest{}
	ke1.AuthRequest.ClientKeyshare = clSecret.Public()
	ke1.AuthRequest.ClientNonce = utils.RandomBytes(suite.Nn())

	ke1.CredentialRequest = &CredentialRequest{}
	ke1.CredentialRequest.BlindedMessage = suite.Group().RandomElement()

	state.KE1 = ke1

	state.Password = utils.RandomBytes(10)

	return state
}

type clStateInterface interface {
	Serialize() ([]byte, error)
	Deserialize(suite Suite, data []byte) error
	Encode() ([]byte, error)
	Decode(suite Suite, data []byte) error
}

func getRandomClientState(t *testing.T, suite Suite, stateType string) clStateInterface {
	t.Helper()

	switch stateType {
	case "Login":
		return getRandomClientLoginState(t, suite)
	case "Registration":
		return getRandomClientRegistrationState(t, suite)
	default:
		t.Error("unknown client state type")
	}

	return nil
}

func TestClientStatesEncodeDecode(t *testing.T) {
	suites := []Suite{Ristretto255Suite.New(), P256Suite.New()}
	stateTypes := []string{"Login", "Registration"}

	for _, suite := range suites {
		t.Run(suite.Group().String(), func(tt *testing.T) {
			for _, stateType := range stateTypes {
				state := getRandomClientState(t, suite, stateType)

				serializedState, err := state.Serialize()
				test.CheckNoErr(tt, err, "serialization error")

				newState := getRandomClientState(t, suite, stateType)

				err = newState.Deserialize(suite, serializedState)
				test.CheckNoErr(tt, err, "deserialization error")

				serializedNewState, err := newState.Serialize()
				test.CheckNoErr(tt, err, "serialization error")

				if !bytes.Equal(serializedState, serializedNewState) {
					test.Report(tt, serializedNewState, serializedState)
				}

				encodedState, err := state.Encode()
				test.CheckNoErr(tt, err, "encoding error")

				newState = getRandomClientState(t, suite, stateType)

				err = newState.Decode(suite, encodedState)
				test.CheckNoErr(tt, err, "decoding error")

				encodedNewState, err := newState.Encode()
				test.CheckNoErr(tt, err, "encoding error")

				if !bytes.Equal(encodedState, encodedNewState) {
					test.Report(tt, encodedNewState, encodedState)
				}
			}
		})
	}
}
