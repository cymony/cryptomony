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

func getRandomServerLoginState(t *testing.T, suite Suite) *ServerLoginState {
	t.Helper()

	sls := &ServerLoginState{}
	sls.ExpectedClientMac = utils.RandomBytes(suite.Nm())

	dh1 := suite.Group().RandomElement().Encode()
	dh2 := suite.Group().RandomElement().Encode()
	dh3 := suite.Group().RandomElement().Encode()

	ikm := utils.Concat(dh1, dh2, dh3)

	_, _, sessionKey, err := deriveKeys(suite, ikm, utils.RandomBytes(100))
	test.CheckNoErr(t, err, "deriveKeys error")

	sls.SessionKey = sessionKey

	return sls
}

func TestServerLoginStateEncodeDecode(t *testing.T) {
	suites := []Suite{Ristretto255Suite.New(), P256Suite.New()}

	for _, suite := range suites {
		t.Run(suite.Group().String(), func(tt *testing.T) {
			state := getRandomServerLoginState(t, suite)

			serializedState, err := state.Serialize()
			test.CheckNoErr(tt, err, "serialization error")

			newState := getRandomServerLoginState(t, suite)

			err = newState.Deserialize(suite, serializedState)
			test.CheckNoErr(tt, err, "deserialization error")

			serializedNewState, err := newState.Serialize()
			test.CheckNoErr(tt, err, "serialization error")

			if !bytes.Equal(serializedState, serializedNewState) {
				test.Report(tt, serializedNewState, serializedState)
			}

			encodedState, err := state.Encode()
			test.CheckNoErr(tt, err, "encoding error")

			newState = getRandomServerLoginState(t, suite)

			err = newState.Decode(suite, encodedState)
			test.CheckNoErr(tt, err, "decoding error")

			encodedNewState, err := newState.Encode()
			test.CheckNoErr(tt, err, "encoding error")

			if !bytes.Equal(encodedState, encodedNewState) {
				test.Report(tt, encodedNewState, encodedState)
			}
		})
	}
}
