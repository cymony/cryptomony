// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oprf

import (
	"math/big"

	"github.com/cymony/cryptomony/utils"
)

// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-configuration

var (
	contextVersion        = "VOPRF10-"
	hashToGroupDSTPrefix  = "HashToGroup-"
	hashToScalarDSTPrefix = "HashToScalar-"
	deriveKeyDSTPrefix    = "DeriveKeyPair"
	finalizeLabel         = "Finalize"
	infoLabel             = "Info"
)

func createContextString(mode ModeType, s Suite) []byte {
	i2ospMode1, err := utils.I2osp(big.NewInt(int64(mode)), 1)
	if err != nil {
		panic(err)
	}

	i2ospSuiteID2, err := utils.I2osp(big.NewInt(int64(s.SuiteID())), 2)
	if err != nil {
		panic(err)
	}

	return utils.Concat([]byte(contextVersion), i2ospMode1, i2ospSuiteID2)
}

func createHashToGroupDST(mode ModeType, s Suite) []byte {
	contextString := createContextString(mode, s)
	return utils.Concat([]byte(hashToGroupDSTPrefix), contextString)
}

func createHashToScalarDST(mode ModeType, s Suite) []byte {
	contextString := createContextString(mode, s)
	return utils.Concat([]byte(hashToScalarDSTPrefix), contextString)
}

func createDeriveKeyDST(mode ModeType, s Suite) []byte {
	contextString := createContextString(mode, s)
	return utils.Concat([]byte(deriveKeyDSTPrefix), contextString)
}

func createFinalizeLabel() []byte {
	return utils.Concat([]byte(finalizeLabel))
}

func createInfoLabel(info []byte) []byte {
	i2ospLenInfo2, err := utils.I2osp(big.NewInt(int64(len(info))), 2)
	if err != nil {
		panic(err)
	}

	return utils.Concat([]byte(infoLabel), i2ospLenInfo2, info)
}
