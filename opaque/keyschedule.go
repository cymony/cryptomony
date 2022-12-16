// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opaque

import (
	"math/big"

	"github.com/cymony/cryptomony/opaque/internal/common"
	"github.com/cymony/cryptomony/utils"
)

//	struct {
//	  uint16 length = Length;
//	  opaque label<8..255> = "OPAQUE-" + Label;
//	  uint8 context<0..255> = Context;
//	} CustomLabel;
func buildLabel(label, context []byte, l int) ([]byte, error) {
	length, err := utils.I2osp(big.NewInt(int64(l)), 2)
	if err != nil {
		return nil, err
	}

	lbl, err := common.I2ospLenX(utils.Concat([]byte(labelOPAQUEDash), label), 1)
	if err != nil {
		return nil, err
	}

	ctx, err := common.I2ospLenX(context, 1)
	if err != nil {
		return nil, err
	}

	return utils.Concat(length, lbl, ctx), nil
}

// Expand-Label(Secret, Label, Context, Length) =
// Expand(Secret, CustomLabel, Length)
func expandLabel(suite Suite, secret, label, context []byte, length int) ([]byte, error) {
	customLabel, err := buildLabel(label, context, length)
	if err != nil {
		return nil, err
	}

	return suite.Expand(secret, customLabel, length), nil
}

// Derive-Secret(Secret, Label, Transcript-Hash) =
// Expand-Label(Secret, Label, Transcript-Hash, Nx)
func deriveSecret(suite Suite, secret, label, transcript []byte) ([]byte, error) {
	return expandLabel(suite, secret, label, transcript, suite.Nx())
}

// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-transcript-functions
func preamble(clientIdentity []byte,
	ke1 *KE1,
	serverIdentity []byte,
	credRes *CredentialResponse,
	sNonce []byte,
	sKeyshare *PublicKey, context []byte) ([]byte, error) {
	// Vector encoding
	ctx2LenI2osp2, err := common.I2ospLenX(context, 2)
	if err != nil {
		return nil, err
	}

	cIdentityLenI2osp2, err := common.I2ospLenX(clientIdentity, 2)
	if err != nil {
		return nil, err
	}

	sIdentityLenI2osp2, err := common.I2ospLenX(serverIdentity, 2)
	if err != nil {
		return nil, err
	}

	// Serialize
	encodedKE1, err := ke1.Serialize()
	if err != nil {
		return nil, err
	}

	encodedCredRes, err := credRes.Serialize()
	if err != nil {
		return nil, err
	}

	encodedSKeyshare, err := sKeyshare.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return utils.Concat([]byte(labelRFCXXXX),
		ctx2LenI2osp2,
		cIdentityLenI2osp2,
		encodedKE1,
		sIdentityLenI2osp2,
		encodedCredRes,
		sNonce,
		encodedSKeyshare), nil
}

// Reference: https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-09.html#name-shared-secret-derivation
func deriveKeys(suite Suite, ikm, preamble []byte) ([]byte, []byte, []byte, error) {
	h := suite.Hash()
	if err := h.MustWriteAll(preamble); err != nil {
		return nil, nil, nil, err
	}

	hPreamble := make([]byte, h.OutputSize())
	if err := h.MustReadFull(hPreamble); err != nil {
		return nil, nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// prk = Extract("", ikm)
	prk := suite.Extract(nil, ikm)

	//nolint:gocritic //not a commented code
	// handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
	handshakeSecret, err := deriveSecret(suite, prk, []byte(labelHandshakeSecret), hPreamble)
	if err != nil {
		return nil, nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
	sessionKey, err := deriveSecret(suite, prk, []byte(labelSessionKey), hPreamble)
	if err != nil {
		return nil, nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
	km2, err := deriveSecret(suite, handshakeSecret, []byte(labelServerMAC), nil)
	if err != nil {
		return nil, nil, nil, err
	}

	//nolint:gocritic //not a commented code
	// Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
	km3, err := deriveSecret(suite, handshakeSecret, []byte(labelClientMAC), nil)
	if err != nil {
		return nil, nil, nil, err
	}

	// return (Km2, Km3, session_key)
	return km2, km3, sessionKey, nil
}
