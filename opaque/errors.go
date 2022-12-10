// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"errors"
)

var (
	ErrCleartextCredentialDecode = errors.New("opaque: cleartext credentials decode failed")
	ErrEnvelopeRecovery          = errors.New("opaque: envelope recovery failed")
	ErrEvaluateElement           = errors.New("opaque: unexpected size of evaluated elements")
	ErrBlindedElement            = errors.New("opaque: unexpected size of blinded elements")
	ErrBlind                     = errors.New("opaque: unexpected size of blinds")
	ErrFinalizeOut               = errors.New("opaque: unexpected size of finalize data")
	ErrSeedLength                = errors.New("opaque: unexpected seed length")
	ErrWrongPublicKey            = errors.New("opaque: wrong public key for private key")
	ErrPrivateKeyInitialization  = errors.New("opaque: private key not initialized")
	ErrPublicKeyInitialization   = errors.New("opaque: public key not initialized")

	// Recover Credentials errors
	ErrRecoverCredentialsFailed = errors.New("opaque: recover credentials operation failed")

	// OPRF errors
	ErrOPRFBlind      = errors.New("opaque: oprf blind operation failed")
	ErrOPRFFinalize   = errors.New("opaque: oprf finalize operation failed")
	ErrOPRFEvaluate   = errors.New("opaque: oprf evaluate operation failed")
	ErrOPRFSeedLength = errors.New("opaque: unexpected length of oprf seed")

	// Authentication errors
	ErrServerAuthentication = errors.New("opaque: server authentication failed")
	ErrClientAuthentication = errors.New("opaque: client authentication failed")

	// Encode, Decode errors
	ErrDecodingFailed = errors.New("opaque: decoding failed")
	ErrEncodingFailed = errors.New("opaque: encoding failed")

	// Serialize, Deserialize errors
	ErrDeserializationFailed = errors.New("opaque: deserialization failed")
	ErrSerializationFailed   = errors.New("opaque: serialization failed")
)
