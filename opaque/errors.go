// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//nolint:revive //Err explanation does not required
package opaque

import (
	"errors"
)

var (
	ErrEnvelopeRecovery         = errors.New("opaque: envelope recovery failed")
	ErrSeedLength               = errors.New("opaque: unexpected seed length")
	ErrPrivateKeyInitialization = errors.New("opaque: private key not initialized")
	ErrPublicKeyInitialization  = errors.New("opaque: public key not initialized")
	ErrRecoverCredentialsFailed = errors.New("opaque: recover credentials operation failed")
	ErrOPRFBlind                = errors.New("opaque: oprf blind operation failed")
	ErrOPRFFinalize             = errors.New("opaque: oprf finalize operation failed")
	ErrOPRFEvaluate             = errors.New("opaque: oprf evaluate operation failed")
	ErrOPRFSeedLength           = errors.New("opaque: unexpected length of oprf seed")
	ErrServerAuthentication     = errors.New("opaque: server authentication failed")
	ErrClientAuthentication     = errors.New("opaque: client authentication failed")
	ErrDecodingFailed           = errors.New("opaque: decoding failed")
	ErrEncodingFailed           = errors.New("opaque: encoding failed")
	ErrDeserializationFailed    = errors.New("opaque: deserialization failed")
	ErrSerializationFailed      = errors.New("opaque: serialization failed")
)
