// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

// ServerLoginState represents the server's ake state
// to give ServerFinish function as parameter.
// This library does not manage the state internally.
type ServerLoginState struct {
	ExpectedClientMac []byte
	SessionKey        []byte
}
