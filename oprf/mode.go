// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

// OPRF Mode constants https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-configuration
type ModeType uint8

const (
	ModeOPRF  ModeType = 0x00
	ModeVOPRF ModeType = 0x01
	ModePOPRF ModeType = 0x02
)

func isModeAvailable(m ModeType) bool {
	switch m {
	case ModeOPRF, ModeVOPRF, ModePOPRF:
		return true
	default:
		return false
	}
}
