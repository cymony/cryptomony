// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/hash"
)

var (
	// SuiteRistretto255Sha512 suite identify the OPRF with Ristretto255 and SHA512.
	// See https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-oprfristretto255-sha-512
	SuiteRistretto255Sha512 Suite = &suite{suiteID: 0x0001, group: eccgroup.Ristretto255Sha512, hash: hash.SHA512, strRep: "OPRF(ristretto255, SHA-512)"}

	// SuiteP256Sha256 suite identify the OPRF with P256 and SHA256.
	// See https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-oprfp-256-sha-256
	SuiteP256Sha256 Suite = &suite{suiteID: 0x0003, group: eccgroup.P256Sha256, hash: hash.SHA256, strRep: "OPRF(P-256, SHA-256)"}

	// SuiteP384Sha384 suite identify the OPRF with P384 and SHA384.
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-oprfp-384-sha-384
	SuiteP384Sha384 Suite = &suite{suiteID: 0x0004, group: eccgroup.P384Sha384, hash: hash.SHA384, strRep: "OPRF(P-384, SHA-384)"}

	// SuiteP521Sha512 suite identify the OPRF with P521 and SHA512.
	// See https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-12.html#name-oprfp-521-sha-512
	SuiteP521Sha512 Suite = &suite{suiteID: 0x0005, group: eccgroup.P521Sha512, hash: hash.SHA512, strRep: "OPRF(P-521, SHA-512)"}
)

// Suite is an interface that identify underlying prime-order curve and hash
type Suite interface {
	String() string
	SuiteID() int
	Group() eccgroup.Group
	Hash() hash.Hashing
	blockExternalImplement()
}

type suite struct {
	strRep  string
	suiteID uint16
	group   eccgroup.Group
	hash    hash.Hashing
}

func (s *suite) String() string {
	return s.strRep
}

func (s *suite) SuiteID() int {
	return int(s.suiteID)
}

func (s *suite) Group() eccgroup.Group {
	return s.group
}

func (s *suite) Hash() hash.Hashing {
	return s.hash
}

func (s *suite) blockExternalImplement() {}

func isSuiteAvailable(s Suite) bool {
	switch s {
	case SuiteP256Sha256, SuiteP384Sha384, SuiteP521Sha512, SuiteRistretto255Sha512:
		return true
	default:
		return false
	}
}
