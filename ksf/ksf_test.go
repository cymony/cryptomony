// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

//nolint:gocyclo,govet //test
package ksf

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cymony/cryptomony/internal/test"
)

func TestKSF(t *testing.T) {
	testVectors := []struct {
		ksfType         Identifier
		optionFunctions []Option
		password        []byte
		salt            []byte
		length          int
		wantErr         bool
		wantedErr       error
		wantPanic       bool
	}{
		{
			ksfType:         Scrypt,
			optionFunctions: []Option{},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          32,
			wantErr:         false,
			wantedErr:       nil,
		},
		{
			ksfType:         Bcrypt,
			optionFunctions: []Option{},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          60,
			wantErr:         false,
			wantedErr:       nil,
		},
		{
			ksfType:         Argon2id,
			optionFunctions: []Option{},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          32,
			wantErr:         false,
			wantedErr:       nil,
		},
		{
			ksfType:         Scrypt,
			optionFunctions: []Option{WithArgon2Memory(2)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          32,
			wantErr:         true,
			wantedErr:       ErrNotArgon2,
		},
		{
			ksfType:         Scrypt,
			optionFunctions: []Option{WithArgon2Time(2)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          32,
			wantErr:         true,
			wantedErr:       ErrNotArgon2,
		},
		{
			ksfType:         Bcrypt,
			optionFunctions: []Option{WithScryptP(2)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          60,
			wantErr:         true,
			wantedErr:       ErrNotScrypt,
		},
		{
			ksfType:         Bcrypt,
			optionFunctions: []Option{WithScryptN(8)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          60,
			wantErr:         true,
			wantedErr:       ErrNotScrypt,
		},
		{
			ksfType:         Bcrypt,
			optionFunctions: []Option{WithArgon2Threads(2)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          60,
			wantErr:         true,
			wantedErr:       ErrNotArgon2,
		},
		{
			ksfType:         Argon2id,
			optionFunctions: []Option{WithBcryptCost(3)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          32,
			wantErr:         true,
			wantedErr:       ErrNotBcrypt,
		},
		{
			ksfType:         Argon2id,
			optionFunctions: []Option{WithScryptR(3)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          32,
			wantErr:         true,
			wantedErr:       ErrNotScrypt,
		},
		{
			ksfType:         Scrypt,
			optionFunctions: []Option{WithScryptN(8), WithScryptP(8), WithScryptR(8)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          32,
			wantErr:         false,
			wantedErr:       nil,
		},
		{
			ksfType:         Bcrypt,
			optionFunctions: []Option{WithBcryptCost(5)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          60,
			wantErr:         false,
			wantedErr:       nil,
		},
		{
			ksfType:         Argon2id,
			optionFunctions: []Option{WithArgon2Memory(3 * 1024), WithArgon2Threads(3), WithArgon2Time(3)},
			password:        []byte("SecretPass"),
			salt:            nil,
			length:          32,
			wantErr:         false,
			wantedErr:       nil,
		},
		{
			ksfType:   Identifier(20),
			wantPanic: true,
		},
	}

	for i, v := range testVectors {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			if v.wantPanic {
				isPanic := test.CheckPanic(func() {
					v.ksfType.New()
				})
				test.CheckNoErr(t, isPanic, "panic expected")
				t.Skip()
			}
			k := v.ksfType.New()

			err := k.SetOptions(v.optionFunctions...)
			if v.wantErr && err == nil {
				test.Report(t, err, v.wantedErr, fmt.Sprintf("%s#%d", k.String(), i))
			}
			if v.wantErr && !errors.Is(err, v.wantedErr) {
				test.Report(t, err, v.wantedErr, fmt.Sprintf("%s#%d", k.String(), i))
			}

			if len(v.optionFunctions) > 0 && !v.wantErr {
				sc, ok := k.(*scryptKSF)
				if ok {
					if sc.n != 8 {
						test.Report(t, sc.n, 8, fmt.Sprintf("%s#%d", k.String(), i))
					}
					if sc.r != 8 {
						test.Report(t, sc.r, 8, fmt.Sprintf("%s#%d", k.String(), i))
					}
					if sc.p != 8 {
						test.Report(t, sc.p, 8, fmt.Sprintf("%s#%d", k.String(), i))
					}
					if sc.String() != "Scrypt(8,8,8)" {
						test.Report(t, sc.String(), "Scrypt(8,8,8)", fmt.Sprintf("%s#%d", k.String(), i))
					}
				}
				bc, ok := k.(*bcryptKSF)
				if ok {
					if bc.cost != 5 {
						test.Report(t, bc.cost, 5, fmt.Sprintf("%s#%d", k.String(), i))
					}
					if bc.String() != "Bcrypt(5)" {
						test.Report(t, bc.String(), "Bcrypt(5)", fmt.Sprintf("%s#%d", k.String(), i))
					}
				}
				ar, ok := k.(*argon2KSF)
				if ok {
					if ar.time != 3 {
						test.Report(t, ar.time, 3, fmt.Sprintf("%s#%d", k.String(), i))
					}
					if ar.memory != 3*1024 {
						test.Report(t, ar.memory, 3*1024, fmt.Sprintf("%s#%d", k.String(), i))
					}
					if ar.threads != 3 {
						test.Report(t, ar.threads, 3, fmt.Sprintf("%s#%d", k.String(), i))
					}
					if ar.String() != fmt.Sprintf("%s(%d,%d,%d)", ar.str, 3, 3*1024, 3) {
						test.Report(t, ar.String(), fmt.Sprintf("%s(%d,%d,%d)", ar.str, 3, 3*1024, 3), fmt.Sprintf("%s#%d", k.String(), i))
					}
				}
			}

			out, err := k.Harden(v.password, v.salt, v.length)
			test.CheckNoErr(t, err, "err not expected harden")
			if len(out) != v.length {
				test.Report(t, len(out), v.length, fmt.Sprintf("%s#%d", k.String(), i))
			}
		})
	}
}
