// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package ksf

type Option func(KSF) error

// WithArgon2Time sets argon algorithm's time parameter.
// This option must used with only argon instance
func WithArgon2Time(time int) Option {
	return func(k KSF) error {
		argon, ok := k.(*argon2KSF)
		if !ok {
			return ErrNotArgon2
		}

		argon.time = time

		return nil
	}
}

// WithArgon2Memory sets argon algorithm's memory parameter.
// This option must used with only argon instance
func WithArgon2Memory(memory int) Option {
	return func(k KSF) error {
		argon, ok := k.(*argon2KSF)
		if !ok {
			return ErrNotArgon2
		}

		argon.memory = memory

		return nil
	}
}

// WithArgon2Threads sets argon algorithm's threads parameter.
// This option must used with only argon instance
func WithArgon2Threads(threads int) Option {
	return func(k KSF) error {
		argon, ok := k.(*argon2KSF)
		if !ok {
			return ErrNotArgon2
		}

		argon.threads = threads

		return nil
	}
}

// WithBcryptCost sets bcrypt algorithm's cost parameter.
// This option must used with only bcrypt instance
func WithBcryptCost(cost int) Option {
	return func(k KSF) error {
		bc, ok := k.(*bcryptKSF)
		if !ok {
			return ErrNotBcrypt
		}

		bc.cost = cost

		return nil
	}
}

// WithScryptN sets scrypt algorithm's n parameter.
// This option must used with only scrypt instance
func WithScryptN(n int) Option {
	return func(k KSF) error {
		sc, ok := k.(*scryptKSF)
		if !ok {
			return ErrNotScrypt
		}

		sc.n = n

		return nil
	}
}

// WithScryptR sets scrypt algorithm's r parameter.
// This option must used with only scrypt instance
func WithScryptR(r int) Option {
	return func(k KSF) error {
		sc, ok := k.(*scryptKSF)
		if !ok {
			return ErrNotScrypt
		}

		sc.r = r

		return nil
	}
}

// WithScryptP sets scrypt algorithm's p parameter.
// This option must used with only scrypt instance
func WithScryptP(p int) Option {
	return func(k KSF) error {
		sc, ok := k.(*scryptKSF)
		if !ok {
			return ErrNotScrypt
		}

		sc.p = p

		return nil
	}
}
