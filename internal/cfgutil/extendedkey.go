// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cfgutil

import "github.com/decred/dcrd/hdkeychain"

// ExtendedKeyFlag embeds a hdkeychain.ExtendedKey and implements the
// flags.Marshaler and Unmarshaler interfaces so it can be used as a config
// struct field.
type ExtendedKeyFlag struct {
	*hdkeychain.ExtendedKey
}

// NewExtendedKeyFlag creates an ExtendedKeyFlag with a default
// hdkeychain.ExtendedKey.
func NewExtendedKeyFlag(defaultValue *hdkeychain.ExtendedKey) *ExtendedKeyFlag {
	return &ExtendedKeyFlag{defaultValue}
}

// MarshalFlag satisifes the flags.Marshaler interface.
func (e *ExtendedKeyFlag) MarshalFlag() (string, error) {
	if e.ExtendedKey != nil {
		return e.ExtendedKey.String()
	}

	return "", nil
}

// UnmarshalFlag satisifes the flags.Unmarshaler interface.
func (e *ExtendedKeyFlag) UnmarshalFlag(extendedKey string) error {
	if extendedKey == "" {
		e.ExtendedKey = nil
		return nil
	}
	key, err := hdkeychain.NewKeyFromString(extendedKey)
	if err != nil {
		return err
	}
	e.ExtendedKey = key
	return nil
}
