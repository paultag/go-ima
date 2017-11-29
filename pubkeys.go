// Copyright 2017 Paul Tagliamonte <paultag@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ima

import (
	"crypto"
	"fmt"
)

// Initialize a KeyPool
func NewKeyPool() KeyPool {
	return KeyPool{pool: map[string][]crypto.PublicKey{}}
}

// KeyPool is a keyring of crypto.PublicKeys. Internally, this uses the
// PublicKeyId to serve not unlike a bloom filter for key selection, which
// allows the Verify function to only try keys which have matching Key IDs.
type KeyPool struct {
	pool map[string][]crypto.PublicKey
}

// Cheeck to see if the crypto.PublicKey's PublicKeyId is set in the underlying
// storage, and if that key might already be included.
func (k KeyPool) MaybeContains(key crypto.PublicKey) bool {
	id, err := PublicKeyId(key)
	if err != nil {
		return false
	}
	idk := fmt.Sprintf("%x", id)
	_, ok := k.pool[idk]
	return ok
}

// Get all matching keys by the KeyId.
func (k KeyPool) Get(id [4]byte) []crypto.PublicKey {
	idk := fmt.Sprintf("%x", id)
	return k.pool[idk]
}

// Add a new crypto.PublicKey to the keychain.
func (k KeyPool) AddKey(key crypto.PublicKey) error {
	id, err := PublicKeyId(key)
	if err != nil {
		return err
	}
	idk := fmt.Sprintf("%x", id)
	if _, ok := k.pool[idk]; !ok {
		k.pool[idk] = []crypto.PublicKey{}
	}
	k.pool[idk] = append(k.pool[idk], key)
	return nil
}
