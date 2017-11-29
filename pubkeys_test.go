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

package ima_test

import (
	"testing"

	"crypto/rand"
	"crypto/rsa"

	"pault.ag/go/ima"
)

func TestKeyPool(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	isok(t, err)

	id, err := ima.PublicKeyId(key.Public())
	isok(t, err)

	pool := ima.NewKeyPool()

	assert(t, pool.MaybeContains(key.Public()) == false)
	assert(t, len(pool.Get(id)) == 0)
	isok(t, pool.AddKey(key.Public()))

	assert(t, pool.MaybeContains(key.Public()) == true)
	assert(t, len(pool.Get(id)) == 1)
}
