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

package xattr_test

import (
	"io/ioutil"
	"os"
	"testing"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"

	"pault.ag/go/ima"
	"pault.ag/go/ima/xattr"
)

func TestSign(t *testing.T) {
	xattr.IMAAttrName = "user.ima"

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	isok(t, err)

	content := []byte("totally legit elf af")
	tmpfile, err := ioutil.TempFile("", "ima-xattr")
	isok(t, err)
	defer os.Remove(tmpfile.Name())
	_, err = tmpfile.Write(content)
	isok(t, err)

	tmpfile.Seek(0, 0)
	isok(t, xattr.Sign(key, rand.Reader, crypto.SHA256, tmpfile))
	keys := ima.NewKeyPool()
	isok(t, keys.AddKey(key.Public()))

	tmpfile.Seek(0, 0)
	isok(t, xattr.Verify(tmpfile, keys))
	isok(t, tmpfile.Close())

	xattr.IMAAttrName = "security.ima"
}
