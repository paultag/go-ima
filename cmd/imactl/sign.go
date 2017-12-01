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

package main

import (
	"crypto"
	"crypto/rand"
	"os"

	"github.com/urfave/cli"

	"pault.ag/go/ima/xattr"
)

func Sign(c *cli.Context) error {
	signer, err := LoadSigner(c)
	if err != nil {
		return err
	}

	for _, path := range c.Args() {
		fd, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fd.Close()
		if err := xattr.Sign(signer, rand.Reader, crypto.SHA256, fd); err != nil {
			return err
		}
	}
	return nil
}

var SignCommand = cli.Command{
	Name:   "sign",
	Action: Wrapper(Sign),
	Usage:  "sign a file",
	Flags:  []cli.Flag{},
}

// vim: foldmethod=marker
