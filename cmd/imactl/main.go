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
	"encoding/pem"
	"io/ioutil"
	"os"

	"crypto"
	"crypto/x509"

	"github.com/urfave/cli"

	"pault.ag/go/ima"
	"pault.ag/go/ima/xattr"
)

func LoadPool(c *cli.Context) (*ima.KeyPool, error) {
	fd, err := os.Open(c.GlobalString("pubkey"))
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	pool := ima.NewKeyPool()

	for {
		if len(data) == 0 {
			break
		}
		var block *pem.Block
		block, data = pem.Decode(data)
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if err := pool.AddKey(key); err != nil {
			return nil, err
		}
	}

	return &pool, nil
}

func LoadSigner(c *cli.Context) (crypto.Signer, error) {
	fd, err := os.Open(c.GlobalString("privkey"))
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func Wrapper(cmd func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) error {
		if err := cmd(c); err != nil {
			panic(err)
		}
		return nil
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "imactl"
	app.Usage = "sign and validate ima signatures"
	app.Version = "0.1"

	// xattr.IMAAttrName = "user.ima"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "pubkey",
			Value: "/etc/keys/pubkey_evm.pem",
		},
		cli.StringFlag{
			Name:  "privkey",
			Value: "/etc/keys/privkey_evm.pem",
		},
	}

	app.Commands = []cli.Command{
		SignCommand,
		VerifyCommand,
	}

	app.Run(os.Args)
}

// vim: foldmethod=marker
