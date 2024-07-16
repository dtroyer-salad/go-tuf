// Copyright 2024 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// SPDX-License-Identifier: Apache-2.0
//

package cmd

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
)

const (
	DefaultMetadataDir = "tuf_metadata"
	DefaultDownloadDir = "tuf_download"
)

// ReadFile reads the content of a file and return its bytes
func ReadFile(name string) ([]byte, error) {
	in, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func decode(pemEncoded []byte, pemEncodedPub []byte) (*ed25519.PrivateKey, *ed25519.PublicKey) {
	block, _ := pem.Decode(pemEncoded)
	x509Encoded := block.Bytes
	pk, _ := x509.ParsePKCS8PrivateKey(x509Encoded)
	var privateKey *ed25519.PrivateKey
	if pk, ok := pk.(ed25519.PrivateKey); ok {
		privateKey = &pk
	}

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(ed25519.PublicKey)

	return privateKey, &publicKey
}

func encode(privateKey *ed25519.PrivateKey, publicKey *ed25519.PublicKey) ([]byte, []byte) {
	x509Encoded, _ := x509.MarshalPKCS8PrivateKey(*privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(*publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return pemEncoded, pemEncodedPub
}
