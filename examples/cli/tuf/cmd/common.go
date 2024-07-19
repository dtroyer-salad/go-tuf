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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
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

func getKeys(metadataDir string) map[string]ed25519.PrivateKey {
	keys := map[string]ed25519.PrivateKey{}
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		privData, err := os.ReadFile(filepath.Join(metadataDir, name+".priv"))
		if err != nil {
			return keys
		}
		pubData, err := os.ReadFile(filepath.Join(metadataDir, name+".pub"))
		if err != nil {
			return keys
		}
		private, _ := decode(privData, pubData)
		keys[name] = *private
	}
	return keys
}

// Initialize an Updater for the local repo
func MakeLocalUpdater(metadataDir string) (*config.UpdaterConfig, *trustedmetadata.TrustedMetadata, error) {
	log := metadata.GetLogger()

	// Load our initial root
	root, err := os.ReadFile(filepath.Join(metadataDir, "root.json"))
	if err != nil {
		return nil, nil, err
	}

	// create updater configuration
	cfg, err := config.New(filepath.Join("file:///", metadataDir, "download"), root)
	if err != nil {
		return nil, nil, err
	}

	cfg.LocalMetadataDir = metadataDir
	cfg.LocalTargetsDir = filepath.Join(metadataDir, "download")
	cfg.RemoteTargetsURL = ""
	cfg.PrefixTargetsWithHash = true

	log.Info("config created")

	// create a new Updater instance
	// up, err := updater.New(cfg)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create Updater instance: %w", err)
	// }

	// Alternative to updater.New() sicne we need access to private fields
	// create a new trusted metadata instance using the trusted root.json
	trusted, err := trustedmetadata.New(cfg.LocalTrustedRoot)
	if err != nil {
		return cfg, nil, err
	}
	// ensure paths exist, doesn't do anything if caching is disabled
	err = cfg.EnsurePathsExist()
	if err != nil {
		return cfg, trusted, err
	}

	log.Info("trusted created")

	// Load real root
	err = loadRoot(cfg, trusted)
	if err != nil {
		return cfg, nil, fmt.Errorf("Error loading current root: %s", err)
	}
	rootVersion := trusted.Root.Signed.Version
	fmt.Printf("new root loaded: %d", rootVersion)

	// load timestamp
	err = loadTimestamp(cfg, trusted)
	timestampVersion := trusted.Timestamp.Signed.Version
	fmt.Printf("timestamp read: %d\n", rootVersion)

	// load snapshot
	data, err := os.ReadFile(
		filepath.Join(
			cfg.LocalMetadataDir,
			fmt.Sprintf("%d.%s.json", timestampVersion, metadata.SNAPSHOT),
		),
	)
	if err != nil {
		return cfg, trusted, err
	}
	_, err = trusted.UpdateSnapshot(data, false)
	if err != nil {
		return cfg, trusted, err
	}

	log.Info("new snapshot loaded: ", trusted.Snapshot.Signed.Version)

	// targets
	data, err = os.ReadFile(
		filepath.Join(
			cfg.LocalMetadataDir,
			fmt.Sprintf("%d.%s.json", trusted.Snapshot.Signed.Version, metadata.TARGETS),
		),
	)
	if err != nil {
		return cfg, trusted, err
	}
	// verify and load the new target metadata
	_, err = trusted.UpdateDelegatedTargets(data, metadata.TARGETS, metadata.ROOT)
	if err != nil {
		return cfg, trusted, err
	}

	return cfg, trusted, nil
}

// loadTimestamp load local and remote timestamp metadata
func loadTimestamp(cfg *config.UpdaterConfig, trusted *trustedmetadata.TrustedMetadata) error {
	log := metadata.GetLogger()
	// try to read local timestamp
	// data, err := update.loadLocalMetadata(filepath.Join(update.cfg.LocalMetadataDir, metadata.TIMESTAMP))
	data, err := os.ReadFile(
		filepath.Join(
			cfg.LocalMetadataDir,
			fmt.Sprintf("%s.json", metadata.TIMESTAMP),
		),
	)
	if err != nil {
		// this means there's no existing local timestamp so we should proceed downloading it without the need to UpdateTimestamp
		log.Info("Local timestamp does not exist")
	} else {
		// local timestamp exists, let's try to verify it and load it to the trusted metadata set
		_, err := trusted.UpdateTimestamp(data)
		if err != nil {
			if errors.Is(err, &metadata.ErrRepository{}) {
				// local timestamp is not valid, proceed downloading from remote; note that this error type includes several other subset errors
				log.Info("Local timestamp is not valid")
			} else {
				// another error
				return err
			}
		}
		log.Info("Local timestamp is valid")
		// all okay, local timestamp exists and it is valid, nevertheless proceed with downloading from remote
	}

	// proceed with persisting the new timestamp
	err = persistMetadata(cfg, metadata.TIMESTAMP, data)
	if err != nil {
		return err
	}
	return nil
}

func loadRoot(cfg *config.UpdaterConfig, trusted *trustedmetadata.TrustedMetadata) error {
	// calculate boundaries
	lowerBound := trusted.Root.Signed.Version + 1
	upperBound := lowerBound + cfg.MaxRootRotations

	// loop until we find the latest available version of root (download -> verify -> load -> persist)
	for nextVersion := lowerBound; nextVersion < upperBound; nextVersion++ {
		// data, err := downloadMetadata(cfg, metadata.ROOT, cfg.RootMaxLength, strconv.FormatInt(nextVersion, 10))
		data, err := os.ReadFile(
			filepath.Join(
				cfg.LocalMetadataDir,
				fmt.Sprintf("%d.%s.json", nextVersion, metadata.ROOT),
			),
		)
		if err != nil {
			// reading the root metadata failed for some reason
			if errors.As(err, &fs.ErrNotExist) {
				// This is expected when we've found the current version
				break
			}
			// some other error ocurred
			err = fmt.Errorf("Error reading new root: %s\n", err)
			return err
		} else {
			// downloading root metadata succeeded, so let's try to verify and load it
			_, err = trusted.UpdateRoot(data)
			if err != nil {
				err = fmt.Errorf("Error Updating root: %s\n", err)
				return err
			}
			// persist root metadata to disk
			err = persistMetadata(cfg, metadata.ROOT, data)
			if err != nil {
				err = fmt.Errorf("Error persisting root: %s\n", err)
				return err
			}
		}
	}
	return nil
}

// downloadMetadata download a metadata file and return it as bytes
func downloadMetadata(cfg *config.UpdaterConfig, roleName string, length int64, version string) ([]byte, error) {
	urlPath := ensureTrailingSlash(cfg.RemoteMetadataURL)
	// build urlPath
	if version == "" {
		urlPath = fmt.Sprintf("%s%s.json", urlPath, url.QueryEscape(roleName))
	} else {
		urlPath = fmt.Sprintf("%s%s.%s.json", urlPath, version, url.QueryEscape(roleName))
	}
	return cfg.Fetcher.DownloadFile(urlPath, length, time.Second*15)
}

// persistMetadata writes metadata to disk atomically to avoid data loss
func persistMetadata(cfg *config.UpdaterConfig, roleName string, data []byte) error {
	log := metadata.GetLogger()
	// do not persist the metadata if we have disabled local caching
	if cfg.DisableLocalCache {
		return nil
	}
	// caching enabled, proceed with persisting the metadata locally
	fileName := filepath.Join(cfg.LocalMetadataDir, fmt.Sprintf("%s.json", url.QueryEscape(roleName)))
	// create a temporary file
	file, err := os.CreateTemp(cfg.LocalMetadataDir, "tuf_tmp")
	if err != nil {
		return err
	}
	defer file.Close()
	// write the data content to the temporary file
	err = os.WriteFile(file.Name(), data, 0644)
	if err != nil {
		// delete the temporary file if there was an error while writing
		errRemove := os.Remove(file.Name())
		if errRemove != nil {
			log.Info("Failed to delete temporary file", "name", file.Name())
		}
		return err
	}

	// can't move/rename an open file on windows, so close it first
	err = file.Close()
	if err != nil {
		return err
	}
	// if all okay, rename the temporary file to the desired one
	err = os.Rename(file.Name(), fileName)
	if err != nil {
		return err
	}
	read, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	if string(read) != string(data) {
		return fmt.Errorf("failed to persist metadata")
	}
	return nil
}

// ensureTrailingSlash ensures url ends with a slash
func ensureTrailingSlash(url string) string {
	if strings.HasSuffix(url, "/") {
		return url
	}
	return url + "/"
}

// From https://cs.opensource.google/go/x/exp/+/39d4317d:maps/maps.go;l=10
// ToDo: When Go 1.23+ is our minimum remove this and use maps.Keys()
// Keys returns the keys of the map m.
// The keys will be in an indeterminate order.
func Keys[M ~map[K]V, K comparable, V any](m M) []K {
	r := make([]K, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	return r
}
