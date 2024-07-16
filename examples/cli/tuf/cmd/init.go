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
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	stdlog "log"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/stdr"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

var rootPath string

var initCmd = &cobra.Command{
	Use:     "init",
	Aliases: []string{"i"},
	Short:   "Initialize a repository",
	Args:    cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return InitializeCmd()
	},
}

func init() {
	initCmd.Flags().StringVarP(&rootPath, "file", "f", "", "location of the trusted root metadata file")
	rootCmd.AddCommand(initCmd)
}

func InitializeCmd() error {
	copyTrusted := true

	// set logger and debug verbosity level
	metadata.SetLogger(stdr.New(stdlog.New(os.Stdout, "ini_cmd", stdlog.LstdFlags)))
	if Verbosity {
		stdr.SetVerbosity(5)
	}

	// prepare the local environment
	localMetadataDir, err := prepareEnvironment()
	if err != nil {
		return err
	}

	// if there's no root.json file passed, make one
	if rootPath == "" {
		rootPath, err = createRoot(localMetadataDir)
		if err != nil {
			return err
		}
		copyTrusted = false
	}

	// read the content of root.json
	rootBytes, err := ReadFile(filepath.Join(localMetadataDir, rootPath))
	if err != nil {
		return fmt.Errorf("reading root.json failed: %s: %s", filepath.Join(localMetadataDir, rootPath), err)
	}

	// verify the content
	_, err = trustedmetadata.New(rootBytes)
	if err != nil {
		return fmt.Errorf("verify failed: %s", err)
	}

	// Save the trusted root.json file to the metadata folder so it is available for future operations (if we haven't downloaded it)
	if copyTrusted {
		err = os.WriteFile(filepath.Join(localMetadataDir, rootPath), rootBytes, 0644)
		if err != nil {
			return fmt.Errorf("writing root.json failed: %s", err)
		}
	}

	fmt.Println("Initialization successful")

	return nil
}

// prepareEnvironment prepares the local environment
func prepareEnvironment() (string, error) {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}
	metadataPath := filepath.Join(cwd, DefaultMetadataDir)
	downloadPath := filepath.Join(cwd, DefaultDownloadDir)

	// create a folder for storing the artifacts
	err = os.Mkdir(metadataPath, 0750)
	if err != nil {
		return "", fmt.Errorf("failed to create local metadata folder: %w", err)
	}

	// create a destination folder for storing the downloaded target
	err = os.Mkdir(downloadPath, 0750)
	if err != nil {
		return "", fmt.Errorf("failed to create download folder: %w", err)
	}
	return metadataPath, nil
}

// Based on basic_repository.go
func createRoot(metadataDir string) (string, error) {
	// Create top-level metadata

	// Containers for metadata objects and keys
	roles := repository.New()
	keys := map[string]ed25519.PrivateKey{}

	// Targets (integrity)
	targets := metadata.Targets(helperExpireIn(7))
	roles.SetTargets("targets", targets)

	// Snapshot (consistency)
	snapshot := metadata.Snapshot(helperExpireIn(7))
	roles.SetSnapshot(snapshot)

	// Timestamp (freshness)
	timestamp := metadata.Timestamp(helperExpireIn(1))
	roles.SetTimestamp(timestamp)

	// Root (root of trust)
	root := metadata.Root(helperExpireIn(365))
	roles.SetRoot(root)

	// Generate one private key of type 'ed25519' for each top-level role
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("key generation failed: %s", err)
		}
		keys[name] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			return "", fmt.Errorf("key conversion failed: %s", err)
		}
		err = roles.Root().Signed.AddKey(key, name)
		if err != nil {
			return "", fmt.Errorf("adding key to root failed: %s", err)
		}

		// Save keys
		privateEnc, publicEnc := encode(&private, &public)
		keyFile := filepath.Join(metadataDir, name+".priv")
		err = os.WriteFile(keyFile, privateEnc, 0600)
		if err != nil {
			return "", err
		}
		keyFile = filepath.Join(metadataDir, name+".pub")
		err = os.WriteFile(keyFile, publicEnc, 0644)
		if err != nil {
			return "", err
		}
	}

	// Sign top-level metadata (in-band)
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		key := keys[name]
		signer, err := signature.LoadSigner(key, crypto.Hash(0))
		if err != nil {
			return "", fmt.Errorf("loading a signer failed: %s", err)
		}
		switch name {
		case "targets":
			_, err = roles.Targets("targets").Sign(signer)
		case "snapshot":
			_, err = roles.Snapshot().Sign(signer)
		case "timestamp":
			_, err = roles.Timestamp().Sign(signer)
		case "root":
			_, err = roles.Root().Sign(signer)
		}
		if err != nil {
			return "", fmt.Errorf("metadata signing failed: %s", err)
		}
	}

	// Persist metadata (consistent snapshot)
	var rootJsonPath string
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		var err error
		switch name {
		case "targets":
			filename := fmt.Sprintf("%d.%s.json", roles.Targets("targets").Signed.Version, name)
			err = roles.Targets("targets").ToFile(filepath.Join(metadataDir, filename), true)
		case "snapshot":
			filename := fmt.Sprintf("%d.%s.json", roles.Snapshot().Signed.Version, name)
			err = roles.Snapshot().ToFile(filepath.Join(metadataDir, filename), true)
		case "timestamp":
			filename := fmt.Sprintf("%s.json", name)
			err = roles.Timestamp().ToFile(filepath.Join(metadataDir, filename), true)
		case "root":
			rootJsonPath = fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, name)
			err = roles.Root().ToFile(filepath.Join(metadataDir, rootJsonPath), true)
		}
		if err != nil {
			return "", fmt.Errorf("saving metadata to file failed: %s", err)
		}
	}
	return rootJsonPath, nil
}

// helperExpireIn returns time offset by days
func helperExpireIn(days int) time.Time {
	return time.Now().AddDate(0, 0, days).UTC()
}
