package cmd

import (
	"crypto"
	"fmt"
	stdlog "log"
	"os"
	"path/filepath"

	"github.com/go-logr/stdr"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const DefaultHash = "sha256"

var targetPath string

var targetAddCmd = &cobra.Command{
	Use:     "target-add",
	Aliases: []string{"i"},
	Short:   "Add a target file",
	Args:    cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return TargetAddCmd()
	},
}

func init() {
	targetAddCmd.Flags().StringVarP(&targetPath, "file", "f", "", "location of the file to add to a target")
	rootCmd.AddCommand(targetAddCmd)
}

func TargetAddCmd() error {
	// set logger and debug verbosity level
	metadata.SetLogger(stdr.New(stdlog.New(os.Stdout, "target_add_cmd", stdlog.LstdFlags)))
	if Verbosity {
		stdr.SetVerbosity(5)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("target_add: getting cwd failed")
	}

	cfg, trusted, err := MakeLocalUpdater(filepath.Join(cwd, DefaultMetadataDir))
	if err != nil {
		return fmt.Errorf("Error loading metadata: %s", err)
	}

	// fmt.Printf("cfg:\n Metadata: %s\n Targets: %s\n", cfg.LocalMetadataDir, cfg.LocalTargetsDir)
	// fmt.Printf(" Remote Metadata: %s\n Remote Targets: %s\n", cfg.RemoteMetadataURL, cfg.RemoteTargetsURL)

	// add target file
	localPath := filepath.Join(cwd, targetPath)
	targetFileInfo, err := metadata.TargetFile().FromFile(localPath, "sha256")
	if err != nil {
		fmt.Errorf("generating target file info failed")
	}
	// fmt.Printf("trusted.Targets: %+v\ntargetFileInfo: %+v\n", Keys(trusted.Targets), targetFileInfo)
	trusted.Targets["targets"].Signed.Targets[targetPath] = targetFileInfo

	// Bump targets version
	trusted.Targets["targets"].Signed.Version += 1

	// Update snapshot to account for changed and new targets(delegatee) metadata
	trusted.Snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(trusted.Targets["targets"].Signed.Version)
	trusted.Snapshot.Signed.Version += 1

	// Update timestamp to account for changed snapshot metadata
	trusted.Timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(trusted.Snapshot.Signed.Version)
	trusted.Timestamp.Signed.Version += 1

	// Sign and write metadata for all changed roles, i.e. all but root
	keys := getKeys(cfg.LocalMetadataDir)
	for _, name := range []string{"targets", "snapshot", "timestamp"} {
		key := keys[name]
		signer, err := signature.LoadSigner(key, crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("loading signer failed: %s", err)
		}
		switch name {
		case "targets":
			trusted.Targets["targets"].ClearSignatures()
			_, err = trusted.Targets["targets"].Sign(signer)
			if err != nil {
				return fmt.Errorf("signing metadata failed: %s", err)
			}
			filename := fmt.Sprintf("%d.%s.json", trusted.Targets["targets"].Signed.Version, name)
			err = trusted.Targets["targets"].ToFile(filepath.Join(cfg.LocalMetadataDir, filename), true)
		case "snapshot":
			trusted.Snapshot.ClearSignatures()
			_, err = trusted.Snapshot.Sign(signer)
			if err != nil {
				return fmt.Errorf("signing metadata failed: %s", err)
			}
			filename := fmt.Sprintf("%d.%s.json", trusted.Snapshot.Signed.Version, name)
			err = trusted.Snapshot.ToFile(filepath.Join(cfg.LocalMetadataDir, filename), true)
		case "timestamp":
			trusted.Timestamp.ClearSignatures()
			_, err = trusted.Timestamp.Sign(signer)
			if err != nil {
				return fmt.Errorf("signing metadata failed: %s", err)
			}
			filename := fmt.Sprintf("%s.json", name)
			err = trusted.Timestamp.ToFile(filepath.Join(cfg.LocalMetadataDir, filename), true)
		}
		if err != nil {
			return fmt.Errorf("saving metadata to file failed: %s", err)
		}
	}

	fmt.Printf("Added %s\n", targetPath)
	return nil
}
