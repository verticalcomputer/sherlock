package collectorruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const coolingStateFile = ".cooling-state.json"
const coolingStateTemp = ".cooling-state.tmp"

type coolingAppliedState struct {
	ProfileID   string             `json:"profile_id"`
	Revision    int64              `json:"revision"`
	Hash        string             `json:"hash"`
	CollectorID domain.CollectorID `json:"collector_id"`
	ClusterID   domain.ClusterID   `json:"cluster_id"`
	SourceID    domain.SourceID    `json:"source_id"`
	State       string             `json:"state"`
}

// applyCoolingUploadState runs under the spool's exclusive process lock before
// any source read. An installed old file must not undo a durable disable after
// restart. This local receipt does not claim that central knows it was applied.
func applyCoolingUploadState(dir string, p domain.CoolingUploadProfile, hash string) error {
	path := filepath.Join(dir, coolingStateFile)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 4096 {
			return fmt.Errorf("invalid local cooling applied state")
		}
		body, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(body) > 4096 {
			return fmt.Errorf("invalid local cooling applied state")
		}
		var prior coolingAppliedState
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&prior) != nil || decoder.Decode(new(any)) != io.EOF || prior.Revision < 1 || (prior.State != "ENABLED" && prior.State != "DISABLED") {
			return fmt.Errorf("invalid local cooling applied state")
		}
		if p.Version != domain.CoolingUploadProductionVersion || prior.ProfileID != p.ProfileID || prior.CollectorID != p.CollectorID || prior.ClusterID != p.ClusterID || prior.SourceID != p.SourceID || p.Revision < prior.Revision {
			return fmt.Errorf("cooling profile regresses or changes durable local authority")
		}
		if p.Revision == prior.Revision {
			if hash != prior.Hash || p.State != prior.State {
				return fmt.Errorf("cooling revision changed immutable local content")
			}
			return nil
		}
	}
	if p.Version != domain.CoolingUploadProductionVersion {
		return nil
	}
	state := coolingAppliedState{p.ProfileID, p.Revision, hash, p.CollectorID, p.ClusterID, p.SourceID, p.State}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temp := filepath.Join(dir, coolingStateTemp)
	// The directory is private and process-locked; remove only our fixed prior
	// temporary file left by a crash. Never follow a temporary symlink.
	if info, err := os.Lstat(temp); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("invalid cooling state temporary entry")
		}
		if err := os.Remove(temp); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	out, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	if _, err = out.Write(body); err != nil {
		out.Close()
		return err
	}
	if err = out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
