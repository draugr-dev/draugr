package sealed

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ServedImage is the reference a scenario's image/ tree is served under, for a descriptor to name.
func ServedImage(scenario string) string { return ServedAddr + "/" + scenario + ":1.0" }

// ServeImage writes the scenario's image/ tree into served as ServedImage(s.Name), and does
// nothing for a scenario without one.
func (s Scenario) ServeImage(served string) error {
	src := filepath.Join(s.Dir, "image")
	if _, err := os.Stat(src); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return WriteServedImage(served, s.Name, "1.0", src)
}

// WriteServedImage writes the tree under src as a single-layer linux/amd64 OCI image into served,
// laid out the way ServedHandler answers the registry API: the manifest under
// /v2/<name>/manifests/<tag> and each blob under /v2/<name>/blobs/<digest>. The layer is written
// with fixed timestamps and owners, so the image, and every digest a report records, is the same
// on every run.
func WriteServedImage(served, name, tag, src string) error {
	layer, diffID, err := layerOf(src)
	if err != nil {
		return err
	}
	config, err := json.Marshal(map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"config":       map[string]any{},
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{diffID}},
	})
	if err != nil {
		return err
	}
	dir := filepath.Join(served, "v2", filepath.FromSlash(name))
	configDesc, err := writeBlob(dir, "application/vnd.oci.image.config.v1+json", config)
	if err != nil {
		return err
	}
	layerDesc, err := writeBlob(dir, "application/vnd.oci.image.layer.v1.tar+gzip", layer)
	if err != nil {
		return err
	}
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        configDesc,
		"layers":        []any{layerDesc},
	})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(manifest)
	manifests := filepath.Join(dir, "manifests")
	if err := os.MkdirAll(manifests, 0o750); err != nil {
		return err
	}
	// Under the tag and under the digest, which is what a client asks for once it has pinned one.
	for _, ref := range []string{tag, "sha256:" + hex.EncodeToString(sum[:])} {
		if err := os.WriteFile(filepath.Join(manifests, ref), manifest, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// layerOf returns the tree under src as a gzipped tar and the digest of the tar before
// compression, which is what an image config lists as the layer's diff_id.
func layerOf(src string) ([]byte, string, error) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	epoch := time.Unix(0, 0).UTC()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == src {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(filepath.ToSlash(rel), FixtureSuffix)
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: 0o755, ModTime: epoch})
		}
		body, err := os.ReadFile(p) // #nosec G304 G122 -- a file under the scenario's own directory
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body)), ModTime: epoch}); err != nil {
			return err
		}
		_, err = tw.Write(body)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}
	diff := sha256.Sum256(raw.Bytes())
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return gz.Bytes(), "sha256:" + hex.EncodeToString(diff[:]), nil
}

// writeBlob writes body under dir/blobs by its digest and returns its descriptor.
func writeBlob(dir, mediaType string, body []byte) (map[string]any, error) {
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	blobs := filepath.Join(dir, "blobs")
	if err := os.MkdirAll(blobs, 0o750); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(blobs, digest), body, 0o600); err != nil {
		return nil, fmt.Errorf("blob %s: %w", digest, err)
	}
	return map[string]any{"mediaType": mediaType, "digest": digest, "size": len(body)}, nil
}
