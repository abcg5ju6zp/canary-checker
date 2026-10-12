package publication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	artifactslib "github.com/flanksource/artifacts"
	artifactFS "github.com/flanksource/artifacts/fs"
)

// verifiedObject is the result of writing an object whose complete byte
// stream has been seen and verified.
type verifiedObject struct {
	size        int64
	checksum    string
	contentType string
	name        string
}

type countingWriter struct {
	count int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.count += int64(len(p))
	return len(p), nil
}

// writeVerifiedObject streams data to fs at key while computing its sha256
// and exact size, then confirms the stored object matches what was sent.
//
// If the write response is uncertain (timeout, dropped connection), the
// object is reconciled with Stat before failing: when the object landed in
// full, the call succeeds instead of re-uploading. That reconciliation is
// what lets retries and service restarts resume an upload whose response was
// lost without duplicating or losing content.
func writeVerifiedObject(ctx context.Context, fs artifactFS.FilesystemRW, key string, data artifactslib.Artifact) (*verifiedObject, error) {
	defer func() { _ = data.Content.Close() }()

	checksum := sha256.New()
	counter := &countingWriter{}

	// Chain: writer reads -> mime sniffer -> byte counter -> sha256 -> source.
	hashed := io.TeeReader(data.Content, checksum)
	counted := io.TeeReader(hashed, counter)
	mimeWriter := &artifactslib.MIMEWriter{Max: 512 * 1024}
	reader := io.TeeReader(counted, mimeWriter)

	info, writeErr := fs.Write(ctx, key, reader)
	if writeErr != nil {
		// Response may have been lost after the object fully landed.
		if existing, ok := objectLanded(fs, key, counter.count); ok {
			existing.checksum = hex.EncodeToString(checksum.Sum(nil))
			existing.contentType = contentTypeOrDefault(data.ContentType, mimeWriter)
			return existing, nil
		}
		return nil, fmt.Errorf("error writing object %s: %w", key, writeErr)
	}

	if info == nil {
		return nil, fmt.Errorf("object %s write returned no object info", key)
	}

	// Verify size through the backend metadata one more time.
	if info.Size() != counter.count {
		return nil, fmt.Errorf("object %s is incomplete: streamed=%d stored=%d", key, counter.count, info.Size())
	}

	return &verifiedObject{
		size:        counter.count,
		checksum:    hex.EncodeToString(checksum.Sum(nil)),
		contentType: contentTypeOrDefault(data.ContentType, mimeWriter),
		name:        info.Name(),
	}, nil
}

func contentTypeOrDefault(provided string, mimeWriter *artifactslib.MIMEWriter) string {
	if provided != "" {
		return provided
	}
	return mimeWriter.Detect().String()
}

func objectLanded(fs artifactFS.FilesystemRW, key string, expectedSize int64) (*verifiedObject, bool) {
	info, err := fs.Stat(key)
	if err != nil || info == nil {
		return nil, false
	}
	// A zero-byte expectation means the stream never produced evidence of
	// what complete content looks like; it cannot be verified.
	if expectedSize <= 0 || info.Size() != expectedSize {
		return nil, false
	}
	return &verifiedObject{size: info.Size(), name: info.Name()}, true
}

// reconcileObject confirms an object at key still exists with the expected
// size. Used when resuming an interrupted publication.
func reconcileObject(fs artifactFS.FilesystemRW, key string, expectedSize int64) error {
	info, err := fs.Stat(key)
	if err != nil {
		return fmt.Errorf("unable to reconcile object %s: %w", key, err)
	}
	if info == nil {
		return fmt.Errorf("object %s not found", key)
	}
	if info.Size() != expectedSize {
		return fmt.Errorf("object %s size mismatch: expected=%d stored=%d", key, expectedSize, info.Size())
	}
	return nil
}
