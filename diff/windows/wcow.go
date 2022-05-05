//go:build windows
// +build windows

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package windows

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	winio "github.com/Microsoft/go-winio"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/diff"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"

	"github.com/Microsoft/hcsshim/cmd/differ/mediatype"
	"github.com/Microsoft/hcsshim/cmd/differ/payload"
)

// windowsWCOWDiff does filesystem comparison and application
// for Windows specific layer diffs.
type windowsWCOWDiff struct {
	windowsDiffBase
}

var _ containerd.DiffService = windowsWCOWDiff{}

// NewWindowsWCOWDiff is the Windows container layer implementation
// for comparing and applying filesystem layers
func NewWindowsWCOWDiff(store content.Store) (containerd.DiffService, error) {
	return windowsWCOWDiff{
		windowsDiffBase: windowsDiffBase{
			store:   store,
			mtExt:   mediatype.ExtensionWCOW,
			finalMT: mediatype.MediaTypeMicrosoftImageLayerWCLayer,
			mntType: "windows-layer",
		},
	}, nil
}

// Apply applies the content associated with the provided digests onto the
// provided mounts. Archive content will be extracted and decompressed if
// necessary.
func (s windowsWCOWDiff) Apply(ctx context.Context, desc ocispec.Descriptor, mounts []mount.Mount, opts ...diff.ApplyOpt) (d ocispec.Descriptor, err error) {
	t1 := time.Now()
	ctx = log.WithLogger(ctx, log.G(ctx).WithField("differ", "windowsWCOWDiff"))
	defer func() {
		if err == nil {
			log.G(ctx).WithFields(logrus.Fields{
				"d":      time.Since(t1).String(),
				"digest": desc.Digest,
				"size":   desc.Size,
				"media":  desc.MediaType,
			}).Debug("diff applied")
		}
	}()

	// quit early if the mount type is not windows-layer
	layer, parentLayerPaths, err := s.mountsToLayerAndParents(mounts)
	if err != nil {
		return emptyDesc, err
	}

	o := func(_ context.Context, _ ocispec.Descriptor, c *diff.ApplyConfig) error {
		wclayerOpts := payload.WCLayerImportOptions{
			RootPath: layer,
			Parents:  parentLayerPaths,
		}
		if c.ProcessorPayloads[wcowWCLayerID], err = wclayerOpts.ToAny(); err != nil {
			return fmt.Errorf("failed to marshal payload %T: %w", wclayerOpts, err)
		}
		return nil
	}

	return s.applyCommon(ctx, desc, mounts, append(opts, o)...)
}

// Compare creates a diff between the given mounts and uploads the result
// to the content store.
func (s windowsWCOWDiff) Compare(ctx context.Context, lower, upper []mount.Mount, opts ...diff.Opt) (d ocispec.Descriptor, err error) {
	t1 := time.Now()

	var config diff.Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return emptyDesc, err
		}
	}

	layers, err := s.mountPairToLayerStack(lower, upper)
	if err != nil {
		return emptyDesc, err
	}

	if config.MediaType == "" {
		config.MediaType = ocispec.MediaTypeImageLayerGzip
	}

	var isCompressed bool
	switch config.MediaType {
	case ocispec.MediaTypeImageLayer:
	case ocispec.MediaTypeImageLayerGzip:
		isCompressed = true
	default:
		return emptyDesc, fmt.Errorf("unsupported diff media type: %v: %w", config.MediaType, errdefs.ErrNotImplemented)
	}

	newReference := false
	if config.Reference == "" {
		newReference = true
		config.Reference = uniqueRef()
	}

	cw, err := s.store.Writer(ctx, content.WithRef(config.Reference), content.WithDescriptor(ocispec.Descriptor{
		MediaType: config.MediaType,
	}))

	if err != nil {
		return emptyDesc, fmt.Errorf("failed to open writer: %w", err)
	}

	defer func() {
		if err != nil {
			cw.Close()
			if newReference {
				if abortErr := s.store.Abort(ctx, config.Reference); abortErr != nil {
					log.G(ctx).WithError(abortErr).WithField("ref", config.Reference).Warnf("failed to delete diff upload")
				}
			}
		}
	}()

	if !newReference {
		if err = cw.Truncate(0); err != nil {
			return emptyDesc, err
		}
	}

	// TODO darrenstahlmsft: When this is done isolated, we should disable this.
	// it currently cannot be disabled, unless we add ref counting. Since this is
	// temporary, leaving it enabled is OK for now.
	// https://github.com/containerd/containerd/issues/1681
	if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege}); err != nil {
		return emptyDesc, err
	}

	if isCompressed {
		dgstr := digest.SHA256.Digester()
		var compressed io.WriteCloser
		compressed, err = compression.CompressStream(cw, compression.Gzip)
		if err != nil {
			return emptyDesc, fmt.Errorf("failed to get compressed stream: %w", err)
		}
		err = archive.WriteDiff(ctx, io.MultiWriter(compressed, dgstr.Hash()), "", layers[0], archive.AsWindowsContainerLayerPair(), archive.WithParentLayers(layers[1:]))
		compressed.Close()
		if err != nil {
			return emptyDesc, fmt.Errorf("failed to write compressed diff: %w", err)
		}

		if config.Labels == nil {
			config.Labels = map[string]string{}
		}
		config.Labels[uncompressed] = dgstr.Digest().String()
	} else {
		if err = archive.WriteDiff(ctx, cw, "", layers[0], archive.AsWindowsContainerLayerPair(), archive.WithParentLayers(layers[1:])); err != nil {
			return emptyDesc, fmt.Errorf("failed to write diff: %w", err)
		}
	}

	var commitopts []content.Opt
	if config.Labels != nil {
		commitopts = append(commitopts, content.WithLabels(config.Labels))
	}

	dgst := cw.Digest()
	if err := cw.Commit(ctx, 0, dgst, commitopts...); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return emptyDesc, fmt.Errorf("failed to commit: %w", err)
		}
	}

	info, err := s.store.Info(ctx, dgst)
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to get info from content store: %w", err)
	}
	if info.Labels == nil {
		info.Labels = make(map[string]string)
	}
	// Set uncompressed label if digest already existed without label
	if _, ok := info.Labels[uncompressed]; !ok {
		info.Labels[uncompressed] = config.Labels[uncompressed]
		if _, err := s.store.Update(ctx, info, "labels."+uncompressed); err != nil {
			return emptyDesc, fmt.Errorf("error setting uncompressed label: %w", err)
		}
	}

	desc := ocispec.Descriptor{
		MediaType: config.MediaType,
		Size:      info.Size,
		Digest:    info.Digest,
	}

	log.G(ctx).WithFields(logrus.Fields{
		"d":     time.Since(t1),
		"dgst":  desc.Digest,
		"size":  desc.Size,
		"media": desc.MediaType,
	}).Debug("diff created")

	return desc, nil
}

// wcowMountPairToLayerStack ensures that the two sets of mount-lists are actually a correct
// parent-and-child, or orphan-and-empty-list, and return the full list of layers, starting
// with the upper-most (most childish?)
func (s *windowsWCOWDiff) mountPairToLayerStack(lower, upper []mount.Mount) ([]string, error) {
	// May return an ErrNotImplemented, which will fall back to LCOW
	upperLayer, upperParentLayerPaths, err := s.mountsToLayerAndParents(upper)
	if err != nil {
		return nil, fmt.Errorf("upper mount invalid: %w", err)
	}

	// Trivial case, diff-against-nothing
	if len(lower) == 0 {
		if len(upperParentLayerPaths) != 0 {
			return nil, fmt.Errorf("windowsWCOWDiff cannot diff a layer with parents against a null layer: %w", errdefs.ErrInvalidArgument)
		}
		return []string{upperLayer}, nil
	}

	if len(upperParentLayerPaths) < 1 {
		return nil, fmt.Errorf("windowsWCOWDiff cannot diff a layer with no parents against another layer: %w", errdefs.ErrInvalidArgument)
	}

	lowerLayer, lowerParentLayerPaths, err := s.mountsToLayerAndParents(lower)
	if errdefs.IsNotImplemented(err) {
		// Upper was a windows-layer, lower is not. We can't handle that.
		return nil, fmt.Errorf("windowsWCOWDiff cannot diff a windows-layer against a non-windows-layer: %w", errdefs.ErrInvalidArgument)
	} else if err != nil {
		return nil, fmt.Errorf("Lower mount invalid: %w", err)
	}

	if upperParentLayerPaths[0] != lowerLayer {
		return nil, fmt.Errorf("windowsWCOWDiff cannot diff a layer against a layer other than its own parent: %w", errdefs.ErrInvalidArgument)
	}

	if len(upperParentLayerPaths) != len(lowerParentLayerPaths)+1 {
		return nil, fmt.Errorf("windowsWCOWDiff cannot diff a layer against a layer with different parents: %w", errdefs.ErrInvalidArgument)
	}
	for i, upperParent := range upperParentLayerPaths[1:] {
		if upperParent != lowerParentLayerPaths[i] {
			return nil, fmt.Errorf("windowsWCOWDiff cannot diff a layer against a layer with different parents: %w", errdefs.ErrInvalidArgument)
		}
	}

	return append([]string{upperLayer}, upperParentLayerPaths...), nil
}

func uniqueRef() string {
	t := time.Now()
	var b [3]byte
	// Ignore read failures, just decreases uniqueness
	rand.Read(b[:])
	return fmt.Sprintf("%d-%s", t.UnixNano(), base64.URLEncoding.EncodeToString(b[:]))
}
