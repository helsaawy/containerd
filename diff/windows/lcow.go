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
	"fmt"
	"os"
	"path"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/diff"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"

	"github.com/Microsoft/hcsshim/cmd/differ/mediatype"
	"github.com/Microsoft/hcsshim/cmd/differ/payload"
)

// maxLCOWVhdSizeGB is the max size in GB of any layer
const maxLCOWVhdSizeGB = 128 * 1024 * 1024 * 1024

// windowsLCOWDiff does filesystem comparison and application
// for Windows specific Linux layer diffs.
type windowsLCOWDiff struct {
	windowsDiffBase
}

var _ containerd.DiffService = &windowsLCOWDiff{}

// NewWindowsLCOWDiff is the Windows LCOW container layer implementation
// for comparing and applying Linux filesystem layers on Windows
func NewWindowsLCOWDiff(store content.Store) (containerd.DiffService, error) {
	return &windowsLCOWDiff{
		windowsDiffBase: windowsDiffBase{
			store:   store,
			mtExt:   mediatype.ExtensionLCOW,
			finalMT: mediatype.MediaTypeMicrosoftImageLayerExt4,
			mntType: "lcow-layer",
		},
	}, nil
}

// Apply applies the content associated with the provided digests onto the
// provided mounts. Archive content will be extracted and decompressed if
// necessary.
func (s *windowsLCOWDiff) Apply(ctx context.Context, desc ocispec.Descriptor, mounts []mount.Mount, opts ...diff.ApplyOpt) (d ocispec.Descriptor, err error) {
	t1 := time.Now()
	ctx = log.WithLogger(ctx, log.G(ctx).WithField("differ", "windowsLCOWDiff"))
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

	// quit early if the mount type is not lcow-layer
	layer, _, err := s.mountsToLayerAndParents(mounts)
	if err != nil {
		return emptyDesc, err
	}

	vhd, err := os.Create(path.Join(layer, "layer.vhd"))
	if err != nil {
		return emptyDesc, fmt.Errorf("could not create vhd for layer %s: %w", layer, err)
	}
	vhd.Close()
	defer func() {
		if err != nil {
			os.Remove(vhd.Name())
		}
	}()

	o := func(_ context.Context, _ ocispec.Descriptor, c *diff.ApplyConfig) error {
		opts := payload.Tar2Ext4Options{
			ConvertWhiteout: true,
			AppendVhdFooter: true,
			MaximumDiskSize: maxLCOWVhdSizeGB,
			VHDPath:         vhd.Name(),
		}

		opts.AppendDMVerity, _ = parseBoolPayload(c.ProcessorPayloads[LCOWLayerIntegrityEnabled])
		if c.ProcessorPayloads[lcowTar2Ext4ID], err = opts.ToAny(); err != nil {
			return fmt.Errorf("failed to marshal payload %T: %w", opts, err)
		}
		return nil
	}

	return s.applyCommon(ctx, desc, mounts, append(opts, o)...)
}

// Compare creates a diff between the given mounts and uploads the result
// to the content store.
func (*windowsLCOWDiff) Compare(ctx context.Context, lower, upper []mount.Mount, opts ...diff.Opt) (ocispec.Descriptor, error) {
	return emptyDesc, fmt.Errorf("windowsLCOWDiff does not implement Compare method: %w", errdefs.ErrNotImplemented)
}
