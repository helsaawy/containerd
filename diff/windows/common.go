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
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/Microsoft/hcsshim/cmd/differ/mediatype"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/diff"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/types"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

var (
	emptyDesc    = ocispec.Descriptor{}
	uncompressed = "containerd.io/uncompressed"
	differID     = "io.containerd.processor.v1.windows.differ"
)

const (
	ForceIsolated             = diff.LabelPrefix + "io.microsoft.isolated"
	LCOWLayerIntegrityEnabled = diff.LabelPrefix + "io.microsoft.lcow.append-dm-verity"
)

// TODO: add noop stream processor for uncompressed streams in the case when isolated is true

// convenience interface for binary processors that return an Err for their stderr and exit code
type errorProcessor interface {
	diff.StreamProcessor
	Err() error
}

// convenience interface for processors that expose Wait(ctx) error
type waitProcessor interface {
	diff.StreamProcessor
	Wait(context.Context) error
}

// windowsDiffBase does filesystem comparison and application
// for Windows specific Linux layer diffs.
type windowsDiffBase struct {
	store content.Store
	// mtExt is extension added to ocispec.MediaTypeImageLayer to select the final conversion
	// processor. Ie, "lcow" or "wcow".
	mtExt string
	// finalMT is the media type output by final conversion processor
	finalMT string
	// mntType is the expected mount type
	mntType string
}

func (s *windowsDiffBase) applyCommon(ctx context.Context, desc ocispec.Descriptor, _ []mount.Mount, opts ...diff.ApplyOpt) (d ocispec.Descriptor, err error) {
	config := diff.ApplyConfig{
		ProcessorPayloads: make(map[string]*types.Any),
	}
	for _, o := range opts {
		if err := o(ctx, desc, &config); err != nil {
			return emptyDesc, fmt.Errorf("failed to apply config opt: %w", err)
		}
	}

	mt := desc.MediaType
	mtLayer := ocispec.MediaTypeImageLayer
	finalMT := s.finalMT
	if isolated, _ := parseBoolPayload(config.ProcessorPayloads[ForceIsolated]); isolated {
		mt = addIsolatedExtension(mt)
		mtLayer = addIsolatedExtension(mtLayer)
		finalMT = addIsolatedExtension(s.finalMT)
		log.G(ctx).WithFields(logrus.Fields{
			"mt":      mt,
			"mtlayer": mtLayer,
			"mtvhd":   finalMT,
		}).Debug("using isolated processors")
	}
	log.G(ctx).WithFields(logrus.Fields{
		"desc": fmt.Sprintf("%#+v", desc),
	}).Info("lcow apply")

	ra, err := s.store.ReaderAt(ctx, desc)
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to get reader from content store: %w", err)
	}
	defer ra.Close()

	processor := diff.NewProcessorChain(mt, content.NewReader(ra))
	defer func() {
		if processor != nil {
			processor.Close()
		}
	}()

	var processors []diff.StreamProcessor
	processors = append(processors, processor)
	for {
		if processor, err = diff.GetProcessor(ctx, processor, config.ProcessorPayloads); err != nil {
			return emptyDesc, fmt.Errorf("failed to get stream processor for %s: %w", mt, err)
		}
		processors = append(processors, processor)
		if processor.MediaType() == mtLayer {
			break
		}
	}

	digester := digest.Canonical.Digester()
	rc := &readCounter{
		r: io.TeeReader(processor, digester.Hash()),
	}
	processor = &passthuProcessor{
		r:  rc,
		mt: addExtension(processor.MediaType(), s.mtExt),
	}

	for {
		if processor, err = diff.GetProcessor(ctx, processor, config.ProcessorPayloads); err != nil {
			return emptyDesc, fmt.Errorf("failed to get stream processor for %s: %w", mt, err)
		}
		processors = append(processors, processor)
		if processor.MediaType() == finalMT {
			break
		}
	}

	// both conversions (tar2ext4 and wclayer.ImportFromTar) need a ReadWriteSeeker, so they
	//  cannot write directly to stdout.
	// so options are either to buffer data in memory and copy VHD contents into this
	// process and then write to disk, or have the  the stream processor
	// write directly to the file.

	// conversion step processor is a sink, so wait for it to return
	if _, err := io.Copy(io.Discard, processor); err != nil {
		return emptyDesc, err
	}

	// If one processor paniced or crashed, previous processors may hang on writing out.
	// Close all processors to force completion.
	for _, p := range processors {
		p.Close()
	}

	// A processor may error if it was closed prematurely by a subsequent processor crashing
	// Aggregate all errors together
	// TODO: add a multierror
	perrs := make([]string, 0, len(processors))
	for _, p := range processors {
		// wait should ruetrn the exit error, so only do one or the other
		if wp, ok := p.(waitProcessor); ok {
			if err := wp.Wait(ctx); err != nil {
				perrs = append(perrs, fmt.Errorf("processor %s: %w", p.MediaType(), err).Error())
			}
		} else if ep, ok := p.(errorProcessor); ok {
			if err := ep.Err(); err != nil {
				perrs = append(perrs, fmt.Errorf("processor %s: %w", p.MediaType(), err).Error())
			}
		}
	}
	if len(perrs) > 0 {
		return emptyDesc, errors.New(strings.Join(perrs, "; "))
	}

	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayer,
		Size:      rc.c,
		Digest:    digester.Digest(),
	}, nil
}

func (s *windowsDiffBase) mountsToLayerAndParents(mounts []mount.Mount) (string, []string, error) {
	if len(mounts) != 1 {
		return "", nil, fmt.Errorf("number of mounts should always be 1 for Windows %s mounts: %w", s.mntType, errdefs.ErrInvalidArgument)
	}
	mnt := mounts[0]
	if mnt.Type != s.mntType {
		// The service plugin (services/diff/local.go) iterates through all registered differs, continuing
		// to the next one if the differ returns ErrNotImplemented.
		return "", nil, fmt.Errorf("layer mount type must be %s, not %s: %w", s.mntType, mnt.Type, errdefs.ErrNotImplemented)
	}

	parentLayerPaths, err := mnt.GetParentPaths()
	if err != nil {
		return "", nil, err
	}

	return mnt.Source, parentLayerPaths, nil
}

type readCounter struct {
	r io.Reader
	c int64
}

func (rc *readCounter) Read(p []byte) (n int, err error) {
	n, err = rc.r.Read(p)
	rc.c += int64(n)
	return
}

// changes the media type of a processor
// useful for adding an extension to force choosing a certain (type of) processor
type passthuProcessor struct {
	r  io.Reader
	mt string
}

var _ diff.StreamProcessor = &passthuProcessor{}

func (p *passthuProcessor) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func (p *passthuProcessor) Close() error {
	return nil
}

func (p *passthuProcessor) MediaType() string {
	return p.mt
}

func parseBoolPayload(p *types.Any) (bool, error) {
	if p == nil {
		return false, errdefs.ErrNotFound
	}

	v, err := typeurl.UnmarshalAny(p)
	if err != nil {
		return false, fmt.Errorf("unmarshalling payload %+v: %w", p, err)
	}

	s, ok := v.(*types.StringValue)
	if !ok {
		return false, fmt.Errorf("payload is %T, not types.StringValue: %w", p.TypeUrl, errdefs.ErrInvalidArgument)
	}

	b, err := strconv.ParseBool(s.Value)
	if err != nil {
		return false, fmt.Errorf("payload %q parsing as bool failed: %w", s.Value, err)
	}

	return b, nil
}

func addIsolatedExtension(mt string) string {
	return addExtension(mt, mediatype.ExtensionIsolated)
}

func addExtension(mt string, ext string) string {
	b, exts := parseMediaTypes(mt)
	for _, e := range exts {
		if e == ext {
			return mt
		}
	}
	exts = append(exts, ext)
	return unparseMediaTypes(b, exts)
}

// parseMediaTypes splits the media type into the base type and
// an array of extensions
//
// copied from github.com/containerd/containerd/images/mediatypes.go
func parseMediaTypes(mt string) (string, []string) {
	if mt == "" {
		return "", []string{}
	}

	s := strings.Split(mt, "+")
	ext := s[1:]

	return s[0], ext
}

// unparseMediaTypes joins together the base media type and the sorted extensions
func unparseMediaTypes(base string, ext []string) string {
	sort.Strings(ext)
	s := []string{base}
	s = append(s, ext...)

	return strings.Join(s, "+")
}
