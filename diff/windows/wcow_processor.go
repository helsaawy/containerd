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
	"io"
	"sync"

	"github.com/Microsoft/go-winio"
	"github.com/containerd/containerd/diff"
	"github.com/containerd/containerd/errdefs"
	"github.com/gogo/protobuf/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Microsoft/hcsshim/cmd/differ/mediatype"
	"github.com/Microsoft/hcsshim/cmd/differ/payload"
	"github.com/Microsoft/hcsshim/pkg/ociwclayer"
)

const (
	wcowWCLayerID = "io.containerd.processor.v1.windows.wcow.wclayer"
)

func init() {
	diff.RegisterProcessor(wclayerHandler)
}

func wclayerHandler(_ context.Context, mediaType string) (diff.StreamProcessorInit, bool) {
	if mediaType != addExtension(ocispec.MediaTypeImageLayer, mediatype.ExtensionWCOW) {
		return nil, false
	}
	spi := func(ctx context.Context, stream diff.StreamProcessor, payloads map[string]*types.Any) (diff.StreamProcessor, error) {
		p := payloads[wcowWCLayerID]
		return newWCLayerProcessor(ctx, stream, p)
	}
	return spi, true
}

type wclayerProcessor struct {
	in      io.Reader
	root    string
	parents []string

	done chan struct{}
	mu   sync.Mutex
	err  error
}

var _ diff.StreamProcessor = &wclayerProcessor{}

func newWCLayerProcessor(ctx context.Context, stream diff.StreamProcessor, pd *types.Any) (_ diff.StreamProcessor, err error) {
	if pd == nil {
		return nil, fmt.Errorf("tar2ext4 options not found: %w", errdefs.ErrNotFound)
	}

	opts := &payload.WCLayerImportOptions{}
	if err = opts.FromAny(pd); err != nil {
		return nil, err
	}

	var in io.Reader
	if f, ok := stream.(diff.RawProcessor); ok {
		ff := f.File()
		defer ff.Close()
		in = ff
	} else {
		in = stream
	}

	p := &wclayerProcessor{
		in:      in,
		root:    opts.RootPath,
		parents: opts.Parents,
		done:    make(chan struct{}),
	}

	go func() {
		defer close(p.done)
		if err := p.start(ctx); err != nil {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.err = err
		}
	}()

	return p, nil
}

func (p *wclayerProcessor) start(ctx context.Context) error {
	// TODO darrenstahlmsft: When this is done isolated, we should disable these.
	// it currently cannot be disabled, unless we add ref counting. Since this is
	// temporary, leaving it enabled is OK for now.
	// https://github.com/containerd/containerd/issues/1681
	if err := winio.EnableProcessPrivileges([]string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}); err != nil {
		return err
	}

	if _, err := ociwclayer.ImportLayerFromTar(ctx, p.in, p.root, p.parents); err != nil {
		return err
	}
	// copy out remaining data
	_, _ = io.Copy(io.Discard, p.in)

	return nil
}

func (p *wclayerProcessor) MediaType() string {
	return mediatype.MediaTypeMicrosoftImageLayerWCLayer
}

func (p *wclayerProcessor) Read([]byte) (int, error) {
	<-p.done
	return 0, io.EOF
}

func (p *wclayerProcessor) Close() error {
	return nil
}

func (p *wclayerProcessor) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}
