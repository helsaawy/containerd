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
	"os"
	"sync"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	"github.com/containerd/containerd/diff"
	"github.com/containerd/containerd/errdefs"
	"github.com/gogo/protobuf/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Microsoft/hcsshim/cmd/differ/mediatype"
	"github.com/Microsoft/hcsshim/cmd/differ/payload"
)

const (
	lcowTar2Ext4ID = "io.containerd.processor.v1.windows.lcow.tar2ext4"
)

func init() {
	diff.RegisterProcessor(tar2ext4Handler)
}

func tar2ext4Handler(_ context.Context, mediaType string) (diff.StreamProcessorInit, bool) {
	if mediaType != addExtension(ocispec.MediaTypeImageLayer, mediatype.ExtensionLCOW) {
		return nil, false
	}
	spi := func(ctx context.Context, stream diff.StreamProcessor, payloads map[string]*types.Any) (diff.StreamProcessor, error) {
		p := payloads[lcowTar2Ext4ID]
		return newT2E4Processor(ctx, stream, p)
	}
	return spi, true
}

type ext4Processor struct {
	in  io.Reader
	vhd *os.File

	done chan struct{}
	mu   sync.Mutex
	err  error
}

var _ diff.StreamProcessor = &ext4Processor{}

func newT2E4Processor(ctx context.Context, stream diff.StreamProcessor, pd *types.Any) (_ diff.StreamProcessor, err error) {
	if pd == nil {
		return nil, fmt.Errorf("tar2ext4 options not found: %w", errdefs.ErrNotFound)
	}

	opts := &payload.Tar2Ext4Options{}
	if err = opts.FromAny(pd); err != nil {
		return nil, err
	}

	var vhd *os.File
	if vhd, err = os.Create(opts.VHDPath); err != nil {
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

	p := &ext4Processor{
		in:   in,
		vhd:  vhd,
		done: make(chan struct{}),
	}

	go func() {
		defer close(p.done)
		if err := p.start(ctx, opts.Options()); err != nil {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.err = err
		}
	}()

	return p, nil
}

func (p *ext4Processor) start(_ context.Context, opts []tar2ext4.Option) error {
	if err := tar2ext4.Convert(p.in, p.vhd, opts...); err != nil {
		return err
	}
	if err := p.vhd.Sync(); err != nil {
		return err
	}
	// copy out remaining data
	_, _ = io.Copy(io.Discard, p.in)

	return nil
}

func (p *ext4Processor) MediaType() string {
	return mediatype.MediaTypeMicrosoftImageLayerExt4
}

func (p *ext4Processor) Read([]byte) (int, error) {
	<-p.done
	return 0, io.EOF
}

func (p *ext4Processor) Close() error {
	return p.vhd.Close()
}

func (p *ext4Processor) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}
