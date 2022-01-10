// +build windows

/*
Copyright 2017 The Kubernetes Authors.

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

package io

import (
	"io"
	"net"
	"sync"

	winio "github.com/Microsoft/go-winio"
	"github.com/containerd/containerd/cio"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

// delayedConnection is a io.ReadWriteCloser that takes a net.Listener, calls Accept on it, and
// then blocks any Read/Write/Close operations until a connection has been established. It is
// created by calling newDelayedConnection, and the context.Context passed to that function can
// be canceled to abort the Accept call.
type delayedConnection struct {
	con net.Conn
	// listenDoneCh is closed when listening is complete. This means the delayedConnection
	// will either be in a connected state, or an error state.
	listenDoneCh chan struct{}
	listenErr    error
	// closeCh is closed to indicate to waitListener that listening should be aborted.
	closeCh chan struct{}
}

func (dc *delayedConnection) Write(p []byte) (int, error) {
	<-dc.listenDoneCh
	if dc.listenErr != nil {
		return 0, errors.Wrap(dc.listenErr, "connection failed")
	}
	return dc.con.Write(p)
}

func (dc *delayedConnection) Read(p []byte) (int, error) {
	<-dc.listenDoneCh
	if dc.listenErr != nil {
		return 0, errors.Wrap(dc.listenErr, "connection failed")
	}
	return dc.con.Read(p)
}

// waitListener runs as a separate goroutine and manages the listener
// for the delayedConnection.
func (dc *delayedConnection) waitListener(ctx context.Context, l net.Listener) {
	// We block this entire function on Accept below, and only unblock when either the
	// listener successfully connects, or if an error is encountered.
	// We can force unblock the Accept by closing the listener, which is done by the
	// goroutine below in several cases.
	ch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done(): // Context hit deadline or canceled.
		case <-dc.closeCh: // Close was called.
		case <-ch: // Accept finished properly.
		}
		l.Close()
	}()
	con, acceptErr := l.Accept()
	// Unblock the goroutine above. It's okay for it to close the listener now, we don't need it
	// anymore.
	close(ch)
	if err := ctx.Err(); err != nil {
		// If the context was canceled, use its error instead of the one from Accept. This ensures
		// Read/Write will return an error like "connection failed: context deadline exceeded".
		dc.listenErr = err
		if con != nil {
			con.Close()
		}
	} else {
		// Otherwise, use the con/err returned from Accept. In the case where Accept was unblocked
		// by closing the listener, error should be something like "use of closed network connection".
		dc.con = con
		dc.listenErr = acceptErr
	}
	// Unblock anyone waiting for listening to be done.
	close(dc.listenDoneCh)
}

func (dc *delayedConnection) Close() error {
	// If we have already closed closeCh, then all the work is already done. Just return an
	// "already closed" error.
	select {
	case <-dc.closeCh:
		return errors.New("connection is already closed")
	default:
	}
	close(dc.closeCh)
	<-dc.listenDoneCh
	var err error
	if dc.con != nil {
		err = dc.con.Close()
	}
	return err
}

func newDelayedConnection(ctx context.Context, path string) (io.ReadWriteCloser, error) {
	l, err := winio.ListenPipe(path, nil)
	if err != nil {
		return nil, err
	}
	dc := &delayedConnection{
		listenDoneCh: make(chan struct{}),
		closeCh:      make(chan struct{}),
	}
	go dc.waitListener(ctx, l)
	return dc, nil
}

// newStdioPipes creates actual fifos for stdio.
func newStdioPipes(fifos *cio.FIFOSet) (_ *stdioPipes, _ *wgCloser, err error) {
	var (
		f           io.ReadWriteCloser
		set         []io.Closer
		ctx, cancel = context.WithCancel(context.Background())
		p           = &stdioPipes{}
	)
	defer func() {
		if err != nil {
			for _, f := range set {
				f.Close()
			}
			cancel()
		}
	}()

	if fifos.Stdin != "" {
		if f, err = newDelayedConnection(ctx, fifos.Stdin); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create stdin pipe %s", fifos.Stdin)
		}
		p.stdin = f
		set = append(set, f)
	}

	if fifos.Stdout != "" {
		if f, err = newDelayedConnection(ctx, fifos.Stdout); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create stdout pipe %s", fifos.Stdout)
		}
		p.stdout = f
		set = append(set, f)
	}

	if fifos.Stderr != "" {
		if f, err = newDelayedConnection(ctx, fifos.Stderr); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create stderr pipe %s", fifos.Stderr)
		}
		p.stderr = f
		set = append(set, f)
	}

	return p, &wgCloser{
		wg:     &sync.WaitGroup{},
		set:    set,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}
