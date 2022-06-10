//go:build windows

package winapi

import (
	"os"

	"golang.org/x/sys/windows"
)

// HANDLE CreateNamedPipeW(
//   [in]           LPCWSTR               lpName,
//   [in]           DWORD                 dwOpenMode,
//   [in]           DWORD                 dwPipeMode,
//   [in]           DWORD                 nMaxInstances,
//   [in]           DWORD                 nOutBufferSize,
//   [in]           DWORD                 nInBufferSize,
//   [in]           DWORD                 nDefaultTimeOut,
//   [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes
// );
//
// https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
//
//sys CreateNamedPipe(name string, mode uint32, pipeMode uint32, maxInstances uint32, outBufferSize uint32, inBufferSize uint32, defaultTimeout uint32, sa *windows.SecurityAttributes) (handle windows.Handle, err error)  [failretval==windows.InvalidHandle] = CreateNamedPipeW

type NamedPipeConfig struct {
	// OpenMode is the pipe access mode (Duplex, Inbound, Outbound), along with other flags (ie, WRITE_DAC).
	OpenMode uint32
	// AdditionalInstances allows additional server side instances of the pipe to be created.
	AdditionalInstances uint32
	// MesageMode enables sending streams of messages that demarcate different writes. Default is byte mode.
	MessageMode bool
	// RejectClients automatically rejects client connections
	RejectClients bool
	// InputBufferSize specifies the size of the input buffer, in bytes.
	InputBufferSize uint32
	// OutputBufferSize specifies the size of the output buffer, in bytes.
	OutputBufferSize uint32
	// Timeout (in ms) to use if WaitNamedPipe specifies NMPWAIT_USE_DEFAULT_WAIT as its timeout.
	Timeout            uint32
	SecurityAttributes *windows.SecurityAttributes
}

// NamedPipe is a wrapper around windows.CreateNamedPipe, and is more general and low-level
// than "github.com/Microsoft/go-winio/".ListenPipe.
// More specifically, it allows access to the underlying handle.
func NewNamedPipe(name string, config *NamedPipeConfig) (*os.File, error) {
	if config == nil {
		config = &NamedPipeConfig{
			OpenMode:           windows.PIPE_ACCESS_DUPLEX,
			SecurityAttributes: NewInheritableSecurityAttributes(),
		}
	}
	mode := config.OpenMode
	if config.AdditionalInstances > 0 {
		mode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}

	pMode := uint32(0x0)
	if config.MessageMode {
		pMode |= windows.PIPE_TYPE_MESSAGE
	}
	if config.RejectClients {
		pMode |= windows.PIPE_REJECT_REMOTE_CLIENTS
	}

	h, err := CreateNamedPipe(
		name,
		mode,
		pMode,
		1+config.AdditionalInstances,
		config.InputBufferSize,
		config.OutputBufferSize,
		config.Timeout,
		config.SecurityAttributes,
	)
	if err != nil {
		return nil, err
	}

	pipe := os.NewFile(uintptr(h), name)
	return pipe, nil
}

// NamedPipeWaitConnection blocks until a client connects to the named pipe.
//
// This requires the pipe to be created without the windows.FILE_FLAG_OVERLAPPED flag.
func NamedPipeWaitConnection(pipe *os.File) error {
	return windows.ConnectNamedPipe(windows.Handle(pipe.Fd()), nil)
}

// NewPipe is a more general version of os.Pipe().
func NewPipe(sa *windows.SecurityAttributes, size int) (*os.File, *os.File, error) {
	var r, w windows.Handle
	if err := windows.CreatePipe(&r, &w, sa, uint32(size)); err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(r), "|0"), os.NewFile(uintptr(w), "|1"), nil
}
