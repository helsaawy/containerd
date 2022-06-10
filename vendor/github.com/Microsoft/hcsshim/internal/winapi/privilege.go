//go:build windows

package winapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/2158be91-3b85-4e49-9f0e-2538856f5c55
//nolint:revive,stylecheck
const (
	SE_GROUP_MANDATORY          = uint32(0x00000001)
	SE_GROUP_ENABLED_BY_DEFAULT = uint32(0x00000002)
	SE_GROUP_ENABLED            = uint32(0x00000004)
	SE_GROUP_OWNER              = uint32(0x00000008)
	SE_GROUP_USE_FOR_DENY_ONLY  = uint32(0x00000010)
)

// privilege names
const (
	SeChangeNotifyPrivilege = "SeChangeNotifyPrivilege"
	SeBackupPrivilege       = winio.SeBackupPrivilege
	SeRestorePrivilege      = winio.SeRestorePrivilege
	SeCreateGlobalPrivilege = "SeCreateGlobalPrivilege"
	SeManageVolumePrivilege = "SeManageVolumePrivilege"
)

func LookupPrivilegeValues(privs []string) ([]windows.LUID, error) {
	luids := make([]windows.LUID, len(privs))
	for i, p := range privs {
		l, err := LookupPrivilegeValue(p)
		if err != nil {
			return nil, fmt.Errorf("lookup privilege value for %q: %w", p, err)
		}
		luids[i] = l
	}
	return luids, nil
}

func LookupPrivilegeValue(priv string) (l windows.LUID, err error) {
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(priv), &l)
	return l, err
}

// BOOL LookupPrivilegeNameW(
//   [in, optional]  LPCWSTR lpSystemName,
//   [in]            PLUID   lpLuid,
//   [out, optional] LPWSTR  lpName,
//   [in, out]       LPDWORD cchName
// );
//
//sys lookupPrivilegeName(systemName string, luid *windows.LUID, buffer *uint16, size *uint32) (err error) = advapi32.LookupPrivilegeNameW

func LookupPrivilegeName(luid windows.LUID) (string, error) {
	s, err := retryLStr(-2, func(b *uint16, l *uint32) error {
		return lookupPrivilegeName("", &luid, b, l)
	})
	if err != nil {
		return "", fmt.Errorf("could not lookup LUID %v: %w", luid, err)
	}
	return windows.UTF16ToString(s), nil
}

// BOOL LookupPrivilegeDisplayNameW(
//   [in, optional]  LPCWSTR lpSystemName,
//   [in]            LPCWSTR lpName,
//   [out, optional] LPWSTR  lpDisplayName,
//   [in, out]       LPDWORD cchDisplayName,
//   [out]           LPDWORD lpLanguageId
// );
//
//sys lookupPrivilegeDisplayName(systemName string, name string, buffer *uint16, size *uint32, languageId *uint32) (err error) = advapi32.LookupPrivilegeDisplayNameW

func LookupPrivilegeDisplayName(s string) (string, error) {
	var langID uint32
	ss, err := retryLStr(0, func(b *uint16, l *uint32) error {
		return lookupPrivilegeDisplayName("", s, b, l, &langID)
	})
	if err != nil {
		return "", fmt.Errorf("could not lookup privilege %s: %w", s, err)
	}
	return windows.UTF16ToString(ss), nil
}

// see: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
func NewTokenPrivileges(luids []windows.LUIDAndAttributes) (*windows.Tokenprivileges, error) {
	// todo: will the GC trim the remaining parts of the buffer since the Tokenprivileges{}
	// struct can only access the first element of the array?

	// extra room for one more
	b := &bytes.Buffer{}
	b.Grow(int(unsafe.Sizeof(windows.Tokenprivileges{}) + unsafe.Sizeof(windows.LUIDAndAttributes{})*uintptr(len(luids))))
	if err := binary.Write(b, binary.LittleEndian, uint32(len(luids))); err != nil {
		return nil, err
	}
	for _, la := range luids {
		if err := binary.Write(b, binary.LittleEndian, la); err != nil {
			return nil, err
		}
	}
	pv := (*windows.Tokenprivileges)(unsafe.Pointer(&b.Bytes()[0]))
	return pv, nil
}
