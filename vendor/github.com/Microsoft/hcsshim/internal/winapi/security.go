package winapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func GrantSIDFileAccess(name string, sid *windows.SID, access windows.ACCESS_MASK) error {
	isDir, err := IsDir(name)
	if err != nil {
		return fmt.Errorf("check if %q is directory: %w", name, err)
	}

	inh := uint32(windows.NO_INHERITANCE)
	if isDir {
		inh = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	return GrantSIDNamedAccess(name, sid, access, inh, windows.SE_FILE_OBJECT)
}

func GrantSIDNamedAccess(
	n string,
	sid *windows.SID,
	access windows.ACCESS_MASK,
	inheritance uint32,
	t windows.SE_OBJECT_TYPE,
) error {
	eas := []windows.EXPLICIT_ACCESS{
		AllowAccessForSID(sid, access, inheritance),
	}
	return UpdateNamedDACL(n, eas, t)
}

func GrantSIDHandleAccess(
	h windows.Handle,
	sid *windows.SID,
	access windows.ACCESS_MASK,
	inheritance uint32,
	t windows.SE_OBJECT_TYPE,
) error {
	eas := []windows.EXPLICIT_ACCESS{
		AllowAccessForSID(sid, access, inheritance),
	}
	return UpdateHandleDACL(h, eas, t)
}

func RevokeSIDFileAccess(name string, sid *windows.SID) error {
	isDir, err := IsDir(name)
	if err != nil {
		return fmt.Errorf("check if %q is directory: %w", name, err)
	}

	inh := uint32(windows.NO_INHERITANCE)
	if isDir {
		inh = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	return RevokeSIDNamedAccess(name, sid, inh, windows.SE_FILE_OBJECT)
}

func RevokeSIDNamedAccess(
	n string,
	sid *windows.SID,
	inheritance uint32,
	t windows.SE_OBJECT_TYPE,
) error {
	eas := []windows.EXPLICIT_ACCESS{
		RevokeAccessForSID(sid, inheritance),
	}
	return UpdateNamedDACL(n, eas, t)
}

func RevokeSIDHandleAccess(
	h windows.Handle,
	sid *windows.SID,
	inheritance uint32,
	t windows.SE_OBJECT_TYPE,
) error {
	eas := []windows.EXPLICIT_ACCESS{
		RevokeAccessForSID(sid, inheritance),
	}
	return UpdateHandleDACL(h, eas, t)
}

func UpdateFileDACL(name string, eas []windows.EXPLICIT_ACCESS) error {
	return UpdateNamedDACL(name, eas, windows.SE_FILE_OBJECT)
}

func UpdateNamedDACL(n string, eas []windows.EXPLICIT_ACCESS, t windows.SE_OBJECT_TYPE) error {
	if len(eas) == 0 {
		return nil
	}

	acl, err := GetNamedDACL(n, t)
	if err != nil {
		return err
	}

	acl, err = windows.ACLFromEntries(eas, acl)
	if err != nil {
		return fmt.Errorf("merging DACL with explicit access entries : %w", err)
	}

	return windows.SetNamedSecurityInfo(n, t, windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION), nil, nil, acl, nil)
}

func UpdateHandleDACL(h windows.Handle, eas []windows.EXPLICIT_ACCESS, t windows.SE_OBJECT_TYPE) error {
	if len(eas) == 0 {
		return nil
	}

	acl, err := GetHandleDACL(h, t)
	if err != nil {
		return err
	}

	acl, err = windows.ACLFromEntries(eas, acl)
	if err != nil {
		return fmt.Errorf("merging DACL with explicit access entries : %w", err)
	}

	return windows.SetSecurityInfo(h, t, windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION), nil, nil, acl, nil)
}

// GetFileDACL returns the discretional access control list for the file or directory.
func GetFileDACL(name string) (*windows.ACL, error) {
	sd, err := GetFileSD(name)
	if err != nil {
		return nil, err
	}
	acl, _, err := sd.DACL()
	return acl, err
}

func GetFileSD(name string) (*windows.SECURITY_DESCRIPTOR, error) {
	return GetNamedSD(name, windows.SE_FILE_OBJECT)
}

func GetNamedDACL(n string, t windows.SE_OBJECT_TYPE) (*windows.ACL, error) {
	sd, err := GetNamedSD(n, t)
	if err != nil {
		return nil, err
	}
	acl, _, err := sd.DACL()
	return acl, err
}

func GetHandleDACL(h windows.Handle, t windows.SE_OBJECT_TYPE) (*windows.ACL, error) {
	sd, err := GetHandleSD(h, t)
	if err != nil {
		return nil, err
	}
	acl, _, err := sd.DACL()
	return acl, err
}

func GetNamedSD(n string, t windows.SE_OBJECT_TYPE) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.GetNamedSecurityInfo(n, t, windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION))
	if err != nil {
		return nil, fmt.Errorf("get named object %q security info: %w", n, err)
	}
	return sd, nil
}

func GetHandleSD(h windows.Handle, t windows.SE_OBJECT_TYPE) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.GetSecurityInfo(h, t, windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION))
	if err != nil {
		return nil, fmt.Errorf("get security info: %w", err)
	}
	return sd, nil
}

func NewInheritableSecurityAttributes() *windows.SecurityAttributes {
	return NewSecurityAttributes(nil, true)
}

func NewSecurityAttributes(descriptor *windows.SECURITY_DESCRIPTOR, inherit bool) *windows.SecurityAttributes {
	i := uint32(0)
	if inherit {
		i = 1
	}
	sa := &windows.SecurityAttributes{
		SecurityDescriptor: descriptor,
		InheritHandle:      i,
	}
	sa.Length = uint32(unsafe.Sizeof(sa))
	return sa
}

func AllowAccessForSID(sid *windows.SID, access windows.ACCESS_MASK, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: access,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func RevokeAccessForSID(sid *windows.SID, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessMode:  windows.REVOKE_ACCESS,
		Inheritance: inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
