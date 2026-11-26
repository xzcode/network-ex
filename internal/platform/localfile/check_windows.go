//go:build windows

package localfile

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getAce = windows.NewLazySystemDLL("advapi32.dll").NewProc("GetAce")

type aclHeader struct {
	Revision, Reserved     byte
	Size, Count, Reserved2 uint16
}
type aceHeader struct {
	Type, Flags byte
	Size        uint16
}

// Refuse broad ACLs rather than treating Unix mode bits as Windows security.
// Installer must restrict service state to SYSTEM and Administrators.
func Check(path string, dir bool, max int64) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if (dir && !st.IsDir()) || (!dir && !st.Mode().IsRegular()) || (!dir && max > 0 && st.Size() > max) {
		return errors.New("unsafe private file/directory type or size")
	}
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil {
		return errors.New("private file has no trusted owner")
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sy, e := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if e != nil {
		return e
	}
	ba, e := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if e != nil {
		return e
	}
	trusted := func(s *windows.SID) bool {
		return s != nil && (s.Equals(sy) || s.Equals(ba) || s.Equals(user.User.Sid))
	}
	if !trusted(owner) {
		return errors.New("private file owner is not trusted")
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return errors.New("private file has no restrictive DACL")
	}
	h := (*aclHeader)(unsafe.Pointer(acl))
	if h.Count == 0 {
		return errors.New("private file DACL is empty")
	}
	for i := uint16(0); i < h.Count; i++ {
		var ace unsafe.Pointer
		ret, _, err := getAce.Call(uintptr(unsafe.Pointer(acl)), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ret == 0 || ace == nil {
			return err
		}
		a := (*aceHeader)(ace)
		if a.Type == 1 {
			continue
		} // deny ACE does not grant access
		if a.Type != 0 || a.Size < 16 {
			return errors.New("unsupported private file ACE")
		}
		sid := (*windows.SID)(unsafe.Add(ace, 8))
		if !trusted(sid) {
			return errors.New("private file grants access to an untrusted principal")
		}
	}
	return nil
}
