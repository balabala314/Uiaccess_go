package main

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32              = windows.NewLazySystemDLL("advapi32.dll")
	procPrivilegeCheck       = modadvapi32.NewProc("PrivilegeCheck")
	procCreateProcessAsUserW = modadvapi32.NewProc("CreateProcessAsUserW")
	createProcessAsUser      = modadvapi32.NewProc("CreateProcessAsUserA")
)

const (
	PRIVILEGE_SET_ALL_NECESSARY = 1
)

type PRIVILEGE_SET struct {
	PrivilegeCount uint32
	Control        uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

type LUID_AND_ATTRIBUTES struct {
	Luid       windows.LUID
	Attributes uint32
}

func PrivilegeCheck(tokenHandle windows.Handle, ps *PRIVILEGE_SET, result *bool) error {
	var bResult int32
	r1, _, e1 := syscall.SyscallN(procPrivilegeCheck.Addr(),
		uintptr(tokenHandle),
		uintptr(unsafe.Pointer(ps)),
		uintptr(unsafe.Pointer(&bResult)),
	)
	if r1 == 0 {
		return e1
	}
	*result = bResult != 0
	return nil
}

func duplicateWinlogonToken(sessionID uint32, desiredAccess uint32) (windows.Handle, error) {
	var tcbLUID windows.LUID
	val, err := syscall.UTF16PtrFromString("SeTcbPrivilege")
	if err := windows.LookupPrivilegeValue(nil, val, &tcbLUID); err != nil {
		return 0, err
	}
	ps := PRIVILEGE_SET{
		PrivilegeCount: 1,
		Control:        PRIVILEGE_SET_ALL_NECESSARY,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{Luid: tcbLUID, Attributes: 0},
		},
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)
	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	if err = windows.Process32First(snapshot, &pe32); err != nil {
		return 0, err
	}
	for {
		exeName := windows.UTF16ToString(pe32.ExeFile[:])
		if exeName == "winlogon.exe" || exeName == "lsass.exe" {
			hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe32.ProcessID)
			if err != nil {
				continue
			}

			var hToken windows.Token
			if err = windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &hToken); err != nil {
				windows.CloseHandle(hProcess)
				continue
			}

			var fTcb bool
			if err = PrivilegeCheck(windows.Handle(hToken), &ps, &fTcb); err == nil && fTcb {
				var tokenSessionID uint32
				var returnedLen uint32
				err = windows.GetTokenInformation(hToken, windows.TokenSessionId, (*byte)(unsafe.Pointer(&tokenSessionID)), uint32(unsafe.Sizeof(tokenSessionID)), &returnedLen)
				if err == nil && tokenSessionID == sessionID {
					var newToken windows.Token
					err = windows.DuplicateTokenEx(hToken, desiredAccess, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &newToken)
					windows.CloseHandle(windows.Handle(hToken))
					windows.CloseHandle(hProcess)
					if err == nil {
						return windows.Handle(newToken), nil
					}
					continue
				}
			}
			windows.CloseHandle(windows.Handle(hToken))
			windows.CloseHandle(hProcess)
		}

		if err = windows.Process32Next(snapshot, &pe32); err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return 0, err
		}
	}

	return 0, syscall.ERROR_NOT_FOUND
}

func createUIAccessToken() (windows.Handle, error) {
	var hTokenSelf windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &hTokenSelf); err != nil {
		return 0, err
	}
	defer windows.CloseHandle(windows.Handle(hTokenSelf))
	var sessionID uint32
	var returnedLen uint32
	if err := windows.GetTokenInformation(hTokenSelf, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sessionID)), uint32(unsafe.Sizeof(sessionID)), &returnedLen); err != nil {
		return 0, err
	}
	hTokenSystem, err := duplicateWinlogonToken(sessionID, windows.TOKEN_IMPERSONATE)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(hTokenSystem)
	if err := windows.SetThreadToken(nil, windows.Token(hTokenSystem)); err != nil {
		return 0, err
	}
	defer windows.RevertToSelf()

	var hTokenNew windows.Token
	if err := windows.DuplicateTokenEx(
		hTokenSelf,
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT,
		nil,
		windows.SecurityAnonymous,
		windows.TokenPrimary,
		&hTokenNew,
	); err != nil {
		return 0, err
	}
	uiAccess := uint32(1)
	if err := windows.SetTokenInformation(
		hTokenNew,
		windows.TokenUIAccess,
		(*byte)(unsafe.Pointer(&uiAccess)),
		uint32(unsafe.Sizeof(uiAccess)),
	); err != nil {
		windows.CloseHandle(windows.Handle(hTokenNew))
		return 0, err
	}
	return windows.Handle(hTokenNew), nil
}

func checkForUIAccess() (bool, error) {
	var hToken windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &hToken); err != nil {
		return false, err
	}
	defer windows.CloseHandle(windows.Handle(hToken))

	var uiAccess uint32
	var returnedLen uint32
	if err := windows.GetTokenInformation(hToken, windows.TokenUIAccess, (*byte)(unsafe.Pointer(&uiAccess)), uint32(unsafe.Sizeof(uiAccess)), &returnedLen); err != nil {
		return false, err
	}

	return uiAccess != 0, nil
}

func PrepareForUIAccess(cmdLine string) error {
	hasUI, err := checkForUIAccess()
	if err != nil {
		return err
	}
	if hasUI {
		return nil
	}

	hToken, err := createUIAccessToken()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hToken)

	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	pi := &windows.ProcessInformation{}

	final_name, err := syscall.UTF16PtrFromString(cmdLine)
	if err := windows.CreateProcessAsUser(
		windows.Token(hToken),
		nil,
		final_name,
		nil,
		nil,
		false,
		0,
		nil,
		nil,
		si,
		pi,
	); err != nil {
		return err
	}
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	windows.ExitProcess(0)
	return nil
}

func main() {
	appPath := os.Args
	if err := PrepareForUIAccess(appPath[1]); err != nil {
		panic(err)
	}
}
