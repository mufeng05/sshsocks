package main

import (
	"errors"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW              = user32.NewProc("RegisterClassExW")
	procCreateWindowExW               = user32.NewProc("CreateWindowExW")
	procDestroyWindow                 = user32.NewProc("DestroyWindow")
	procDefWindowProcW                = user32.NewProc("DefWindowProcW")
	procGetMessageW                   = user32.NewProc("GetMessageW")
	procTranslateMessage              = user32.NewProc("TranslateMessage")
	procDispatchMessageW              = user32.NewProc("DispatchMessageW")
	procPostQuitMessage               = user32.NewProc("PostQuitMessage")
	procPostMessageW                  = user32.NewProc("PostMessageW")
	procFindWindowW                   = user32.NewProc("FindWindowW")
	procRegisterWindowMessageW        = user32.NewProc("RegisterWindowMessageW")
	procCreatePopupMenu               = user32.NewProc("CreatePopupMenu")
	procAppendMenuW                   = user32.NewProc("AppendMenuW")
	procCheckMenuRadioItem            = user32.NewProc("CheckMenuRadioItem")
	procTrackPopupMenu                = user32.NewProc("TrackPopupMenu")
	procDestroyMenu                   = user32.NewProc("DestroyMenu")
	procSetForegroundWindow           = user32.NewProc("SetForegroundWindow")
	procGetCursorPos                  = user32.NewProc("GetCursorPos")
	procCreateIconIndirect            = user32.NewProc("CreateIconIndirect")
	procGetSystemMetrics              = user32.NewProc("GetSystemMetrics")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procOpenClipboard                 = user32.NewProc("OpenClipboard")
	procCloseClipboard                = user32.NewProc("CloseClipboard")
	procEmptyClipboard                = user32.NewProc("EmptyClipboard")
	procSetClipboardData              = user32.NewProc("SetClipboardData")
	procShellNotifyIconW              = shell32.NewProc("Shell_NotifyIconW")
	procCreateDIBSection              = gdi32.NewProc("CreateDIBSection")
	procCreateBitmap                  = gdi32.NewProc("CreateBitmap")
	procDeleteObject                  = gdi32.NewProc("DeleteObject")
	procGlobalAlloc                   = kernel32.NewProc("GlobalAlloc")
	procGlobalLock                    = kernel32.NewProc("GlobalLock")
	procGlobalUnlock                  = kernel32.NewProc("GlobalUnlock")
	procGlobalFree                    = kernel32.NewProc("GlobalFree")
)

const (
	wmNull            = 0x0000
	wmDestroy         = 0x0002
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmLButtonUp       = 0x0202
	wmRButtonUp       = 0x0205
	wmUser            = 0x0400
	wmApp             = 0x8000

	ninBalloonUserClick = wmUser + 5

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2

	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04
	nifInfo    = 0x10

	niifInfo    = 0x01
	niifWarning = 0x02

	mfString     = 0x0000
	mfGrayed     = 0x0001
	mfChecked    = 0x0008
	mfPopup      = 0x0010
	mfByPosition = 0x0400
	mfSeparator  = 0x0800

	tpmRightButton = 0x0002
	tpmNoNotify    = 0x0080
	tpmReturnCmd   = 0x0100

	mbIconError     = 0x10
	mbIconWarning   = 0x30
	mbIconInfo      = 0x40
	mbSetForeground = 0x10000

	smCxSmIcon   = 49
	swShowNormal = 1
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type pointW struct{ x, y int32 }

type msgW struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      pointW
	private uint32
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     windows.Handle
}

type iconInfo struct {
	fIcon    int32
	xHotspot uint32
	yHotspot uint32
	hbmMask  windows.Handle
	hbmColor windows.Handle
}

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

func utf16Ptr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// putUTF16 把 s 写进定长的 WCHAR 数组，放不下时截断并加省略号。
func putUTF16(dst []uint16, s string) {
	u := utf16.Encode([]rune(s))
	if len(u) >= len(dst) {
		u = u[:len(dst)-2]
		if n := len(u); n > 0 && u[n-1] >= 0xD800 && u[n-1] < 0xDC00 {
			u = u[:n-1] // 不要留下半个代理对
		}
		u = append(u, '…')
	}
	dst[copy(dst, u)] = 0
}

// createIcon 用 renderIcon 生成的 BGRA 像素创建图标。
func createIcon(size int, bgra []byte) (windows.Handle, error) {
	bi := bitmapInfoHeader{biWidth: int32(size), biHeight: -int32(size), biPlanes: 1, biBitCount: 32}
	bi.biSize = uint32(unsafe.Sizeof(bi))
	var bits unsafe.Pointer
	color, _, err := procCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if color == 0 {
		return 0, err
	}
	defer procDeleteObject.Call(color)
	copy(unsafe.Slice((*byte)(bits), len(bgra)), bgra)

	maskBits := make([]byte, (size+15)/16*2*size) // 全 0 的掩码，透明度完全由 alpha 决定
	mask, _, err := procCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, uintptr(unsafe.Pointer(&maskBits[0])))
	if mask == 0 {
		return 0, err
	}
	defer procDeleteObject.Call(mask)

	ii := iconInfo{fIcon: 1, hbmMask: windows.Handle(mask), hbmColor: windows.Handle(color)}
	h, _, err := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	if h == 0 {
		return 0, err
	}
	return windows.Handle(h), nil
}

func setClipboardText(hwnd uintptr, text string) error {
	u := utf16.Encode([]rune(text + "\x00"))
	if r, _, err := procOpenClipboard.Call(hwnd); r == 0 {
		return err
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
	const gmemMoveable, cfUnicodeText = 0x0002, 13
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(u)*2))
	if h == 0 {
		return err
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return err
	}
	copy(unsafe.Slice(*(**uint16)(unsafe.Pointer(&p)), len(u)), u)
	procGlobalUnlock.Call(h)
	if r, _, err := procSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		procGlobalFree.Call(h)
		return err
	}
	return nil
}

func messageBox(hwnd uintptr, text string, flags uint32) {
	windows.MessageBox(windows.HWND(hwnd), utf16Ptr(text), utf16Ptr("sshsocks"), flags|mbSetForeground)
}

func openWithNotepad(path string) {
	windows.ShellExecute(0, utf16Ptr("open"), utf16Ptr("notepad.exe"), utf16Ptr(`"`+path+`"`), nil, swShowNormal)
}

// setDPIAware 让托盘图标和菜单在高分屏下保持清晰。
func setDPIAware() {
	if procSetProcessDpiAwarenessContext.Find() == nil {
		procSetProcessDpiAwarenessContext.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	}
}

// allowDarkMenus 让托盘菜单跟随系统的深色模式。
// 用的是 uxtheme.dll 未公开的接口（按序号导出），Windows 10 1903 起可用，失败就保持浅色。
func allowDarkMenus() {
	if v := windows.RtlGetVersion(); v.MajorVersion < 10 || v.BuildNumber < 18362 {
		return
	}
	h, err := windows.LoadLibraryEx("uxtheme.dll", 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return
	}
	if p, err := windows.GetProcAddressByOrdinal(h, 135); err == nil {
		syscall.SyscallN(p, 1) // SetPreferredAppMode(AllowDark)
	}
	if p, err := windows.GetProcAddressByOrdinal(h, 136); err == nil {
		syscall.SyscallN(p) // FlushMenuThemes
	}
}

// acquireInstanceLock 保证只运行一个实例。
func acquireInstanceLock() bool {
	_, err := windows.CreateMutex(nil, false, utf16Ptr(`Local\sshsocks-single-instance`))
	return !errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}
