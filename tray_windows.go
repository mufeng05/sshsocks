package main

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const trayClassName = "sshsocksTrayWindow"

const (
	wmTray    = wmApp + 1 // 托盘图标上的鼠标操作
	wmRefresh = wmApp + 2 // 状态变了，更新图标
	wmPing    = wmApp + 3 // 用户又启动了一次程序
	wmAddIcon = wmApp + 4 // 重试添加托盘图标
)

// 菜单命令。每个代理占用一段编号：基数 + 序号。
const (
	idEditConfig = 1 + iota
	idOpenLog
	idReconnectAll
	idAutostart
	idQuit
	idSysProxyOff
	idSysProxyBase  = 100
	idCopyBase      = 200
	idReconnectBase = 300
	idErrorBase     = 400
	maxMenuTunnels  = 100
)

// Tray 是托盘图标。除 Refresh 和 Notify 外，方法都只在界面线程上调用。
type Tray struct {
	app            *App
	hwnd           uintptr
	taskbarCreated uint32
	icons          map[rgb]windows.Handle
	color          rgb
	tip            string
	addRetries     int
	mu             sync.Mutex // 串行化 Shell_NotifyIcon
	refreshPending atomic.Bool
}

var theTray *Tray // 窗口过程通过它找到托盘

// runTray 创建托盘图标并运行消息循环，直到用户退出。
func runTray(app *App) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var hinst windows.Handle
	windows.GetModuleHandleEx(0, nil, &hinst)
	className := utf16Ptr(trayClassName)
	wc := wndClassExW{lpfnWndProc: syscall.NewCallback(wndProc), hInstance: hinst, lpszClassName: className}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassEx：%w", err)
	}
	// 不显示的普通顶层窗口：能收到 TaskbarCreated 广播，也能响应 taskkill 发来的 WM_CLOSE
	hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(utf16Ptr("sshsocks"))),
		0, 0, 0, 0, 0, 0, 0, uintptr(hinst), 0)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowEx：%w", err)
	}
	tr := &Tray{app: app, hwnd: hwnd, icons: map[rgb]windows.Handle{}, color: colorIdle, tip: "sshsocks"}
	r, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(utf16Ptr("TaskbarCreated"))))
	tr.taskbarCreated = uint32(r)
	theTray = tr
	app.tray = tr
	tr.addIcon()
	app.Start()

	var m msgW
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return nil
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func findTrayWindow() uintptr {
	h, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(utf16Ptr(trayClassName))), 0)
	return h
}

func wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	if tr := theTray; tr != nil && hwnd == tr.hwnd {
		switch msg {
		case wmTray:
			switch lParam & 0xFFFF {
			case wmLButtonUp, wmRButtonUp:
				tr.showMenu()
			case ninBalloonUserClick:
				tr.app.OpenLog()
			}
			return 0
		case wmRefresh:
			tr.refreshPending.Store(false)
			tr.update()
			return 0
		case wmPing:
			tr.Notify("sshsocks 已经在运行", "点击任务栏右下角的图标查看状态和菜单", false)
			return 0
		case wmAddIcon:
			tr.addIcon()
			return 0
		case wmQueryEndSession:
			return 1
		case wmEndSession:
			if wParam != 0 {
				tr.app.Shutdown() // 注销或关机前恢复系统代理
			}
			return 0
		case wmDestroy:
			tr.shellNotify(nimDelete, tr.nid())
			procPostQuitMessage.Call(0)
			return 0
		}
		if tr.taskbarCreated != 0 && uint32(msg) == tr.taskbarCreated {
			tr.addIcon() // 资源管理器重启了，重新添加图标
			return 0
		}
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

// Refresh 请求按最新状态更新图标，可在任意线程调用。
func (tr *Tray) Refresh() {
	if tr != nil && !tr.refreshPending.Swap(true) {
		procPostMessageW.Call(tr.hwnd, wmRefresh, 0, 0)
	}
}

// Notify 弹出系统通知，可在任意线程调用。
func (tr *Tray) Notify(title, text string, warn bool) {
	if tr == nil {
		return
	}
	d := tr.nid()
	d.uFlags = nifInfo
	d.dwInfoFlags = niifInfo
	if warn {
		d.dwInfoFlags = niifWarning
	}
	putUTF16(d.szInfoTitle[:], title)
	putUTF16(d.szInfo[:], text)
	tr.shellNotify(nimModify, d)
}

func (tr *Tray) nid() *notifyIconDataW {
	d := &notifyIconDataW{hWnd: tr.hwnd, uID: 1}
	d.cbSize = uint32(unsafe.Sizeof(*d))
	return d
}

func (tr *Tray) shellNotify(op uintptr, d *notifyIconDataW) bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	r, _, _ := procShellNotifyIconW.Call(op, uintptr(unsafe.Pointer(d)))
	return r != 0
}

func (tr *Tray) icon(c rgb) windows.Handle {
	if h, ok := tr.icons[c]; ok {
		return h
	}
	size, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	h, err := createIcon(max(int(size), 16), renderIcon(max(int(size), 16), c))
	if err != nil {
		log.Printf("创建图标失败：%v", err)
	}
	tr.icons[c] = h
	return h
}

func (tr *Tray) addIcon() {
	d := tr.nid()
	d.uFlags = nifMessage | nifIcon | nifTip
	d.uCallbackMessage = wmTray
	d.hIcon = tr.icon(tr.color)
	putUTF16(d.szTip[:], tr.tip)
	tr.shellNotify(nimDelete, tr.nid())
	if tr.shellNotify(nimAdd, d) {
		tr.addRetries = 0
		return
	}
	// 开机自启时任务栏可能还没准备好，过一会儿再试
	if tr.addRetries < 30 {
		tr.addRetries++
		time.AfterFunc(2*time.Second, func() { procPostMessageW.Call(tr.hwnd, wmAddIcon, 0, 0) })
	} else {
		log.Printf("无法添加托盘图标（任务栏一直没有响应）")
	}
}

// update 按当前状态更新图标颜色和鼠标悬停提示。
func (tr *Tray) update() {
	st := tr.app.Snapshot()
	tr.color, tr.tip = trayLook(st)
	d := tr.nid()
	d.uFlags = nifIcon | nifTip
	d.hIcon = tr.icon(tr.color)
	putUTF16(d.szTip[:], tr.tip)
	tr.shellNotify(nimModify, d)
}

func trayLook(st Snapshot) (rgb, string) {
	if len(st.Tunnels) == 0 {
		if st.ConfigErr != nil {
			return colorError, "sshsocks：配置文件有误"
		}
		return colorIdle, "sshsocks：还没有配置代理"
	}
	c := colorOK
	lines := []string{"sshsocks"}
	if st.ConfigErr != nil {
		c = colorError
		lines = append(lines, "配置文件有误，未生效")
	}
	for _, t := range st.Tunnels {
		switch {
		case t.Failing():
			c = colorError
		case t.State == StateConnecting && c == colorOK:
			c = colorBusy
		}
		lines = append(lines, stateSymbol(t.TunnelStatus)+" "+t.Listen+" "+t.Label())
	}
	return c, strings.Join(lines, "\n")
}

func stateSymbol(s TunnelStatus) string {
	switch {
	case s.Failing():
		return "×"
	case s.State == StateConnected:
		return "●"
	}
	return "○"
}

func (tr *Tray) showMenu() {
	st := tr.app.Snapshot()
	menu := newMenu()
	defer procDestroyMenu.Call(menu) // 子菜单随父菜单一起销毁

	appendMenu(menu, mfGrayed, 0, "sshsocks "+version)
	appendMenu(menu, mfSeparator, 0, "")
	if st.ConfigErr != nil {
		appendMenu(menu, mfString, idEditConfig, "⚠ 配置有误："+shorten(st.ConfigErr.Error(), 40))
	} else if len(st.Tunnels) == 0 {
		appendMenu(menu, mfGrayed, 0, "还没有配置代理，点「编辑配置」添加")
	}
	tunnels := st.Tunnels[:min(len(st.Tunnels), maxMenuTunnels)]
	for i, t := range tunnels {
		sub := newMenu()
		appendMenu(sub, mfGrayed, 0, "链路："+t.Chain)
		status := "状态：" + t.Label()
		if t.State == StateConnected && t.Conns > 0 {
			status += fmt.Sprintf("，%d 个连接", t.Conns)
		}
		appendMenu(sub, mfGrayed, 0, status)
		if t.Err != nil {
			appendMenu(sub, mfString, uintptr(idErrorBase+i), "原因："+shorten(t.Err.Error(), 36)+"（点击查看全文）")
		}
		appendMenu(sub, mfSeparator, 0, "")
		appendMenu(sub, mfString, uintptr(idCopyBase+i), "复制代理地址 "+systemProxyAddr(t.Listen))
		appendMenu(sub, mfString, uintptr(idReconnectBase+i), "立即重连")
		appendMenu(menu, mfPopup, sub, stateSymbol(t.TunnelStatus)+"  "+t.Listen+"    "+t.Chain+"\t"+t.Label())
	}
	appendMenu(menu, mfSeparator, 0, "")

	// 系统代理：勾选的是系统里实际生效的设置
	sp := newMenu()
	appendMenu(sp, mfString, idSysProxyOff, "不使用")
	checked := 0 // 在子菜单中的位置
	cur, _ := queryProxySettings()
	for i, t := range tunnels {
		addr := systemProxyAddr(t.Listen)
		appendMenu(sp, mfString, uintptr(idSysProxyBase+i), addr+"    "+t.Chain)
		if cur != nil && cur.pointsTo(addr) {
			checked = i + 1
		}
	}
	if cur != nil && cur.flags&proxyTypeProxy != 0 && checked == 0 {
		appendMenu(sp, mfSeparator, 0, "")
		appendMenu(sp, mfGrayed, 0, "当前是其他程序设置的 "+cur.server)
		checked = -1
	}
	if checked >= 0 {
		procCheckMenuRadioItem.Call(sp, 0, uintptr(len(tunnels)), uintptr(checked), mfByPosition)
	}
	appendMenu(menu, mfPopup, sp, "系统代理")
	appendMenu(menu, mfSeparator, 0, "")
	appendMenu(menu, mfString, idEditConfig, "编辑配置")
	appendMenu(menu, mfString, idOpenLog, "查看日志")
	appendMenu(menu, mfString, idReconnectAll, "全部重连")
	auto := uintptr(mfString)
	if tr.app.AutostartEnabled() {
		auto |= mfChecked
	}
	appendMenu(menu, auto, idAutostart, "开机自动启动")
	appendMenu(menu, mfSeparator, 0, "")
	appendMenu(menu, mfString, idQuit, "退出")

	var pt pointW
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(tr.hwnd) // 否则点菜单外面时菜单不会消失
	cmd, _, _ := procTrackPopupMenu.Call(menu, tpmReturnCmd|tpmRightButton|tpmNoNotify,
		uintptr(pt.x), uintptr(pt.y), 0, tr.hwnd, 0)
	procPostMessageW.Call(tr.hwnd, wmNull, 0, 0)
	tr.command(int(cmd), tunnels)
}

func (tr *Tray) command(cmd int, tunnels []TunnelInfo) {
	pick := func(base int) (TunnelInfo, bool) {
		i := cmd - base
		if i >= 0 && i < len(tunnels) {
			return tunnels[i], true
		}
		return TunnelInfo{}, false
	}
	switch {
	case cmd == idEditConfig:
		tr.app.EditConfig()
	case cmd == idOpenLog:
		tr.app.OpenLog()
	case cmd == idReconnectAll:
		tr.app.ReconnectAll()
	case cmd == idAutostart:
		tr.app.ToggleAutostart()
	case cmd == idQuit:
		procDestroyWindow.Call(tr.hwnd)
	case cmd == idSysProxyOff:
		tr.app.SetSystemProxy("")
	case cmd >= idErrorBase:
		if t, ok := pick(idErrorBase); ok && t.Err != nil {
			messageBox(tr.hwnd, t.Listen+"（"+t.Chain+"）\n\n"+t.Err.Error(), mbIconWarning)
		}
	case cmd >= idReconnectBase:
		if t, ok := pick(idReconnectBase); ok {
			tr.app.Reconnect(t.tunnel)
		}
	case cmd >= idCopyBase:
		if t, ok := pick(idCopyBase); ok {
			if err := setClipboardText(tr.hwnd, systemProxyAddr(t.Listen)); err != nil {
				log.Printf("复制到剪贴板失败：%v", err)
			}
		}
	case cmd >= idSysProxyBase:
		if t, ok := pick(idSysProxyBase); ok {
			tr.app.SetSystemProxy(t.Listen)
		}
	}
}

func newMenu() uintptr {
	m, _, _ := procCreatePopupMenu.Call()
	return m
}

func appendMenu(menu uintptr, flags, id uintptr, text string) {
	text = strings.ReplaceAll(text, "&", "&&") // & 在菜单里表示快捷键
	procAppendMenuW.Call(menu, flags, id, uintptr(unsafe.Pointer(utf16Ptr(text))))
}

// shorten 把过长的文字截断，免得菜单被撑得很宽。
func shorten(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
