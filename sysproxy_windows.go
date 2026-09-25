package main

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	wininet                  = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOptionW   = wininet.NewProc("InternetSetOptionW")
	procInternetQueryOptionW = wininet.NewProc("InternetQueryOptionW")
)

const (
	internetOptionRefresh             = 37
	internetOptionSettingsChanged     = 39
	internetOptionPerConnectionOption = 75

	perConnFlags         = 1
	perConnProxyServer   = 2
	perConnProxyBypass   = 3
	perConnAutoConfigURL = 4
	perConnFlagsUI       = 10

	proxyTypeDirect = 1
	proxyTypeProxy  = 2
)

// 本机和局域网地址不走代理
const proxyBypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;" +
	"172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

type perConnOption struct {
	option uint32
	value  uintptr // DWORD 或字符串指针
}

type perConnOptionList struct {
	size        uint32
	connection  *uint16 // nil 表示局域网连接
	optionCount uint32
	optionError uint32
	options     *perConnOption
}

// proxySettings 是「Internet 选项」里的代理设置，浏览器等程序都用它。
type proxySettings struct {
	flags   uint32
	server  string
	bypass  string
	autoURL string
}

func queryProxySettings() (*proxySettings, error) {
	opts := []perConnOption{{option: perConnFlagsUI}, {option: perConnProxyServer}, {option: perConnProxyBypass}, {option: perConnAutoConfigURL}}
	if err := perConnQuery(opts); err != nil {
		opts[0].option = perConnFlags // 老系统不支持 FLAGS_UI
		if err := perConnQuery(opts); err != nil {
			return nil, err
		}
	}
	return &proxySettings{
		flags:   uint32(opts[0].value),
		server:  takeWinString(opts[1].value),
		bypass:  takeWinString(opts[2].value),
		autoURL: takeWinString(opts[3].value),
	}, nil
}

func perConnQuery(opts []perConnOption) error {
	list := perConnOptionList{optionCount: uint32(len(opts)), options: &opts[0]}
	list.size = uint32(unsafe.Sizeof(list))
	size := list.size
	r, _, err := procInternetQueryOptionW.Call(0, internetOptionPerConnectionOption, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return err
	}
	return nil
}

// takeWinString 取出 WinINet 分配的字符串并释放它。
func takeWinString(p uintptr) string {
	if p == 0 {
		return ""
	}
	s := windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&p)))
	procGlobalFree.Call(p)
	return s
}

func applyProxySettings(s *proxySettings) error {
	server, bypass, autoURL := utf16Ptr(s.server), utf16Ptr(s.bypass), utf16Ptr(s.autoURL)
	opts := []perConnOption{
		{perConnFlags, uintptr(s.flags)},
		{perConnProxyServer, uintptr(unsafe.Pointer(server))},
		{perConnProxyBypass, uintptr(unsafe.Pointer(bypass))},
		{perConnAutoConfigURL, uintptr(unsafe.Pointer(autoURL))},
	}
	list := perConnOptionList{optionCount: uint32(len(opts)), options: &opts[0]}
	list.size = uint32(unsafe.Sizeof(list))
	r, _, err := procInternetSetOptionW.Call(0, internetOptionPerConnectionOption, uintptr(unsafe.Pointer(&list)), uintptr(list.size))
	runtime.KeepAlive(server)
	runtime.KeepAlive(bypass)
	runtime.KeepAlive(autoURL)
	if r == 0 {
		return err
	}
	// 通知正在运行的程序（浏览器等）设置已更改
	procInternetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOptionW.Call(0, internetOptionRefresh, 0, 0)
	return nil
}

// enableSystemProxy 把系统代理指向 addr。第一次开启时先保存原来的设置，关闭时原样恢复。
func enableSystemProxy(addr string) error {
	if _, saved := loadSavedProxy(); !saved {
		orig, err := queryProxySettings()
		if err != nil {
			return fmt.Errorf("读取当前代理设置失败：%w", err)
		}
		if err := saveProxy(orig); err != nil {
			return fmt.Errorf("保存当前代理设置失败：%w", err)
		}
	}
	return applyProxySettings(&proxySettings{flags: proxyTypeDirect | proxyTypeProxy, server: addr, bypass: proxyBypass})
}

// disableSystemProxy 恢复开启前的设置；没有保存过就只关掉「使用代理服务器」。
func disableSystemProxy() error {
	orig, saved := loadSavedProxy()
	if !saved {
		cur, err := queryProxySettings()
		if err != nil {
			return err
		}
		cur.flags = cur.flags&^proxyTypeProxy | proxyTypeDirect
		orig = cur
	}
	if err := applyProxySettings(orig); err != nil {
		return err
	}
	clearSavedProxy()
	return nil
}

// releaseSystemProxy 在程序退出时调用：系统代理仍指向本程序才恢复原设置，
// 已经被其他程序改掉的就不去动它。
func releaseSystemProxy(addr string) error {
	if cur, err := queryProxySettings(); err == nil && !cur.pointsTo(addr) {
		clearSavedProxy()
		return nil
	}
	return disableSystemProxy()
}

func (s *proxySettings) pointsTo(addr string) bool {
	return s.flags&proxyTypeProxy != 0 && strings.EqualFold(s.server, addr)
}

// systemProxyAddr 返回写进系统代理设置的地址：监听在 0.0.0.0 时改用 127.0.0.1。
func systemProxyAddr(listen string) string {
	host, port, _ := net.SplitHostPort(listen)
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// 开启前的设置保存在注册表里，这样程序异常退出后下次启动还能恢复。
func saveProxy(s *proxySettings) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, appKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	for name, v := range map[string]string{"SavedProxyServer": s.server, "SavedProxyBypass": s.bypass, "SavedProxyAutoURL": s.autoURL} {
		if err := k.SetStringValue(name, v); err != nil {
			return err
		}
	}
	return k.SetDWordValue("SavedProxyFlags", s.flags) // 最后写，有它就说明保存完整
}

func loadSavedProxy() (*proxySettings, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, appKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, false
	}
	defer k.Close()
	flags, _, err := k.GetIntegerValue("SavedProxyFlags")
	if err != nil {
		return nil, false
	}
	s := &proxySettings{flags: uint32(flags)}
	s.server, _, _ = k.GetStringValue("SavedProxyServer")
	s.bypass, _, _ = k.GetStringValue("SavedProxyBypass")
	s.autoURL, _, _ = k.GetStringValue("SavedProxyAutoURL")
	return s, true
}

func clearSavedProxy() {
	k, err := registry.OpenKey(registry.CURRENT_USER, appKeyPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	for _, name := range []string{"SavedProxyFlags", "SavedProxyServer", "SavedProxyBypass", "SavedProxyAutoURL"} {
		k.DeleteValue(name)
	}
}
