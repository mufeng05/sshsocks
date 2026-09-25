package main

import (
	"errors"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// App 管理所有代理，并把状态交给托盘显示。
type App struct {
	cfgPath   string
	logPath   string
	customCfg bool // 是否通过 -c 指定了配置文件（影响开机启动的命令行）
	env       *sshEnv
	tray      *Tray

	mu       sync.Mutex
	tunnels  []*Tunnel
	cfgErr   error
	sysProxy string            // 本程序设置的系统代理对应的监听地址
	notified map[*Tunnel]bool // 已经弹过失败通知的代理，恢复时再通知一次
	closed   bool
}

type TunnelInfo struct {
	TunnelStatus
	tunnel *Tunnel
}

type Snapshot struct {
	Tunnels   []TunnelInfo
	ConfigErr error
}

func NewApp(cfgPath, logPath string, customCfg bool) *App {
	return &App{cfgPath: cfgPath, logPath: logPath, customCfg: customCfg, env: defaultSSHEnv(), notified: map[*Tunnel]bool{}}
}

// Start 在托盘图标就绪后调用。
func (a *App) Start() {
	if _, err := os.Stat(a.cfgPath); errors.Is(err, fs.ErrNotExist) {
		if err := writeTemplate(a.cfgPath); err != nil {
			log.Printf("创建配置文件失败：%v", err)
		} else {
			log.Printf("已创建配置文件 %s", a.cfgPath)
			a.tray.Notify("欢迎使用 sshsocks", "已打开配置文件，填好服务器后保存即可生效", false)
			openWithNotepad(a.cfgPath)
		}
	}
	a.Reload()

	// 上次开着系统代理就接着开；对应的代理已不在配置里则恢复原设置
	if pref := loadSetting("SystemProxy"); pref != "" {
		if a.hasListen(pref) {
			a.SetSystemProxy(pref)
		} else {
			releaseSystemProxy(systemProxyAddr(pref))
			saveSetting("SystemProxy", "")
		}
	}
	go a.watchConfig()
}

func writeTemplate(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// 带 BOM、CRLF，各种编辑器都能正确识别中文
	text := string(rune(0xFEFF)) + strings.ReplaceAll(configTemplate, "\n", "\r\n")
	return os.WriteFile(path, []byte(text), 0o644)
}

// Reload 重新读取配置。没变的代理保持连接不动，只重启改动过的。
func (a *App) Reload() {
	cfg, err := LoadConfig(a.cfgPath)
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	if err != nil {
		a.cfgErr = err
		a.mu.Unlock()
		log.Printf("配置文件有误，未生效：%v", err)
		a.tray.Notify("配置文件有误，未生效", err.Error(), true)
		a.tray.Refresh()
		return
	}
	a.cfgErr = nil
	running := map[string]*Tunnel{}
	for _, t := range a.tunnels {
		if !t.ListenFailed() { // 上次没能监听的重新来过
			running[t.fingerprint()] = t
		}
	}
	var next, started, stopped []*Tunnel
	for _, p := range cfg.Proxies {
		if t := running[p.fingerprint()]; t != nil {
			next = append(next, t)
			continue
		}
		t := NewTunnel(p, a.env, a.onTunnelChange)
		next = append(next, t)
		started = append(started, t)
	}
	for _, t := range a.tunnels {
		if !slices.Contains(next, t) {
			stopped = append(stopped, t)
		}
	}
	a.tunnels = next
	sysProxy := a.sysProxy
	a.mu.Unlock()

	stopAll(stopped) // 先停旧的，腾出端口
	for _, t := range started {
		t.Start()
		if ip := net.ParseIP(hostOf(t.Listen)); ip != nil && !ip.IsLoopback() && t.User == "" {
			log.Printf("[%s] 注意：监听在非本机地址且没有设置 auth，局域网里的任何人都能使用这个代理", t.Listen)
		}
	}
	log.Printf("已加载配置：%d 个代理（新启动 %d 个，停止 %d 个）", len(next), len(started), len(stopped))
	a.tray.Refresh()

	if sysProxy != "" && !a.hasListen(sysProxy) {
		a.SetSystemProxy("")
		a.tray.Notify("已关闭系统代理", sysProxy+" 已从配置中删除", true)
	}
}

// watchConfig 发现配置文件被修改就重新加载。
func (a *App) watchConfig() {
	stamp := func() (time.Time, int64) {
		fi, err := os.Stat(a.cfgPath)
		if err != nil {
			return time.Time{}, -1
		}
		return fi.ModTime(), fi.Size()
	}
	lastMod, lastSize := stamp()
	for {
		time.Sleep(time.Second)
		mod, size := stamp()
		if size < 0 || mod.Equal(lastMod) && size == lastSize {
			continue
		}
		time.Sleep(300 * time.Millisecond) // 等编辑器写完
		lastMod, lastSize = stamp()
		log.Printf("配置文件已修改，重新加载")
		a.Reload()
	}
}

func (a *App) onTunnelChange(t *Tunnel) {
	st := t.Status()
	var title, text string
	a.mu.Lock()
	switch {
	case st.State == StateFailed && !a.notified[t]:
		a.notified[t] = true
		title, text = st.Listen+" 连接失败", st.Err.Error()
		if t.ListenFailed() {
			title = st.Listen + " 无法使用"
		}
	case st.State == StateConnected && a.notified[t]:
		delete(a.notified, t)
		title, text = st.Listen+" 已恢复连接", st.Chain
	case st.State == StateStopped:
		delete(a.notified, t)
	}
	a.mu.Unlock()
	if title != "" {
		a.tray.Notify(title, text, st.State == StateFailed)
	}
	a.tray.Refresh()
}

func (a *App) Snapshot() Snapshot {
	a.mu.Lock()
	tunnels, cfgErr := a.tunnels, a.cfgErr
	a.mu.Unlock()
	s := Snapshot{ConfigErr: cfgErr}
	for _, t := range tunnels {
		s.Tunnels = append(s.Tunnels, TunnelInfo{t.Status(), t})
	}
	return s
}

func (a *App) hasListen(listen string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.ContainsFunc(a.tunnels, func(t *Tunnel) bool { return t.Listen == listen })
}

// SetSystemProxy 把系统代理指向某个代理端口；listen 为空表示关闭并恢复原设置。
func (a *App) SetSystemProxy(listen string) {
	var err error
	if listen == "" {
		err = disableSystemProxy()
	} else {
		err = enableSystemProxy(systemProxyAddr(listen))
	}
	if err != nil {
		log.Printf("设置系统代理失败：%v", err)
		a.tray.Notify("设置系统代理失败", err.Error(), true)
		return
	}
	saveSetting("SystemProxy", listen)
	a.mu.Lock()
	a.sysProxy = listen
	a.mu.Unlock()
	if listen == "" {
		log.Printf("已关闭系统代理，恢复为原来的设置")
	} else {
		log.Printf("系统代理已设为 %s", systemProxyAddr(listen))
	}
}

// Reconnect 让代理立即重连；之前没能监听端口的重新尝试监听。
func (a *App) Reconnect(t *Tunnel) {
	if !t.ListenFailed() {
		t.Reconnect()
		return
	}
	nt := NewTunnel(t.Proxy, a.env, a.onTunnelChange)
	a.mu.Lock()
	i := slices.Index(a.tunnels, t)
	if i < 0 || a.closed {
		a.mu.Unlock()
		return
	}
	a.tunnels[i] = nt
	a.mu.Unlock()
	t.Stop()
	nt.Start()
}

func (a *App) ReconnectAll() {
	for _, t := range a.Snapshot().Tunnels {
		a.Reconnect(t.tunnel)
	}
}

func (a *App) EditConfig() {
	if _, err := os.Stat(a.cfgPath); errors.Is(err, fs.ErrNotExist) {
		writeTemplate(a.cfgPath)
	}
	openWithNotepad(a.cfgPath)
}

func (a *App) OpenLog() { openWithNotepad(a.logPath) }

func (a *App) autostartCmd() string {
	exe, _ := os.Executable()
	cmd := `"` + exe + `"`
	if a.customCfg {
		cmd += ` -c "` + a.cfgPath + `"`
	}
	return cmd
}

func (a *App) AutostartEnabled() bool { return autostartEnabled(a.autostartCmd()) }

func (a *App) ToggleAutostart() {
	on := !a.AutostartEnabled()
	if err := setAutostart(a.autostartCmd(), on); err != nil {
		messageBox(0, "设置开机启动失败："+err.Error(), mbIconError)
		return
	}
	log.Printf("开机自动启动：%v", on)
}

// Shutdown 停止所有代理；系统代理若仍指向本程序则恢复原设置（下次启动会重新开启）。
func (a *App) Shutdown() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	tunnels, sysProxy := a.tunnels, a.sysProxy
	a.tunnels = nil
	a.mu.Unlock()
	if sysProxy != "" {
		if err := releaseSystemProxy(systemProxyAddr(sysProxy)); err != nil {
			log.Printf("恢复系统代理设置失败：%v", err)
		}
	}
	stopAll(tunnels)
}

func stopAll(tunnels []*Tunnel) {
	var wg sync.WaitGroup
	for _, t := range tunnels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.Stop()
		}()
	}
	wg.Wait()
}

func hostOf(hostport string) string {
	h, _, _ := net.SplitHostPort(hostport)
	return h
}
