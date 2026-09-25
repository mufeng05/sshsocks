// sshsocks：通过 SSH（支持多级跳板）提供本地 SOCKS5/HTTP 代理的托盘小工具。
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
)

const version = "1.0.0"

func main() {
	cfgFlag := flag.String("c", "", "配置文件路径，默认是程序所在目录下的 sshsocks.conf")
	flag.Parse()

	cfgPath, err := configPath(*cfgFlag)
	if err != nil {
		messageBox(0, "找不到配置文件的位置："+err.Error(), mbIconError)
		return
	}
	logPath := filepath.Join(filepath.Dir(cfgPath), "sshsocks.log")
	if w, err := openLog(logPath); err == nil {
		log.SetOutput(w)
	}

	if !acquireInstanceLock() {
		// 已经在运行了：让它弹个提示，本进程直接退出
		if hwnd := findTrayWindow(); hwnd != 0 {
			procPostMessageW.Call(hwnd, wmPing, 0, 0)
		}
		return
	}
	setDPIAware()
	allowDarkMenus()

	log.Printf("sshsocks %s 启动，配置文件：%s", version, cfgPath)
	app := NewApp(cfgPath, logPath, *cfgFlag != "")
	if err := runTray(app); err != nil {
		log.Printf("启动失败：%v", err)
		messageBox(0, "启动失败："+err.Error(), mbIconError)
	}
	app.Shutdown()
	log.Printf("sshsocks 已退出")
}

// configPath 决定配置文件的位置：默认放在程序旁边，程序目录不可写（比如在
// Program Files 下）时改用 %APPDATA%\sshsocks。
func configPath(arg string) (string, error) {
	if arg != "" {
		return filepath.Abs(arg)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	p := filepath.Join(dir, "sshsocks.conf")
	if _, err := os.Stat(p); err == nil || dirWritable(dir) {
		return p, nil
	}
	appData, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(appData, "sshsocks", "sshsocks.conf"), nil
}

func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".sshsocks-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// logFile 超过 1 MB 时把旧日志改名为 .old，只保留一份。
type logFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

const maxLogSize = 1 << 20

func openLog(path string) (*logFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	fi, _ := f.Stat()
	debug.SetCrashOutput(f, debug.CrashOptions{}) // 图形界面程序没有控制台，崩溃信息也写进日志
	return &logFile{path: path, f: f, size: fi.Size()}, nil
}

func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.size+int64(len(p)) > maxLogSize {
		l.f.Close()
		os.Rename(l.path, l.path+".old")
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return 0, err
		}
		l.f, l.size = f, 0
		debug.SetCrashOutput(f, debug.CrashOptions{})
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}
