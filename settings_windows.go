package main

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	appKeyPath      = `Software\sshsocks`
	runKeyPath      = `Software\Microsoft\Windows\CurrentVersion\Run`
	approvedKeyPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
	runValueName    = "sshsocks"
)

// loadSetting / saveSetting 读写 HKCU\Software\sshsocks 下的字符串，值为空表示删除。
func loadSetting(name string) string {
	k, err := registry.OpenKey(registry.CURRENT_USER, appKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue(name)
	return v
}

func saveSetting(name, value string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, appKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if value == "" {
		if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	return k.SetStringValue(name, value)
}

// autostartEnabled 判断开机启动项是否指向 cmd，并且没有在任务管理器里被禁用。
func autostartEnabled(cmd string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	v, _, err := k.GetStringValue(runValueName)
	k.Close()
	if err != nil || !strings.EqualFold(v, cmd) {
		return false
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, approvedKeyPath, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if b, _, err := k.GetBinaryValue(runValueName); err == nil && len(b) > 0 && b[0]&1 == 1 {
			return false // 在任务管理器的「启动应用」里被禁用了
		}
	}
	return true
}

func setAutostart(cmd string, on bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	// 清掉任务管理器里的禁用标记，否则启动项不生效
	if ak, err := registry.OpenKey(registry.CURRENT_USER, approvedKeyPath, registry.SET_VALUE); err == nil {
		ak.DeleteValue(runValueName)
		ak.Close()
	}
	if on {
		return k.SetStringValue(runValueName, cmd)
	}
	if err := k.DeleteValue(runValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}
