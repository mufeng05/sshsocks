package main

import (
	"os"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// 会临时修改本机的系统代理设置，所以默认不运行：
//
//	$env:SSHSOCKS_TEST_SYSPROXY=1; go test -run TestSystemProxyRoundTrip -v .
func TestSystemProxyRoundTrip(t *testing.T) {
	if os.Getenv("SSHSOCKS_TEST_SYSPROXY") == "" {
		t.Skip("未设置 SSHSOCKS_TEST_SYSPROXY")
	}
	if _, saved := loadSavedProxy(); saved {
		t.Fatal("注册表里已有保存的代理设置，可能有 sshsocks 正在运行，先退出它")
	}
	_, keyErr := registry.OpenKey(registry.CURRENT_USER, appKeyPath, registry.QUERY_VALUE)
	hadKey := keyErr == nil
	regBefore := internetSettingsValues(t)
	before, err := queryProxySettings()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("原设置：flags=%d server=%q bypass=%q autoURL=%q", before.flags, before.server, before.bypass, before.autoURL)
	defer func() {
		// 无论测试结果如何都要恢复原样
		if cur, _ := queryProxySettings(); cur == nil || *cur != *before {
			applyProxySettings(before)
		}
		clearSavedProxy()
		if !hadKey {
			registry.DeleteKey(registry.CURRENT_USER, appKeyPath)
		}
	}()

	if err := enableSystemProxy("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	on, _ := queryProxySettings()
	if !on.pointsTo("127.0.0.1:18080") || on.bypass != proxyBypass || on.autoURL != "" {
		t.Errorf("开启后：%+v", on)
	}
	if saved, ok := loadSavedProxy(); !ok || *saved != *before {
		t.Errorf("保存的原设置不对：%+v", saved)
	}
	if reg := internetSettingsValues(t); reg["ProxyEnable"] != "1" || reg["ProxyServer"] != "127.0.0.1:18080" {
		t.Errorf("注册表没有生效：%v", reg)
	}

	// 已被其他程序改掉时，退出不应该动它
	other := &proxySettings{flags: proxyTypeDirect | proxyTypeProxy, server: "127.0.0.1:65000", bypass: "<local>"}
	applyProxySettings(other)
	if err := releaseSystemProxy("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	if cur, _ := queryProxySettings(); !cur.pointsTo("127.0.0.1:65000") {
		t.Errorf("释放时改动了其他程序的设置：%+v", cur)
	}
	if _, ok := loadSavedProxy(); ok {
		t.Error("释放后应清除保存的设置")
	}

	// 正常的开启 → 关闭流程要完整恢复
	applyProxySettings(before)
	enableSystemProxy("127.0.0.1:18080")
	if err := disableSystemProxy(); err != nil {
		t.Fatal(err)
	}
	after, _ := queryProxySettings()
	if *after != *before {
		t.Errorf("关闭后没有恢复原设置：\n  原来 %+v\n  现在 %+v", before, after)
	}
	if reg := internetSettingsValues(t); len(reg) != len(regBefore) || reg["ProxyEnable"] != regBefore["ProxyEnable"] ||
		reg["ProxyServer"] != regBefore["ProxyServer"] || reg["ProxyOverride"] != regBefore["ProxyOverride"] || reg["AutoConfigURL"] != regBefore["AutoConfigURL"] {
		t.Errorf("注册表没有恢复：\n  原来 %v\n  现在 %v", regBefore, reg)
	}
}

func internetSettingsValues(t *testing.T) map[string]string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	vals := map[string]string{}
	for _, name := range []string{"ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"} {
		if s, _, err := k.GetStringValue(name); err == nil {
			vals[name] = s
		} else if n, _, err := k.GetIntegerValue(name); err == nil {
			vals[name] = string(rune('0' + n))
		}
	}
	return vals
}
