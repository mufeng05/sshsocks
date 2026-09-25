package main

import (
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig("\uFEFF" + `
# 注释
[servers]
hk = root@1.2.3.4
  ; 分号开头的行也是注释
jp = ubuntu@[2001:db8::1]:2222  key=~/.ssh/jp
us = admin@us.example.com  password="p@ss #1 'x'"  passphrase='a"b'
bastion = alice@corp@jump.example.com:2200

[proxies]
1080 = hk                    # 单跳
0.0.0.0:1081 = hk -> us  auth=me:secret
[::1]:1082 = jp->hk→us
localhost:1083 = hk, root@9.9.9.9:22 ， bastion
1084 = hk -> root@5.5.5.5:2200 password="a b" key=k1 auth=me:x
`)
	if err != nil {
		t.Fatal(err)
	}
	jp := cfg.Servers["jp"]
	if jp.Host != "2001:db8::1" || jp.Port != 2222 || jp.User != "ubuntu" || len(jp.Keys) != 1 || jp.Keys[0] != "~/.ssh/jp" {
		t.Errorf("jp = %+v", jp)
	}
	us := cfg.Servers["us"]
	if us.Password != "p@ss #1 'x'" || us.Passphrase != `a"b` || us.Port != 22 {
		t.Errorf("us = %+v", us)
	}
	if b := cfg.Servers["bastion"]; b.User != "alice@corp" || b.Host != "jump.example.com" || b.Port != 2200 {
		t.Errorf("bastion = %+v", b)
	}

	want := []struct{ listen, chain, user, pass string }{
		{"127.0.0.1:1080", "hk", "", ""},
		{"0.0.0.0:1081", "hk → us", "me", "secret"},
		{"[::1]:1082", "jp → hk → us", "", ""},
		{"127.0.0.1:1083", "hk → root@9.9.9.9 → bastion", "", ""},
		{"127.0.0.1:1084", "hk → root@5.5.5.5:2200", "me", "x"},
	}
	if len(cfg.Proxies) != len(want) {
		t.Fatalf("got %d proxies", len(cfg.Proxies))
	}
	if s := cfg.Proxies[4].Chain[1]; s.Password != "a b" || len(s.Keys) != 1 || s.Keys[0] != "k1" {
		t.Errorf("内联服务器的选项没生效：%+v", s)
	}
	if hk := cfg.Servers["hk"]; hk.Password != "" || len(hk.Keys) != 0 {
		t.Errorf("内联选项不应影响前面的 hk：%+v", hk)
	}
	for i, w := range want {
		p := cfg.Proxies[i]
		if p.Listen != w.listen || p.ChainLabel() != w.chain || p.User != w.user || p.Pass != w.pass {
			t.Errorf("proxy %d = %s %q %s:%s, want %+v", i, p.Listen, p.ChainLabel(), p.User, p.Pass, w)
		}
	}
	if cfg.Proxies[1].Chain[0] != cfg.Proxies[0].Chain[0] {
		t.Error("同名服务器应共用同一个 *Server")
	}
}

func TestParseConfigTemplate(t *testing.T) {
	cfg, err := ParseConfig(configTemplate)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 0 || len(cfg.Proxies) != 0 {
		t.Errorf("模板里的示例都是注释，不应解析出内容：%+v", cfg)
	}
	// 把示例去掉注释后应当是合法配置
	var b strings.Builder
	for _, line := range strings.Split(configTemplate, "\n") {
		if strings.HasPrefix(line, "# ") && line[2] != ' ' && strings.Contains(line, " = ") {
			line = line[2:]
		}
		b.WriteString(line + "\n")
	}
	cfg, err = ParseConfig(b.String())
	if err != nil {
		t.Fatalf("示例配置无效：%v\n%s", err, b.String())
	}
	if len(cfg.Servers) != 3 || len(cfg.Proxies) != 3 || cfg.Proxies[2].ChainLabel() != "jp → hk → us" {
		t.Errorf("示例解析结果不对：%d 台服务器，%d 个代理", len(cfg.Servers), len(cfg.Proxies))
	}
}

func TestParseConfigErrors(t *testing.T) {
	cases := []struct{ text, want string }{
		{"hk = root@1.2.3.4", "第 1 行：这一行应该写在 [servers] 或 [proxies] 下面"},
		{"[server]", "未知的段"},
		{"[servers]\nhk root@1.2.3.4", "格式应为"},
		{"[servers]\nhk = 1.2.3.4", "应为 用户名@地址"},
		{"[servers]\nhk = root@1.2.3.4:99999", "端口无效"},
		{"[servers]\nhk = root@2001:db8::1:x", "地址无效"},
		{"[servers]\nhk = root@1.2.3.4 pasword=x", `未知选项 "pasword"`},
		{"[servers]\nhk = root@1.2.3.4 password=it's", "引号没有闭合"},
		{"[servers]\nhk = root@1.2.3.4\nhk = root@1.2.3.5", "第 3 行：服务器名 \"hk\" 重复了"},
		{"[servers]\nh k = root@1.2.3.4", "不能包含空格"},
		{"[proxies]\n1080 = hk", `服务器 "hk" 没有在 [servers] 里定义`},
		{"[proxies]\n\n1080 = root@a\n127.0.0.1:1080 = root@b", "第 4 行：监听地址 127.0.0.1:1080 与第 3 行重复"},
		{"[proxies]\n70000 = root@a", "监听端口"},
		{"[proxies]\nexample.com:1080 = root@a", "必须是 IP"},
		{"[proxies]\n1080 = -> ", "没有写要经过哪些服务器"},
		{"[proxies]\n1080 = root@a auth=nopass", "auth 的格式"},
		{"[servers]\nhk = root@a\n[proxies]\n1080 = hk password=x", "要紧跟在 用户名@地址 后面"},
		{"[proxies]\n1080 = password=x root@a", "要紧跟在 用户名@地址 后面"},
		{"[proxies]\n1080 = root@a pasword=x", `未知选项 "pasword"`},
	}
	for _, c := range cases {
		_, err := ParseConfig(c.text)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseConfig(%q) = %v，应包含 %q", c.text, err, c.want)
		}
	}
}

func TestResolvePath(t *testing.T) {
	cases := map[string]string{
		`~\.ssh\id`:  `C:\home\.ssh\id`,
		`~/.ssh/id`:  `C:\home\.ssh\id`,
		`keys\a.pem`: `C:\conf\keys\a.pem`,
		`D:\k\b.pem`: `D:\k\b.pem`,
	}
	for in, want := range cases {
		if got := resolvePath(in, `C:\conf`, `C:\home`); got != want {
			t.Errorf("resolvePath(%q) = %q, want %q", in, got, want)
		}
	}
}
