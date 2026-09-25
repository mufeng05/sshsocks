package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// Server 是一台 SSH 服务器。
type Server struct {
	Name       string   // [servers] 里的名字；链路里直接写地址的为空
	User       string
	Host       string
	Port       int
	Keys       []string // 私钥文件；为空时自动使用 ssh-agent 和 ~/.ssh 下的默认私钥
	Password   string
	Passphrase string
}

func (s *Server) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

// Label 用于日志和菜单显示。
func (s *Server) Label() string {
	if s.Name != "" {
		return s.Name
	}
	if s.Port == 22 {
		return s.User + "@" + s.Host
	}
	return s.User + "@" + s.Addr()
}

// Proxy 是一个本地代理端口：流量依次经过 Chain 中的服务器，从最后一台出去。
type Proxy struct {
	Listen string
	Chain  []*Server
	User   string // 代理认证，可选
	Pass   string
}

func (p *Proxy) ChainLabel() string {
	names := make([]string, len(p.Chain))
	for i, s := range p.Chain {
		names[i] = s.Label()
	}
	return strings.Join(names, " → ")
}

// fingerprint 概括代理的全部配置，重新加载配置时据此判断要不要重启它。
func (p *Proxy) fingerprint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%q %q %q", p.Listen, p.User, p.Pass)
	for _, s := range p.Chain {
		fmt.Fprintf(&b, " | %q %q %d %q %q %q", s.User, s.Host, s.Port, s.Keys, s.Password, s.Passphrase)
	}
	return b.String()
}

type Config struct {
	Servers map[string]*Server
	Proxies []*Proxy
}

// ConfigError 指出配置文件中出错的行。
type ConfigError struct {
	Line int
	Msg  string
}

func (e *ConfigError) Error() string { return fmt.Sprintf("第 %d 行：%s", e.Line, e.Msg) }

func lineErr(line int, format string, a ...any) error {
	return &ConfigError{line, fmt.Sprintf(format, a...)}
}

// LoadConfig 读取配置文件。私钥的相对路径以配置文件所在目录为准，~ 表示用户目录。
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(string(data))
	if err != nil {
		return nil, err
	}
	home, _ := os.UserHomeDir()
	for _, p := range cfg.Proxies {
		for _, s := range p.Chain {
			for i, k := range s.Keys {
				s.Keys[i] = resolvePath(k, filepath.Dir(path), home) // 对已是绝对路径的不起作用，重复处理也无妨
			}
		}
	}
	return cfg, nil
}

func resolvePath(p, base, home string) string {
	switch {
	case p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`):
		p = filepath.Join(home, p[1:])
	case !filepath.IsAbs(p):
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}

func ParseConfig(text string) (*Config, error) {
	cfg := &Config{Servers: map[string]*Server{}}
	// 链路中的一跳：引用 [servers] 里的名字，或者直接写的地址
	type hopRef struct {
		name   string
		inline *Server
	}
	// 代理可以引用写在后面的服务器，所以先收集起来，最后再解析链路
	type proxyLine struct {
		line  int
		proxy *Proxy
		hops  []hopRef
	}
	var proxies []proxyLine
	section := ""

	for i, raw := range strings.Split(strings.TrimPrefix(text, "\uFEFF"), "\n") {
		n := i + 1
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section != "servers" && section != "proxies" {
				return nil, lineErr(n, "未知的段 [%s]，只能是 [servers] 或 [proxies]", section)
			}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if !ok || key == "" || val == "" {
			return nil, lineErr(n, "格式应为「名字 = 内容」")
		}
		words, err := splitWords(val)
		if err != nil {
			return nil, lineErr(n, "%v", err)
		}

		switch section {
		case "servers":
			if strings.ContainsFunc(key, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune("@,，→", r) }) || strings.Contains(key, "->") {
				return nil, lineErr(n, "服务器名 %q 不能包含空格、@、逗号或箭头", key)
			}
			if _, dup := cfg.Servers[key]; dup {
				return nil, lineErr(n, "服务器名 %q 重复了", key)
			}
			s, err := parseServer(words)
			if err != nil {
				return nil, lineErr(n, "%v", err)
			}
			s.Name = key
			cfg.Servers[key] = s

		case "proxies":
			listen, err := normalizeListen(key)
			if err != nil {
				return nil, lineErr(n, "%v", err)
			}
			p := &Proxy{Listen: listen}
			var hops []hopRef
			for _, w := range words {
				k, v, isOpt := cutOption(w)
				if !isOpt {
					for _, h := range splitHops(w) {
						if !strings.Contains(h, "@") {
							hops = append(hops, hopRef{name: h})
							continue
						}
						s, err := parseAddress(h)
						if err != nil {
							return nil, lineErr(n, "%v", err)
						}
						hops = append(hops, hopRef{inline: s})
					}
					continue
				}
				if strings.EqualFold(k, "auth") {
					user, pass, ok := strings.Cut(v, ":")
					if !ok || user == "" {
						return nil, lineErr(n, "auth 的格式应为 auth=用户名:密码")
					}
					p.User, p.Pass = user, pass
					continue
				}
				// 其他选项属于紧挨在前面的那个 用户名@地址
				if len(hops) == 0 || hops[len(hops)-1].inline == nil {
					return nil, lineErr(n, "选项 %s 要紧跟在 用户名@地址 后面（[servers] 里定义的服务器，选项请写在那里）", k)
				}
				if err := setServerOption(hops[len(hops)-1].inline, k, v); err != nil {
					return nil, lineErr(n, "%v", err)
				}
			}
			if len(hops) == 0 {
				return nil, lineErr(n, "没有写要经过哪些服务器")
			}
			proxies = append(proxies, proxyLine{n, p, hops})

		default:
			return nil, lineErr(n, "这一行应该写在 [servers] 或 [proxies] 下面")
		}
	}

	seen := map[string]int{}
	for _, pl := range proxies {
		if prev, dup := seen[pl.proxy.Listen]; dup {
			return nil, lineErr(pl.line, "监听地址 %s 与第 %d 行重复", pl.proxy.Listen, prev)
		}
		seen[pl.proxy.Listen] = pl.line
		for _, h := range pl.hops {
			s := h.inline
			if s == nil {
				if s = cfg.Servers[h.name]; s == nil {
					return nil, lineErr(pl.line, "服务器 %q 没有在 [servers] 里定义（也可以直接写成 用户名@地址）", h.name)
				}
			}
			pl.proxy.Chain = append(pl.proxy.Chain, s)
		}
		cfg.Proxies = append(cfg.Proxies, pl.proxy)
	}
	return cfg, nil
}

func parseServer(words []string) (*Server, error) {
	var s *Server
	for _, w := range words {
		k, v, isOpt := cutOption(w)
		if !isOpt {
			if s != nil {
				return nil, fmt.Errorf("多余的内容 %q", w)
			}
			var err error
			if s, err = parseAddress(w); err != nil {
				return nil, err
			}
			continue
		}
		if s == nil {
			return nil, errors.New("要先写 用户名@地址，再写选项")
		}
		if err := setServerOption(s, k, v); err != nil {
			return nil, err
		}
	}
	if s == nil {
		return nil, errors.New("缺少 用户名@地址")
	}
	return s, nil
}

func setServerOption(s *Server, k, v string) error {
	if v == "" {
		return fmt.Errorf("%s 的值是空的", k)
	}
	switch strings.ToLower(k) {
	case "key":
		s.Keys = append(s.Keys, v)
	case "password":
		s.Password = v
	case "passphrase":
		s.Passphrase = v
	default:
		return fmt.Errorf("未知选项 %q（服务器可用 key、password、passphrase，代理可用 auth）", k)
	}
	return nil
}

// parseAddress 解析 用户名@地址[:端口]。用户名里也可以有 @（有些堡垒机这样用）。
func parseAddress(w string) (*Server, error) {
	at := strings.LastIndex(w, "@")
	if at <= 0 || at == len(w)-1 {
		return nil, fmt.Errorf("%q 格式不对，应为 用户名@地址 或 用户名@地址:端口", w)
	}
	s := &Server{User: w[:at], Port: 22}
	hostport := w[at+1:]
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%q 中的端口无效", w)
		}
		s.Host, s.Port = h, port
	} else {
		s.Host = strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
	}
	if s.Host == "" || strings.ContainsAny(s.Host, `/\[]@`) || (strings.Contains(s.Host, ":") && net.ParseIP(s.Host) == nil) {
		return nil, fmt.Errorf("%q 中的地址无效（IPv6 地址带端口时要写成 [地址]:端口）", w)
	}
	return s, nil
}

// normalizeListen 把 "1080"、":1080"、"0.0.0.0:1080" 等写法统一成 地址:端口。
func normalizeListen(s string) (string, error) {
	host, port := "127.0.0.1", s
	if strings.Contains(s, ":") {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return "", fmt.Errorf("监听地址 %q 格式不对，应为 端口 或 地址:端口", s)
		}
		host, port = h, p
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("监听端口 %q 无效", port)
	}
	switch {
	case host == "":
		host = "0.0.0.0"
	case strings.EqualFold(host, "localhost"):
		host = "127.0.0.1"
	case net.ParseIP(host) == nil:
		return "", fmt.Errorf("监听地址 %q 必须是 IP", host)
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

// stripComment 去掉注释：# 或 ; 开头的整行，以及引号外、前面是空白的 #。
func stripComment(line string) string {
	if t := strings.TrimSpace(line); strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
		return ""
	}
	var quote rune
	prevSpace := false
	for i, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#' && prevSpace:
			return line[:i]
		}
		prevSpace = unicode.IsSpace(r)
	}
	return line
}

// splitWords 按空白切分，双引号或单引号括起来的部分保持完整（引号本身会去掉）。
func splitWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	var quote rune
	inWord := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case unicode.IsSpace(r):
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, errors.New("引号没有闭合（值里本身带引号时，用另一种引号把它括起来）")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

// cutOption 识别 名字=值 形式的选项，名字只能由字母组成。
func cutOption(w string) (key, val string, ok bool) {
	k, v, found := strings.Cut(w, "=")
	if !found || k == "" {
		return "", "", false
	}
	for _, r := range k {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return "", "", false
		}
	}
	return k, v, true
}

var hopSeparators = strings.NewReplacer("->", ",", "→", ",", "，", ",")

// splitHops 拆开 "a->b"、"a,b" 这类没有空格的链路写法。
func splitHops(w string) []string {
	var hops []string
	for _, h := range strings.Split(hopSeparators.Replace(w), ",") {
		if h = strings.TrimSpace(h); h != "" {
			hops = append(hops, h)
		}
	}
	return hops
}

const configTemplate = `# ======================================================================
#  sshsocks 配置文件（保存后自动生效，不用重启程序）
# ======================================================================
#
# [servers] 定义服务器，每行一台：
#     名字 = 用户名@地址[:端口]  [选项...]
#   可用选项：
#     key=私钥路径        不写 key 和 password 时，自动使用 ssh-agent
#                         以及 ~/.ssh 下的 id_ed25519、id_ecdsa、id_rsa
#     password=密码       用密码登录；密码里有空格或 # 时用引号括起来
#     passphrase=口令     私钥有密码保护时填写
#
# [proxies] 定义本地代理，每行一个：
#     监听地址 = 服务器1 -> 服务器2 -> ... -> 出口服务器   [auth=用户名:密码]
#   · 流量从最后一台服务器出去，前面的都是跳板，可以有任意多级
#   · 监听地址只写端口时是 127.0.0.1:端口；要给局域网用就写 0.0.0.0:端口，
#     并建议加上 auth=用户名:密码
#   · 每个端口同时是 SOCKS5 代理和 HTTP 代理
#   · 链路里也可以直接写 用户名@地址[:端口]，不必先在 [servers] 里定义，
#     选项紧跟在它后面即可，例如：1090 = root@1.2.3.4 password=xxx
#
# 主机指纹记录在 ~/.ssh/known_hosts（与系统自带的 ssh 共用）：
# 首次连接时自动记录，之后指纹变了会拒绝连接，防止中间人攻击。
#
# 下面是示例：把 # 去掉，改成你自己的服务器即可。

[servers]
# hk = root@1.2.3.4
# jp = root@5.6.7.8:2222  key=D:\keys\jp.pem
# us = admin@us.example.com  password="my password"

[proxies]
# 1080 = hk               # 单跳：从 hk 出去
# 1081 = hk -> us         # 两跳：经 hk 连到 us，从 us 出去
# 1082 = jp -> hk -> us   # 三跳
`
