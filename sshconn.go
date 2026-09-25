package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

// 每一跳（TCP 连接 + SSH 握手 + 认证）的时限。
var hopTimeout = 15 * time.Second

// sshEnv 是连接 SSH 时用到的本机环境。
type sshEnv struct {
	sshDir     string     // 默认私钥所在目录，通常是 %USERPROFILE%\.ssh
	knownHosts string     // 与 OpenSSH 共用的 known_hosts
	agentPipe  string     // ssh-agent 的命名管道，为空表示不用
	mu         sync.Mutex // 串行化 known_hosts 的读写
}

func defaultSSHEnv() *sshEnv {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".ssh")
	pipe := `\\.\pipe\openssh-ssh-agent`
	if p := os.Getenv("SSH_AUTH_SOCK"); strings.HasPrefix(p, `\\.\pipe\`) {
		pipe = p
	}
	return &sshEnv{sshDir: dir, knownHosts: filepath.Join(dir, "known_hosts"), agentPipe: pipe}
}

// clientConfig 生成连接某台服务器的配置。cleanup 在握手结束后调用，用来关闭 ssh-agent 连接。
func (e *sshEnv) clientConfig(s *Server) (cfg *ssh.ClientConfig, cleanup func(), err error) {
	cleanup = func() {}
	var auth []ssh.AuthMethod
	switch {
	case len(s.Keys) > 0:
		var signers []ssh.Signer
		for _, k := range s.Keys {
			sg, err := loadKey(k, s.Passphrase)
			if err != nil {
				return nil, nil, err
			}
			signers = append(signers, sg)
		}
		auth = append(auth, ssh.PublicKeys(signers...))

	case s.Password == "":
		// 没指定认证方式：和 OpenSSH 一样，先用 ssh-agent，再试默认私钥
		var signers []ssh.Signer
		seen := map[string]bool{}
		add := func(sg ssh.Signer) {
			if k := string(sg.PublicKey().Marshal()); !seen[k] {
				seen[k] = true
				signers = append(signers, sg)
			}
		}
		if e.agentPipe != "" {
			if conn, err := os.OpenFile(e.agentPipe, os.O_RDWR, 0); err == nil {
				cleanup = func() { conn.Close() }
				if list, err := agent.NewClient(conn).Signers(); err == nil {
					for _, sg := range list {
						add(sg)
					}
				}
			}
		}
		var locked []string
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			path := filepath.Join(e.sshDir, name)
			sg, err := loadKey(path, s.Passphrase)
			var missing *ssh.PassphraseMissingError
			switch {
			case err == nil:
				add(sg)
			case errors.As(err, &missing):
				locked = append(locked, path)
			}
		}
		if len(signers) == 0 {
			cleanup()
			if len(locked) > 0 {
				return nil, nil, fmt.Errorf("私钥 %s 有密码保护，请加上 passphrase=口令，或先把它加入 ssh-agent", strings.Join(locked, "、"))
			}
			return nil, nil, errors.New("没有可用的登录方式：请用 key= 指定私钥，或用 password= 指定密码")
		}
		auth = append(auth, ssh.PublicKeys(signers...))
	}

	if pw := s.Password; pw != "" {
		auth = append(auth, ssh.Password(pw), ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}))
	}

	return &ssh.ClientConfig{
		User:              s.User,
		Auth:              auth,
		HostKeyCallback:   e.checkHostKey,
		HostKeyAlgorithms: e.hostKeyAlgorithms(s.Addr()),
	}, cleanup, nil
}

// passphraseError 包装 ssh.PassphraseMissingError，让调用方能识别“私钥被加密”。
type passphraseError struct {
	path string
	err  *ssh.PassphraseMissingError
}

func (e *passphraseError) Error() string {
	return fmt.Sprintf("私钥 %s 有密码保护，请加上 passphrase=口令", e.path)
}
func (e *passphraseError) Unwrap() error { return e.err }

func loadKey(path, passphrase string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取私钥 %s 失败：%w", path, err)
	}
	if bytes.HasPrefix(data, []byte("PuTTY-User-Key-File")) {
		return nil, fmt.Errorf("私钥 %s 是 PuTTY 格式，请用 PuTTYgen 的 Conversions → Export OpenSSH key 导出后再用", path)
	}
	signer, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == "" {
			return nil, &passphraseError{path, missing}
		}
		if signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase)); err != nil {
			return nil, fmt.Errorf("私钥 %s 的口令不对：%w", path, err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("无法识别私钥 %s：%w", path, err)
	}
	return signer, nil
}

// ---------------------------------------------------------------- known_hosts

// HostKeyError 表示服务器的主机密钥和 known_hosts 里记录的不一致。
type HostKeyError struct {
	Host        string // known_hosts 中的写法
	Fingerprint string
	File        string
}

func (e *HostKeyError) Error() string {
	return fmt.Sprintf("主机密钥与 known_hosts 中的记录不一致（现在是 %s），可能遭到中间人攻击！"+
		"如果确认服务器重装过，请运行 ssh-keygen -R \"%s\" 删除旧记录后重连", e.Fingerprint, e.Host)
}

// knownHostName 返回 known_hosts 里的主机写法：22 端口只写主机名，其他端口写成 [主机]:端口。
func knownHostName(addr string) string {
	host, port, _ := net.SplitHostPort(addr)
	host = strings.ToLower(host)
	if port == "22" {
		return host
	}
	return "[" + host + "]:" + port
}

// lookupHost 找出 known_hosts 中属于 addr 的公钥。无法识别的行会被跳过，
// 这样文件里有本程序不支持的密钥类型也不影响使用。
func (e *sshEnv) lookupHost(addr string) (known, revoked []ssh.PublicKey, err error) {
	data, err := os.ReadFile(e.knownHosts)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	name := knownHostName(addr)
	for _, line := range bytes.Split(data, []byte("\n")) {
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts(line)
		if err != nil || marker == "cert-authority" || !matchHost(hosts, name) {
			continue
		}
		if marker == "revoked" {
			revoked = append(revoked, key)
		} else {
			known = append(known, key)
		}
	}
	return known, revoked, nil
}

// matchHost 按 OpenSSH 的规则匹配主机：支持 * ? 通配、! 排除和哈希过的主机名。
func matchHost(patterns []string, name string) bool {
	matched := false
	for _, p := range patterns {
		negate := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		var ok bool
		if strings.HasPrefix(p, "|1|") {
			ok = matchHashedHost(p, name)
		} else {
			ok = wildcardMatch(strings.ToLower(p), name)
		}
		if ok && negate {
			return false
		}
		matched = matched || ok
	}
	return matched
}

func matchHashedHost(p, name string) bool {
	salt64, hash64, ok := strings.Cut(p[len("|1|"):], "|")
	if !ok {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(salt64)
	want, err2 := base64.StdEncoding.DecodeString(hash64)
	if err1 != nil || err2 != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(name))
	return hmac.Equal(mac.Sum(nil), want)
}

func wildcardMatch(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// hostKeyAlgorithms 决定向服务器要哪种主机密钥。
// 已记录过的主机只要记录过的类型；否则 known_hosts 里存的是 ed25519、
// 服务器却先给出 ecdsa，就会被误判成指纹不符。
func (e *sshEnv) hostKeyAlgorithms(addr string) []string {
	e.mu.Lock()
	known, _, _ := e.lookupHost(addr)
	e.mu.Unlock()
	if len(known) == 0 {
		// 与 OpenSSH 的偏好一致
		return []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	var algos []string
	for _, k := range known {
		names := []string{k.Type()}
		if k.Type() == ssh.KeyAlgoRSA {
			names = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
		}
		for _, n := range names {
			if !slices.Contains(algos, n) {
				algos = append(algos, n)
			}
		}
	}
	return algos
}

// checkHostKey 校验主机密钥，首次连接时记录下来（相当于 OpenSSH 的 StrictHostKeyChecking=accept-new）。
func (e *sshEnv) checkHostKey(addr string, _ net.Addr, key ssh.PublicKey) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	known, revoked, err := e.lookupHost(addr)
	if err != nil {
		return fmt.Errorf("读取 %s 失败：%w", e.knownHosts, err)
	}
	for _, k := range revoked {
		if bytes.Equal(k.Marshal(), key.Marshal()) {
			return fmt.Errorf("%s 的主机密钥已被标记为吊销", addr)
		}
	}
	for _, k := range known {
		if bytes.Equal(k.Marshal(), key.Marshal()) {
			return nil
		}
	}
	if len(known) > 0 {
		return &HostKeyError{Host: knownHostName(addr), Fingerprint: ssh.FingerprintSHA256(key), File: e.knownHosts}
	}
	if err := e.appendKnownHost(addr, key); err != nil {
		return fmt.Errorf("写入 %s 失败：%w", e.knownHosts, err)
	}
	log.Printf("首次连接 %s，已记录主机指纹 %s", addr, ssh.FingerprintSHA256(key))
	return nil
}

func (e *sshEnv) appendKnownHost(addr string, key ssh.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(e.knownHosts), 0o700); err != nil {
		return err
	}
	line := knownHostName(addr) + " " + string(ssh.MarshalAuthorizedKey(key))
	// 原文件末尾没有换行时先补一个，免得和最后一行粘在一起
	if data, err := os.ReadFile(e.knownHosts); err == nil && len(data) > 0 && data[len(data)-1] != '\n' {
		line = "\n" + line
	}
	f, err := os.OpenFile(e.knownHosts, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ---------------------------------------------------------------- 链式连接

// HopError 指出链路中哪一跳出了问题。
type HopError struct {
	Server *Server
	Via    *Server // 上一跳，第一跳为 nil
	Dial   bool    // true：连不上这台服务器；false：连上了但 SSH 握手或认证失败
	Err    error
}

func (e *HopError) Error() string {
	if e.Dial && e.Via != nil {
		return fmt.Sprintf("经 %s 连接 %s 失败：%s", e.Via.Label(), e.Server.Label(), describeError(e.Err))
	}
	return fmt.Sprintf("%s：%s", e.Server.Label(), describeError(e.Err))
}

func (e *HopError) Unwrap() error { return e.Err }

// dialChain 依次连接链路中的每台服务器：后一跳的 TCP 连接从前一跳的 SSH 连接里转发出去。
// 返回的 clients 与 chain 一一对应，最后一个就是出口。
func dialChain(ctx context.Context, env *sshEnv, chain []*Server) ([]*ssh.Client, error) {
	var clients []*ssh.Client
	for i, s := range chain {
		var prev *ssh.Client
		if i > 0 {
			prev = clients[i-1]
		}
		c, dialFailed, err := dialHop(ctx, env, prev, s)
		if err != nil {
			closeClients(clients)
			he := &HopError{Server: s, Dial: dialFailed, Err: err}
			if i > 0 {
				he.Via = chain[i-1]
			}
			return nil, he
		}
		clients = append(clients, c)
	}
	return clients, nil
}

func dialHop(ctx context.Context, env *sshEnv, prev *ssh.Client, s *Server) (c *ssh.Client, dialFailed bool, err error) {
	cfg, cleanup, err := env.clientConfig(s)
	if err != nil {
		return nil, false, err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(ctx, hopTimeout)
	defer cancel()
	var conn net.Conn
	if prev == nil {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", s.Addr())
	} else {
		conn, err = prev.DialContext(ctx, "tcp", s.Addr())
	}
	if err != nil {
		return nil, true, err
	}

	// NewClientConn 没有超时参数，到时间就关掉底层连接让它返回
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(conn, s.Addr(), cfg)
	if !stop() {
		if err == nil {
			sc.Close()
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, false, errors.New("SSH 握手超时")
		}
		return nil, false, ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, false, err
	}
	return ssh.NewClient(sc, chans, reqs), false, nil
}

func closeClients(clients []*ssh.Client) {
	for i := len(clients) - 1; i >= 0; i-- {
		clients[i].Close()
	}
}

// describeError 把常见的网络/SSH 错误翻译成容易看懂的中文。
func describeError(err error) string {
	var (
		he   *HopError
		hk   *HostKeyError
		oce  *ssh.OpenChannelError
		dns  *net.DNSError
		nerr net.Error
	)
	msg := err.Error()
	switch {
	case errors.As(err, &he):
		return he.Error()
	case errors.As(err, &hk):
		return hk.Error()
	case errors.As(err, &oce):
		switch oce.Reason {
		case ssh.Prohibited:
			return "服务器不允许转发（检查 sshd_config 中的 AllowTcpForwarding）"
		case ssh.ConnectionFailed:
			return "连接失败（" + oce.Message + "）"
		}
		return oce.Message
	case errors.As(err, &dns):
		return "域名解析失败（" + dns.Name + "）"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &nerr) && nerr.Timeout():
		return "连接超时"
	case errors.Is(err, windows.WSAECONNREFUSED):
		return "连接被拒绝（端口没开，或者填错了？）"
	case errors.Is(err, windows.WSAECONNRESET), errors.Is(err, io.EOF):
		return "连接被对方断开"
	case strings.Contains(msg, "unable to authenticate"):
		return "认证失败（用户名、密码或私钥不对）"
	case strings.Contains(msg, "no common algorithm"):
		return "和服务器没有共同支持的算法（" + msg + "）"
	}
	return strings.TrimPrefix(msg, "ssh: handshake failed: ")
}
