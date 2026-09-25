package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ---------------------------------------------------------------- 测试用 SSH 服务器

type testServer struct {
	ln      net.Listener
	cfg     *ssh.ServerConfig
	mu      sync.Mutex
	conns   []net.Conn
	targets []string // 收到的转发请求
}

type serverOpts struct {
	addr       string
	hostKeys   []ssh.Signer
	user       string
	password   string
	authorized ssh.PublicKey
	noForward  bool // 模拟 AllowTcpForwarding no
}

func startServer(t *testing.T, o serverOpts) *testServer {
	t.Helper()
	cfg := &ssh.ServerConfig{}
	if o.password != "" {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == o.user && string(p) == o.password {
				return nil, nil
			}
			return nil, errors.New("denied")
		}
	}
	if o.authorized != nil {
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == o.user && bytes.Equal(k.Marshal(), o.authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		}
	}
	if len(o.hostKeys) == 0 {
		o.hostKeys = []ssh.Signer{newKey(t, "ed25519")}
	}
	for _, k := range o.hostKeys {
		cfg.AddHostKey(k)
	}
	if o.addr == "" {
		o.addr = "127.0.0.1:0"
	}
	var ln net.Listener
	var err error
	for range 50 { // 重启时端口可能还没释放
		if ln, err = net.Listen("tcp", o.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{ln: ln, cfg: cfg}
	go s.accept(o.noForward)
	t.Cleanup(s.Close)
	return s
}

func (s *testServer) Addr() string { return s.ln.Addr().String() }

func (s *testServer) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *testServer) Targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

// Close 关掉监听和所有已建立的连接，模拟服务器宕机。
func (s *testServer) Close() {
	s.ln.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
}

func (s *testServer) accept(noForward bool) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		go s.serveConn(c, noForward)
	}
}

func (s *testServer) serveConn(c net.Conn, noForward bool) {
	sc, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		if noForward {
			nc.Reject(ssh.Prohibited, "administratively prohibited")
			continue
		}
		var p struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
			nc.Reject(ssh.ConnectionFailed, "bad request")
			continue
		}
		target := net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
		s.mu.Lock()
		s.targets = append(s.targets, target)
		s.mu.Unlock()
		dst, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			nc.Reject(ssh.ConnectionFailed, "Connection refused")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			dst.Close()
			continue
		}
		go ssh.DiscardRequests(creqs)
		go func() {
			done := make(chan struct{}, 2)
			go func() { io.Copy(ch, dst); ch.CloseWrite(); done <- struct{}{} }()
			go func() { io.Copy(dst, ch); dst.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
			<-done
			<-done
			ch.Close()
			dst.Close()
		}()
	}
}

func newKey(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var key any
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// writeKey 生成一个私钥文件，返回路径和对应的 Signer。
func writeKey(t *testing.T, dir, name, passphrase string) (string, ssh.Signer) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return path, signer
}

// ---------------------------------------------------------------- 辅助函数

func testEnv(t *testing.T) *sshEnv {
	dir := t.TempDir()
	return &sshEnv{sshDir: dir, knownHosts: filepath.Join(dir, "known_hosts")}
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startTunnel 按配置文本启动第一个代理。配置里的 {port} 会换成一个空闲端口。
func startTunnel(t *testing.T, env *sshEnv, conf string) *Tunnel {
	t.Helper()
	conf = strings.ReplaceAll(conf, "{port}", strconv.Itoa(freePort(t)))
	cfg, err := ParseConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	tun := NewTunnel(cfg.Proxies[0], env, nil)
	tun.Start()
	t.Cleanup(tun.Stop)
	return tun
}

func waitState(t *testing.T, tun *Tunnel, want State) TunnelStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := tun.Status()
		if st.State == want {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("状态 %v（%v），等不到 %v", st.State, st.Err, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func socksDial(proxyAddr, target, user, pass string) (net.Conn, error) {
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { c.Close(); return nil, err }
	method := byte(0)
	if user != "" {
		method = 2
	}
	c.Write([]byte{5, 1, method})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		return fail(err)
	}
	if resp[1] != method {
		return fail(fmt.Errorf("method %#x", resp[1]))
	}
	if method == 2 {
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(append(msg, byte(len(pass))), pass...)
		c.Write(msg)
		if _, err := io.ReadFull(c, resp); err != nil {
			return fail(err)
		}
		if resp[1] != 0 {
			return fail(errors.New("auth failed"))
		}
	}
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return fail(err)
	}
	if rep[1] != 0 {
		return fail(fmt.Errorf("socks reply %d", rep[1]))
	}
	return c, nil
}

// socksGet 通过 SOCKS5 代理对 target 发一个 HTTP GET，返回响应体。
func socksGet(proxyAddr, target, path string) (string, error) {
	c, err := socksDial(proxyAddr, target, "", "")
	if err != nil {
		return "", err
	}
	defer c.Close()
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, target)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func echoServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %s %s|%s|conn=%s", r.Method, r.URL.RequestURI(), r.Host, body, r.Header.Get("Connection"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------- 测试

// 三跳链路：密码、私钥、内联地址混用；分别用 SOCKS5、HTTP CONNECT、普通 HTTP 代理访问。
func TestChainAllProtocols(t *testing.T) {
	env := testEnv(t)
	keyPath, signer := writeKey(t, t.TempDir(), "id_hop2", "")
	s1 := startServer(t, serverOpts{user: "u1", password: "p1 #x"})
	s2 := startServer(t, serverOpts{user: "u2", authorized: signer.PublicKey(), hostKeys: []ssh.Signer{newKey(t, "ecdsa")}})
	s3 := startServer(t, serverOpts{user: "u3", password: "p3"})
	web := echoServer(t)
	webHost := strings.TrimPrefix(web.URL, "http://")

	tun := startTunnel(t, env, fmt.Sprintf(`
[servers]
a = u1@%s password="p1 #x"
b = u2@%s key=%s
[proxies]
{port} = a -> b -> u3@%s password=p3
`, s1.Addr(), s2.Addr(), keyPath, s3.Addr()))
	waitState(t, tun, StateConnected)
	proxyAddr := tun.Listen

	// SOCKS5
	body, err := socksGet(proxyAddr, webHost, "/socks?x=1")
	if err != nil || !strings.HasPrefix(body, "GET /socks?x=1 ") {
		t.Fatalf("SOCKS5: %q %v", body, err)
	}

	// 普通 HTTP 代理（absolute-URI），带请求体
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Post(web.URL+"/plain?y=2", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if got := string(b); got != "POST /plain?y=2 "+webHost+"|hello|conn=close" {
		t.Fatalf("HTTP: %q", got)
	}

	// HTTP CONNECT（HTTPS 网站）
	tlsWeb := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "tls ok")
	}))
	defer tlsWeb.Close()
	tr := tlsWeb.Client().Transport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(proxyURL)
	resp, err = (&http.Client{Transport: tr}).Get(tlsWeb.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "tls ok" {
		t.Fatalf("CONNECT: %q", b)
	}

	// 每一跳都只转发给下一跳，最后一跳才访问目标
	if got := s1.Targets(); len(got) != 1 || got[0] != s2.Addr() {
		t.Errorf("s1 转发了 %v", got)
	}
	if got := s2.Targets(); len(got) != 1 || got[0] != s3.Addr() {
		t.Errorf("s2 转发了 %v", got)
	}
	if got := s3.Targets(); len(got) != 3 {
		t.Errorf("s3 转发了 %v", got)
	}

	// 首次连接应把三台服务器都记进 known_hosts
	data, _ := os.ReadFile(env.knownHosts)
	for _, s := range []*testServer{s1, s2, s3} {
		if !strings.Contains(string(data), fmt.Sprintf("[127.0.0.1]:%d ", s.Port())) {
			t.Errorf("known_hosts 缺少 %s：\n%s", s.Addr(), data)
		}
	}

	// 直接用浏览器打开代理端口时显示说明页
	resp, err = http.Get("http://" + proxyAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "sshsocks 正在运行") {
		t.Errorf("状态页：%q", b)
	}
}

// known_hosts 里记的是 ed25519，服务器同时有 ecdsa 和 ed25519 时不能误报指纹不符；
// 密钥真的变了时要拒绝连接。
func TestHostKeyVerification(t *testing.T) {
	env := testEnv(t)
	ed, ec := newKey(t, "ed25519"), newKey(t, "ecdsa")
	s := startServer(t, serverOpts{user: "u", password: "p", hostKeys: []ssh.Signer{ec, ed}})
	name := knownHostName(s.Addr())
	lines := []string{
		"# comment",
		"garbage line that is not a key",
		"example.com ssh-foo AAAAB3NzaC1yc2E=", // 不认识的密钥类型
		knownhosts.Line([]string{knownhosts.HashHostname(name)}, ed.PublicKey()),
	}
	os.WriteFile(env.knownHosts, []byte(strings.Join(lines, "\n")), 0o600) // 末尾没有换行

	tun := startTunnel(t, env, fmt.Sprintf("[proxies]\n{port} = u@%s password=p", s.Addr()))
	waitState(t, tun, StateConnected)
	tun.Stop()
	if data, _ := os.ReadFile(env.knownHosts); strings.Count(string(data), "\n") != 3 {
		t.Errorf("已知主机不应再追加记录：\n%s", data)
	}

	// 服务器换了密钥（比如被中间人冒充）
	port := s.Addr()
	s.Close()
	startServer(t, serverOpts{addr: port, user: "u", password: "p", hostKeys: []ssh.Signer{newKey(t, "ed25519")}})
	tun = startTunnel(t, env, fmt.Sprintf("[proxies]\n{port} = u@%s password=p", port))
	st := waitState(t, tun, StateFailed)
	var hk *HostKeyError
	if !errors.As(st.Err, &hk) || !strings.Contains(st.Err.Error(), "ssh-keygen -R") || strings.Contains(st.Err.Error(), "handshake failed") {
		t.Fatalf("应当报主机密钥不一致，实际：%v", st.Err)
	}
}

func TestReconnect(t *testing.T) {
	env := testEnv(t)
	hostKey := newKey(t, "ed25519")
	s := startServer(t, serverOpts{user: "u", password: "p", hostKeys: []ssh.Signer{hostKey}})
	addr := s.Addr()
	web := echoServer(t)
	webHost := strings.TrimPrefix(web.URL, "http://")
	tun := startTunnel(t, env, fmt.Sprintf("[proxies]\n{port} = u@%s password=p", addr))
	waitState(t, tun, StateConnected)
	if _, err := socksGet(tun.Listen, webHost, "/1"); err != nil {
		t.Fatal(err)
	}

	s.Close() // 服务器断开
	st := waitState(t, tun, StateFailed)
	t.Logf("断开后：%v", st.Err)
	if _, err := socksGet(tun.Listen, webHost, "/2"); err == nil {
		t.Fatal("服务器不在时请求应当失败")
	}

	startServer(t, serverOpts{addr: addr, user: "u", password: "p", hostKeys: []ssh.Signer{hostKey}})
	// 请求到来时会立即重试，不必等重试间隔
	start := time.Now()
	if body, err := socksGet(tun.Listen, webHost, "/3"); err != nil || !strings.HasPrefix(body, "GET /3 ") {
		t.Fatalf("恢复后请求失败：%q %v", body, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("恢复用了 %v，应当立即重连", d)
	}
}

// freezeRelay 转发 TCP；冻结时把数据扣住但不断开连接，模拟睡眠唤醒、换网络后连接“假死”。
type freezeRelay struct {
	ln     net.Listener
	mu     sync.Mutex
	cond   *sync.Cond
	frozen bool
}

func startFreezeRelay(t *testing.T, target string) *freezeRelay {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &freezeRelay{ln: ln}
	r.cond = sync.NewCond(&r.mu)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			go r.pipe(d, c)
			go r.pipe(c, d)
		}
	}()
	t.Cleanup(func() { ln.Close(); r.freeze(false) })
	return r
}

func (r *freezeRelay) freeze(on bool) {
	r.mu.Lock()
	r.frozen = on
	r.mu.Unlock()
	r.cond.Broadcast()
}

func (r *freezeRelay) pipe(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		r.mu.Lock()
		for r.frozen {
			r.cond.Wait()
		}
		r.mu.Unlock()
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func setTimings(t *testing.T, interval, timeout, hop time.Duration) {
	oi, ot, oh := keepAliveInterval, keepAliveTimeout, hopTimeout
	keepAliveInterval, keepAliveTimeout, hopTimeout = interval, timeout, hop
	t.Cleanup(func() { keepAliveInterval, keepAliveTimeout, hopTimeout = oi, ot, oh })
}

func TestDetectDeadConnection(t *testing.T) {
	setTimings(t, 200*time.Millisecond, 300*time.Millisecond, time.Second)
	s := startServer(t, serverOpts{user: "u", password: "p"})
	relay := startFreezeRelay(t, s.Addr())
	web := echoServer(t)
	webHost := strings.TrimPrefix(web.URL, "http://")
	tun := startTunnel(t, testEnv(t), fmt.Sprintf("[proxies]\n{port} = u@%s password=p", relay.ln.Addr()))
	waitState(t, tun, StateConnected)

	relay.freeze(true)
	start := time.Now()
	for tun.Status().State == StateConnected {
		if time.Since(start) > 3*time.Second {
			t.Fatal("连接假死后没有被发现")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("%v 后发现连接假死", time.Since(start).Round(time.Millisecond))

	relay.freeze(false)
	if body, err := socksGet(tun.Listen, webHost, "/after"); err != nil || !strings.HasPrefix(body, "GET /after ") {
		t.Fatalf("网络恢复后请求失败：%q %v", body, err)
	}
}

func TestProxyAuth(t *testing.T) {
	env := testEnv(t)
	s := startServer(t, serverOpts{user: "u", password: "p"})
	web := echoServer(t)
	webHost := strings.TrimPrefix(web.URL, "http://")
	tun := startTunnel(t, env, fmt.Sprintf("[proxies]\n{port} = u@%s password=p auth=me:s3cret", s.Addr()))
	waitState(t, tun, StateConnected)

	if _, err := socksDial(tun.Listen, webHost, "", ""); err == nil {
		t.Error("没有认证的 SOCKS5 请求应被拒绝")
	}
	if _, err := socksDial(tun.Listen, webHost, "me", "wrong"); err == nil {
		t.Error("密码错误的 SOCKS5 请求应被拒绝")
	}
	c, err := socksDial(tun.Listen, webHost, "me", "s3cret")
	if err != nil {
		t.Fatalf("正确的认证被拒绝：%v", err)
	}
	c.Close()

	get := func(user *url.Userinfo) int {
		u := &url.URL{Scheme: "http", Host: tun.Listen, User: user}
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
		resp, err := client.Get(web.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(nil); code != 407 {
		t.Errorf("没有认证的 HTTP 请求返回 %d", code)
	}
	if code := get(url.UserPassword("me", "s3cret")); code != 200 {
		t.Errorf("带认证的 HTTP 请求返回 %d", code)
	}
}

func TestErrorMessages(t *testing.T) {
	s := startServer(t, serverOpts{user: "u", password: "p"})
	noFwd := startServer(t, serverOpts{user: "u", password: "p", noForward: true})
	closed := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	cases := []struct{ servers, chain, want string }{
		{"a = u@" + s.Addr() + " password=wrong", "a", "a：认证失败"},
		{"a = u@" + closed + " password=p", "a", "a：连接被拒绝"},
		{"a = u@" + s.Addr() + " password=p\nb = u@" + closed + " password=p", "a -> b", "经 a 连接 b 失败：连接失败（Connection refused）"},
		{"a = u@" + noFwd.Addr() + " password=p\nb = u@" + s.Addr() + " password=p", "a -> b", "经 a 连接 b 失败：服务器不允许转发"},
		{"a = u@" + s.Addr(), "a", "a：没有可用的登录方式"},
	}
	for _, c := range cases {
		tun := startTunnel(t, testEnv(t), "[servers]\n"+c.servers+"\n[proxies]\n{port} = "+c.chain)
		st := waitState(t, tun, StateFailed)
		if !strings.Contains(st.Err.Error(), c.want) {
			t.Errorf("%s\n  得到：%v\n  应含：%s", c.chain, st.Err, c.want)
		}
	}

	// 默认私钥有口令保护时给出明确提示
	env := testEnv(t)
	writeKey(t, env.sshDir, "id_ed25519", "pw")
	tun := startTunnel(t, env, fmt.Sprintf("[proxies]\n{port} = u@%s", s.Addr()))
	if st := waitState(t, tun, StateFailed); !strings.Contains(st.Err.Error(), "passphrase=") {
		t.Errorf("加密私钥的提示不对：%v", st.Err)
	}

	// 端口被占用
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	tun = startTunnel(t, testEnv(t), fmt.Sprintf("[proxies]\n%s = u@%s password=p", ln.Addr(), s.Addr()))
	if st := tun.Status(); st.State != StateFailed || !strings.Contains(st.Err.Error(), "占用") || !tun.ListenFailed() {
		t.Errorf("端口占用：%v %v", st.State, st.Err)
	}
}

func TestDefaultKeyAndPassphrase(t *testing.T) {
	env := testEnv(t)
	_, signer := writeKey(t, env.sshDir, "id_ed25519", "")
	locked, lockedSigner := writeKey(t, t.TempDir(), "locked", "open sesame")
	s := startServer(t, serverOpts{user: "u", authorized: signer.PublicKey()})
	s2 := startServer(t, serverOpts{user: "u", authorized: lockedSigner.PublicKey()})

	tun := startTunnel(t, env, fmt.Sprintf("[proxies]\n{port} = u@%s", s.Addr()))
	waitState(t, tun, StateConnected)

	tun = startTunnel(t, env, fmt.Sprintf("[servers]\nx = u@%s key=%s passphrase=\"open sesame\"\n[proxies]\n{port} = x", s2.Addr(), locked))
	waitState(t, tun, StateConnected)
}

func TestMatchHost(t *testing.T) {
	hashed := knownhosts.HashHostname("[example.com]:2222")
	cases := []struct {
		patterns []string
		name     string
		want     bool
	}{
		{[]string{"example.com"}, "example.com", true},
		{[]string{"EXAMPLE.com"}, "example.com", true},
		{[]string{"a.com", "example.com"}, "example.com", true},
		{[]string{"example.com"}, "[example.com]:2222", false},
		{[]string{"[example.com]:2222"}, "[example.com]:2222", true},
		{[]string{"*.example.com"}, "ssh.example.com", true},
		{[]string{"*.example.com", "!bad.example.com"}, "bad.example.com", false},
		{[]string{"192.168.?.1"}, "192.168.5.1", true},
		{[]string{hashed}, "[example.com]:2222", true},
		{[]string{hashed}, "example.com", false},
	}
	for _, c := range cases {
		if got := matchHost(c.patterns, c.name); got != c.want {
			t.Errorf("matchHost(%v, %q) = %v", c.patterns, c.name, got)
		}
	}
}

func TestHTTPForward(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("GET http://example.com/a%20b?q=1 HTTP/1.1\r\n" +
		"Host: example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic eA==\r\n" +
		"Connection: keep-alive\r\nCookie: a=b\r\n\r\n"))
	h, err := readHTTPHead(br)
	if err != nil {
		t.Fatal(err)
	}
	authority, path, ok := splitProxyURL(h.target)
	if !ok || authority != "example.com" || path != "/a%20b?q=1" {
		t.Fatalf("splitProxyURL = %q %q %v", authority, path, ok)
	}
	want := "GET /a%20b?q=1 HTTP/1.1\r\nHost: example.com\r\nCookie: a=b\r\nConnection: close\r\n\r\n"
	if got := h.forward(path, authority); got != want {
		t.Errorf("forward =\n%q\nwant\n%q", got, want)
	}
	for in, want := range map[string]string{
		"http://example.com":          "example.com /",
		"HTTP://u:p@example.com:81?x": "example.com:81 /?x",
		"http://[::1]:8080/":          "[::1]:8080 /",
	} {
		a, p, _ := splitProxyURL(in)
		if a+" "+p != want {
			t.Errorf("splitProxyURL(%q) = %q %q", in, a, p)
		}
	}
}
