package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	handshakeTimeout = 30 * time.Second // 客户端发完握手/请求头的时限
	maxHeaderBytes   = 64 << 10
)

func (t *Tunnel) serve() {
	defer t.wg.Done()
	for {
		c, err := t.ln.Accept()
		if err != nil {
			if t.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[%s] 接受连接出错：%v", t.Listen, err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.handle(c)
		}()
	}
}

// handle 根据第一个字节判断协议：0x05 是 SOCKS5，其余当作 HTTP 代理请求。
func (t *Tunnel) handle(c net.Conn) {
	if !t.track(c, true) {
		c.Close()
		return
	}
	defer func() {
		t.track(c, false)
		c.Close()
	}()
	c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(c, 16<<10)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	switch first[0] {
	case 5:
		t.serveSOCKS(c, br)
	case 4: // SOCKS4 不支持
	default:
		t.serveHTTP(c, br)
	}
}

// ---------------------------------------------------------------- SOCKS5（RFC 1928 / 1929）

func (t *Tunnel) serveSOCKS(c net.Conn, br *bufio.Reader) {
	// 协商认证方式：VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	method := byte(0x00) // 无需认证
	if t.User != "" {
		method = 0x02 // 用户名/密码
	}
	if !bytes.Contains(methods, []byte{method}) {
		c.Write([]byte{5, 0xFF})
		return
	}
	if _, err := c.Write([]byte{5, method}); err != nil {
		return
	}
	if method == 0x02 && !t.socksAuth(c, br) {
		return
	}

	// 请求：VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 5 {
		return
	}
	var host string
	switch req[3] {
	case 1, 4: // IPv4、IPv6
		ip := make([]byte, 4)
		if req[3] == 4 {
			ip = make([]byte, 16)
		}
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3: // 域名：交给出口服务器解析，本机不做 DNS 查询
		n, err := br.ReadByte()
		if err != nil {
			return
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	default:
		socksReply(c, 8) // 不支持的地址类型
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(br, port); err != nil {
		return
	}
	if req[1] != 1 { // 只支持 CONNECT；SSH 无法转发 UDP
		socksReply(c, 7)
		return
	}

	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
	c.SetReadDeadline(time.Time{})
	remote, err := t.dial(target)
	if err != nil {
		t.logDialError(target, err)
		socksReply(c, socksErrorCode(err))
		return
	}
	defer remote.Close()
	if socksReply(c, 0) != nil {
		return
	}
	relay(c, br, remote)
}

func (t *Tunnel) socksAuth(c net.Conn, br *bufio.Reader) bool {
	// VER ULEN UNAME PLEN PASSWD
	readField := func() (string, bool) {
		n, err := br.ReadByte()
		if err != nil {
			return "", false
		}
		b := make([]byte, n)
		_, err = io.ReadFull(br, b)
		return string(b), err == nil
	}
	ver, err := br.ReadByte()
	if err != nil || ver != 1 {
		return false
	}
	user, ok1 := readField()
	pass, ok2 := readField()
	ok := ok1 && ok2 && t.checkAuth(user, pass)
	status := byte(1)
	if ok {
		status = 0
	}
	c.Write([]byte{1, status})
	return ok
}

func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func socksErrorCode(err error) byte {
	var oce *ssh.OpenChannelError
	if !errors.As(err, &oce) {
		return 1 // 一般性失败
	}
	switch {
	case oce.Reason == ssh.Prohibited:
		return 2 // 规则不允许
	case strings.Contains(strings.ToLower(oce.Message), "refused"):
		return 5 // 连接被拒绝
	}
	return 4 // 主机不可达
}

func (t *Tunnel) checkAuth(user, pass string) bool {
	u := subtle.ConstantTimeCompare([]byte(user), []byte(t.User))
	p := subtle.ConstantTimeCompare([]byte(pass), []byte(t.Pass))
	return u&p == 1
}

// ---------------------------------------------------------------- HTTP 代理

type httpHead struct {
	method, target, proto string
	lines                 []string // 请求头，每行一个 "Name: value"
}

func readHTTPHead(br *bufio.Reader) (*httpHead, error) {
	var lines []string
	total := 0
	for {
		var line []byte
		for {
			chunk, err := br.ReadSlice('\n')
			line = append(line, chunk...)
			if total += len(chunk); total > maxHeaderBytes {
				return nil, errors.New("请求头太大")
			}
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				return nil, err
			}
			break
		}
		s := strings.TrimRight(string(line), "\r\n")
		if s == "" {
			if len(lines) == 0 {
				continue // 容忍请求前多余的空行
			}
			break
		}
		lines = append(lines, s)
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil, errors.New("不是有效的 HTTP 请求")
	}
	return &httpHead{method: parts[0], target: parts[1], proto: parts[2], lines: lines[1:]}, nil
}

func (h *httpHead) header(name string) string {
	for _, l := range h.lines {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (t *Tunnel) serveHTTP(c net.Conn, br *bufio.Reader) {
	head, err := readHTTPHead(br)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			httpReply(c, 400, "Bad Request", err.Error())
		}
		return
	}
	c.SetReadDeadline(time.Time{})

	if t.User != "" && !t.checkBasicAuth(head.header("Proxy-Authorization")) {
		io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
			"Proxy-Authenticate: Basic realm=\"sshsocks\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}

	if strings.EqualFold(head.method, "CONNECT") {
		target := head.target
		if _, _, err := net.SplitHostPort(target); err != nil {
			target = net.JoinHostPort(target, "443")
		}
		remote, err := t.dial(target)
		if err != nil {
			t.logDialError(target, err)
			httpReply(c, 502, "Bad Gateway", "无法连接 "+target+"："+describeError(err))
			return
		}
		defer remote.Close()
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		relay(c, br, remote)
		return
	}

	authority, path, ok := splitProxyURL(head.target)
	if !ok {
		if strings.HasPrefix(head.target, "/") {
			t.serveStatusPage(c)
		} else {
			httpReply(c, 400, "Bad Request", "不支持的请求地址："+head.target)
		}
		return
	}
	target := authority
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "80")
	}
	remote, err := t.dial(target)
	if err != nil {
		t.logDialError(target, err)
		httpReply(c, 502, "Bad Gateway", "无法连接 "+target+"："+describeError(err))
		return
	}
	defer remote.Close()
	if _, err := io.WriteString(remote, head.forward(path, authority)); err != nil {
		return
	}
	relay(c, br, remote)
}

// forward 把代理请求改写成发给目标网站的普通请求。
// 加上 Connection: close，让一条客户端连接只对应一个请求，免得后续请求被发到错误的网站。
func (h *httpHead) forward(path, authority string) string {
	upgrade := h.header("Upgrade") != "" // WebSocket 等协议升级需要保留 Connection 头
	var b strings.Builder
	b.WriteString(h.method + " " + path + " " + h.proto + "\r\n")
	hasHost := false
	for _, l := range h.lines {
		name, _, _ := strings.Cut(l, ":")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "proxy-connection", "proxy-authorization":
			continue
		case "connection", "keep-alive":
			if !upgrade {
				continue
			}
		case "host":
			hasHost = true
		}
		b.WriteString(l + "\r\n")
	}
	if !hasHost {
		b.WriteString("Host: " + authority + "\r\n")
	}
	if !upgrade {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

// splitProxyURL 把 http://host:port/path?query 拆成 host:port 和 /path?query，保留原样不做转义。
func splitProxyURL(target string) (authority, path string, ok bool) {
	const scheme = "http://"
	if len(target) <= len(scheme) || !strings.EqualFold(target[:len(scheme)], scheme) {
		return "", "", false
	}
	rest := target[len(scheme):]
	authority, path = rest, "/"
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	if strings.HasPrefix(path, "?") {
		path = "/" + path
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	return authority, path, authority != ""
}

func (t *Tunnel) checkBasicAuth(header string) bool {
	scheme, cred, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return false
	}
	user, pass, _ := strings.Cut(string(raw), ":")
	return t.checkAuth(user, pass)
}

// serveStatusPage 在浏览器直接打开代理端口时显示一个说明。
func (t *Tunnel) serveStatusPage(c net.Conn) {
	st := t.Status()
	body := fmt.Sprintf("sshsocks 正在运行\n\n"+
		"这是一个 SOCKS5 / HTTP 代理端口，请把它填到浏览器或系统的代理设置里，而不是直接访问。\n\n"+
		"监听：%s\n链路：%s\n状态：%s\n", st.Listen, st.Chain, st.State)
	if st.Err != nil {
		body += "错误：" + st.Err.Error() + "\n"
	}
	httpReply(c, 200, "OK", body)
}

func httpReply(c net.Conn, code int, status, body string) {
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, status, len(body), body)
}

// logDialError 只记录目标本身连不上的情况；SSH 链路的问题已经由 maintain 记录过了。
func (t *Tunnel) logDialError(target string, err error) {
	var oce *ssh.OpenChannelError
	if errors.As(err, &oce) {
		log.Printf("[%s] 无法连接 %s：%s", t.Listen, target, describeError(err))
	}
}

// ---------------------------------------------------------------- 转发

// relay 在客户端和远端之间双向转发数据，一方关闭写入时把 EOF 传给另一方。
func relay(client net.Conn, br *bufio.Reader, remote net.Conn) {
	if n := br.Buffered(); n > 0 { // 客户端可能已经提前发来了数据
		b, _ := br.Peek(n)
		if _, err := remote.Write(b); err != nil {
			return
		}
		br.Discard(n)
	}
	errc := make(chan error, 2)
	pipe := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		errc <- err
	}
	go pipe(remote, client)
	go pipe(client, remote)
	for range 2 {
		if err := <-errc; err != nil {
			return // 调用方会关闭两端，另一个方向随之结束
		}
	}
}
