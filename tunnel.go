package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

type State int

const (
	StateConnecting State = iota
	StateConnected
	StateFailed
	StateStopped
)

func (s State) String() string {
	switch s {
	case StateConnecting:
		return "连接中…"
	case StateConnected:
		return "已连接"
	case StateFailed:
		return "连接失败"
	}
	return "已停止"
}

// 定义成变量是为了测试时可以调短。
var (
	keepAliveInterval = 15 * time.Second
	keepAliveTimeout  = 15 * time.Second
	maxRetryDelay     = 30 * time.Second
	stableAfter       = 10 * time.Second // 连接保持这么久才算稳定，之后断开会立即重连
	requestTimeout    = 30 * time.Second // 代理请求等待 SSH 连接并打开通道的总时限
)

var errStopped = errors.New("代理已停止")

// Tunnel 维护一条 SSH 链路，并在本地端口上提供 SOCKS5/HTTP 代理。
type Tunnel struct {
	*Proxy
	env      *sshEnv
	onChange func(*Tunnel)

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	ln        net.Listener
	retry     chan struct{}    // 失败等待中：马上重试
	reconnect chan struct{}    // 已连接：断开重连
	broken    chan *ssh.Client // 转发时发现连接已坏

	mu         sync.Mutex
	state      State
	err        error
	client     *ssh.Client   // 出口服务器的连接，未连接时为 nil
	changed    chan struct{} // 每次状态变化时关闭并换新，用来唤醒等待连接的请求
	conns      map[net.Conn]struct{}
	listenFail bool
}

func NewTunnel(p *Proxy, env *sshEnv, onChange func(*Tunnel)) *Tunnel {
	ctx, cancel := context.WithCancel(context.Background())
	return &Tunnel{
		Proxy:     p,
		env:       env,
		onChange:  onChange,
		ctx:       ctx,
		cancel:    cancel,
		retry:     make(chan struct{}, 1),
		reconnect: make(chan struct{}, 1),
		broken:    make(chan *ssh.Client, 1),
		changed:   make(chan struct{}),
		conns:     map[net.Conn]struct{}{},
	}
}

// Start 开始监听本地端口，并在后台建立和保持 SSH 连接。
func (t *Tunnel) Start() {
	ln, err := net.Listen("tcp", t.Listen)
	if err != nil {
		t.mu.Lock()
		t.listenFail = true
		t.mu.Unlock()
		t.setState(StateFailed, fmt.Errorf("无法监听 %s：%s", t.Listen, describeListenError(err)), nil)
		log.Printf("[%s] %v", t.Listen, t.Status().Err)
		return
	}
	t.ln = ln
	t.wg.Add(2)
	go t.maintain()
	go t.serve()
}

// Stop 关闭监听和所有连接，返回时后台工作都已结束。
func (t *Tunnel) Stop() {
	t.cancel()
	if t.ln != nil {
		t.ln.Close()
	}
	t.mu.Lock()
	for c := range t.conns {
		c.Close()
	}
	t.mu.Unlock()
	t.wg.Wait()
	t.setState(StateStopped, nil, nil)
}

// Reconnect 立即重连：已连接的断开重来，正在等待重试的马上重试。
func (t *Tunnel) Reconnect() {
	switch t.Status().State {
	case StateConnected:
		notify(t.reconnect)
	case StateFailed:
		notify(t.retry)
	}
}

func (t *Tunnel) ListenFailed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.listenFail
}

type TunnelStatus struct {
	Listen string
	Chain  string
	State  State
	Err    error // 失败原因；重试期间保留上一次的错误
	Conns  int   // 正在代理的连接数
}

// Failing 表示连接失败，或者失败后正在重试。
func (s TunnelStatus) Failing() bool {
	return s.State == StateFailed || s.State == StateConnecting && s.Err != nil
}

func (s TunnelStatus) Label() string {
	if s.State == StateConnecting && s.Err != nil {
		return "重试中…"
	}
	return s.State.String()
}

func (t *Tunnel) Status() TunnelStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TunnelStatus{Listen: t.Listen, Chain: t.ChainLabel(), State: t.state, Err: t.err, Conns: len(t.conns)}
}

func (t *Tunnel) setState(st State, err error, c *ssh.Client) {
	t.mu.Lock()
	if st == StateConnecting && err == nil && t.state == StateFailed {
		err = t.err // 重试期间保留上次的错误，界面上显示为“重试中”
	}
	changed := t.state != st || errText(t.err) != errText(err)
	t.state, t.err, t.client = st, err, c
	close(t.changed)
	t.changed = make(chan struct{})
	t.mu.Unlock()
	if changed && t.onChange != nil {
		t.onChange(t)
	}
}

// maintain 负责连接、心跳检测和断线重连。
func (t *Tunnel) maintain() {
	defer t.wg.Done()
	delay := time.Second
	wait := func() bool {
		select {
		case <-t.ctx.Done():
			return false
		case <-t.retry:
		case <-time.After(delay):
		}
		delay = min(delay*2, maxRetryDelay)
		return true
	}

	lastErr := "" // 同样的错误只记一次日志，免得服务器长时间不通时刷屏
	for t.ctx.Err() == nil {
		t.setState(StateConnecting, nil, nil)
		clients, err := dialChain(t.ctx, t.env, t.Chain)
		if t.ctx.Err() != nil {
			closeClients(clients)
			return
		}
		if err != nil {
			t.setState(StateFailed, err, nil)
			if err.Error() != lastErr {
				lastErr = err.Error()
				log.Printf("[%s] 连接失败：%v（将自动重试）", t.Listen, err)
			}
			if !wait() {
				return
			}
			continue
		}

		lastErr = ""
		exit := clients[len(clients)-1]
		drain(t.reconnect)
		t.setState(StateConnected, nil, exit)
		log.Printf("[%s] 已连接：%s", t.Listen, t.ChainLabel())
		since := time.Now()
		err = t.watch(exit)
		t.setState(StateConnecting, nil, nil)
		closeClients(clients)
		if t.ctx.Err() != nil {
			return
		}
		log.Printf("[%s] 连接断开（%s），正在重连", t.Listen, describeError(err))
		if time.Since(since) >= stableAfter {
			delay = time.Second
		} else if !wait() { // 刚连上就断，避免反复快速重连
			return
		}
	}
}

// watch 在连接存活期间阻塞，返回断开的原因。
func (t *Tunnel) watch(c *ssh.Client) error {
	closed := make(chan error, 1)
	go func() { closed <- c.Wait() }()
	tick := time.NewTicker(keepAliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return t.ctx.Err()
		case err := <-closed:
			if err == nil {
				err = io.EOF
			}
			return err
		case <-t.reconnect:
			return errors.New("手动重连")
		case bad := <-t.broken:
			if bad == c {
				return errors.New("转发请求失败")
			}
		case <-tick.C:
			if err := keepAlive(t.ctx, c); err != nil {
				return err
			}
		}
	}
}

// keepAlive 发一个心跳请求，服务器回复（哪怕是拒绝）就说明整条链路还通。
func keepAlive(ctx context.Context, c *ssh.Client) error {
	errc := make(chan error, 1)
	go func() {
		_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
		errc <- err
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(keepAliveTimeout):
		return errors.New("心跳超时")
	}
}

// dial 通过出口服务器连接 target。未连接时会等待连接建立（最多 requestTimeout）。
func (t *Tunnel) dial(target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(t.ctx, requestTimeout)
	defer cancel()
	c, err := t.waitClient(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		var oce *ssh.OpenChannelError
		if !errors.As(err, &oce) && ctx.Err() == nil {
			// 不是目标拒绝，而是 SSH 连接本身出了问题：让后台立即重连
			select {
			case t.broken <- c:
			default:
			}
		}
		return nil, err
	}
	return conn, nil
}

func (t *Tunnel) waitClient(ctx context.Context) (*ssh.Client, error) {
	attempted := false // 是否已经等过一次连接尝试
	for {
		t.mu.Lock()
		c, st, err, changed := t.client, t.state, t.err, t.changed
		t.mu.Unlock()
		switch {
		case c != nil:
			return c, nil
		case st == StateStopped:
			return nil, errStopped
		case st == StateFailed && attempted:
			return nil, err
		case st == StateFailed:
			notify(t.retry) // 有人要用了，不必等重试间隔
		case st == StateConnecting:
			attempted = true
		}
		select {
		case <-changed:
		case <-ctx.Done():
			if err != nil {
				return nil, err
			}
			return nil, errors.New("等待 SSH 连接超时")
		}
	}
}

// track 登记或注销一个客户端连接；代理已停止时返回 false。
func (t *Tunnel) track(c net.Conn, add bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !add {
		delete(t.conns, c)
		return true
	}
	if t.ctx.Err() != nil {
		return false
	}
	t.conns[c] = struct{}{}
	return true
}

func describeListenError(err error) string {
	switch {
	case errors.Is(err, windows.WSAEADDRINUSE):
		return "端口已被其他程序占用"
	case errors.Is(err, windows.WSAEACCES):
		return "端口被系统保留或没有权限（Hyper-V/WSL 常会保留一段端口，换一个试试）"
	case errors.Is(err, windows.WSAEADDRNOTAVAIL):
		return "本机没有这个 IP 地址"
	}
	return err.Error()
}

func notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func drain(ch chan struct{}) {
	select {
	case <-ch:
	default:
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
