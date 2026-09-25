# sshsocks

一个 Windows 托盘小工具：通过 SSH（支持任意多级跳板）在本地提供 SOCKS5 / HTTP 代理。

- 单个 exe（约 5 MB），不用安装，不依赖系统里的 ssh.exe
- 写一个很短的配置文件，保存后自动生效
- 自动连接、心跳检测、断线自动重连
- 每个端口同时是 SOCKS5 和 HTTP 代理，域名由出口服务器解析（不会在本地泄露 DNS）
- 托盘菜单一键设为系统代理（关闭或退出时恢复原来的设置）、开机自启

## 使用

1. 从 [Releases](../../releases/latest) 下载 `sshsocks.exe`，放到任意文件夹，双击运行。
   第一次运行会在它旁边生成 `sshsocks.conf` 并用记事本打开。
2. 按下面的格式填好服务器和代理，保存。托盘图标变绿就能用了。
3. 浏览器或软件里把代理设成 `127.0.0.1:端口`（SOCKS5 或 HTTP 都行），
   或者在托盘菜单「系统代理」里选一个端口。

Windows 11 会把新图标放进任务栏右下角的 `^` 里，可以把它拖到任务栏上常驻显示。

## 配置文件

```ini
[servers]
hk = root@1.2.3.4                              # 自动使用 ssh-agent 或 ~/.ssh/id_ed25519 等默认私钥
jp = root@5.6.7.8:2222  key=D:\keys\jp.pem     # 指定私钥
us = admin@us.example.com  password="my pass"  # 密码登录

[proxies]
1080 = hk                  # 单跳：从 hk 出去
1081 = hk -> us            # 两跳：先连 hk，再经 hk 连 us，从 us 出去
1082 = jp -> hk -> us      # 三跳，依此类推
1090 = root@9.9.9.9 password=xxx           # 不定义服务器，直接写也行
0.0.0.0:1088 = hk  auth=me:secret          # 给局域网用，建议加代理认证
```

- 服务器选项：`key=私钥路径`（可写多个）、`password=密码`、`passphrase=私钥口令`。
  值里有空格或 `#` 时用引号括起来。私钥的相对路径以配置文件所在目录为准，`~` 表示用户目录。
- 代理选项：`auth=用户名:密码`，SOCKS5 和 HTTP 代理都会要求认证。
- 监听地址只写端口时是 `127.0.0.1:端口`。
- `#` 开头是注释；行尾注释的 `#` 前面要有空格。
- 修改后保存即可：没改动的代理保持连接不断，改动的才会重启。配置写错时会提示第几行，
  并继续使用上一份正确的配置。

## 安全

- 主机指纹记录在 `~/.ssh/known_hosts`，和系统自带的 ssh 共用。首次连接自动记录，
  之后指纹变了会拒绝连接并提示（可能是中间人攻击）。确认服务器重装过的话，
  按提示运行 `ssh-keygen -R "主机"` 删掉旧记录即可。
- 密码是明文写在配置文件里的，能用私钥就尽量用私钥。

## 托盘菜单

- 每个代理的状态（● 已连接、○ 连接中、× 失败），子菜单里可以看失败原因、复制地址、立即重连
- 系统代理：选择一个端口，或「不使用」恢复原来的设置
- 编辑配置、查看日志、全部重连、开机自动启动、退出

## 文件与注册表

- `sshsocks.conf`、`sshsocks.log`：在 exe 旁边（exe 所在目录不可写时放在 `%APPDATA%\sshsocks`）。
  也可以用 `sshsocks.exe -c 路径` 指定配置文件。
- `HKCU\Software\sshsocks`：记住系统代理的选择，以及开启前的原设置。
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\sshsocks`：开机启动项（勾选时才有）。

## 限制

- SSH 只能转发 TCP，不支持 UDP（QUIC 等会自动回落到 TCP）。
- 不支持需要输入动态验证码的登录。
- PuTTY 格式的 `.ppk` 私钥需要先用 PuTTYgen 导出为 OpenSSH 格式。
- 服务器的 sshd 需要允许 TCP 转发（`AllowTcpForwarding`，默认就是允许的）。

## 从源码构建

需要 Go 1.26+：

```powershell
go test .                                                    # 测试（会在本机起临时 SSH 服务器）
go build -trimpath -ldflags "-s -w -H windowsgui" -o sshsocks.exe .
```

`rsrc_windows_amd64.syso` 提供程序图标和清单。需要重新生成时：

```powershell
$env:SSHSOCKS_ICON_OUT="winres"; go test -run TestWriteIcons .
go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --out rsrc --manifest gui --icon winres\icon.ico
```

## 许可证

[MIT](LICENSE)
