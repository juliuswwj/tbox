# tbox 项目环境配置

## Android 构建环境变量

构建 Android APK 前需设置以下环境变量：

```bash
export ANDROID_HOME=/opt/tools
export ANDROID_NDK_HOME=/usr/lib/android-sdk/ndk/28.2.13676358
export PATH=$PATH:$(go env GOPATH)/bin
```

- SDK: `/opt/tools` (build-tools 34.0.0, platforms android-34)
- NDK: `/usr/lib/android-sdk/ndk/28.2.13676358`
- gomobile: 需通过 `go install golang.org/x/mobile/cmd/gomobile@latest` 安装，然后 `gomobile init`

## 构建命令

```bash
# 编译 APK（先构建 AAR，再 assembleDebug）
make android-apk

# 仅构建 AAR
make android

# 编译 Go 二进制
make build

# 运行单元测试
make test
```

APK 输出路径：`android/app/build/outputs/apk/debug/app-debug.apk`

## Android 客户端连接状态诊断

客户端不再直接跳转到 CONNECTED，而是经过以下状态转换：

```
IDLE → CONNECTING → CHECKING → CONNECTED
                              → CONNECTED_NO_NET
```

1. **CONNECTING**: VpnService 启动，TUN 接口创建中。
2. **CHECKING**: TUN 创建后进入连通性检测阶段。通过 TUN 隧道向 `https://ifconfig.io` 发 HEAD 请求，渐进式重试（1.5s → 3s → ... → 最大 10 次）。确认 HTTP 200 后进入 CONNECTED。
3. **CONNECTED**: 隧道畅通，显示 TUN IP。
4. **CONNECTED_NO_NET**: 隧道建立但流量不通，或后续定期检测（30s 间隔）发现断开。

健康检测需要 app 自身流量经过 TUN，因此 `createTun()` 中**不再调用 `addDisallowedApplication`**。sing-box 的 carrier socket 由 `VpnService.protect()` 保护绕过 VPN，不会产生路由环路。

## ADB 设备

设备 FIONJFFU9XDM5LPB (USB 连接)，安装命令：

```bash
adb install android/app/build/outputs/apk/debug/app-debug.apk
```

## Pi 设备 (orangepizero2w) service 冲突问题

Pi 上的 `wifi-server.service` (旧) 和 `wifi-ui.service` (新) 是重复的服务，都监听 port 80 并启动同一个 `wifi_server.py`。旧服务先启动抢到端口，新服务 crash-loop。

**修复**：`sudo systemctl disable --now wifi-setup.service` 停掉旧服务。

## Pi 设备 (orangepizero2w) DNS 架构

### DNS 路由强制规则（不要动！）

Pi 上的 iptables 规则是**有意设置**的：

```bash
iptables -I OUTPUT 1 -o wlan0 -p udp --dport 53 -j DROP
iptables -I OUTPUT 1 -o wlan0 -p tcp --dport 53 -j DROP
```

这些规则**不是 bug**，是为了**防止 DNS 经过 wlan0 被污染**。DNS 唯一定向路径：`ip rule to 8.8.8.8/1.1.1.1 lookup tbox0` → table 100 → tbox0 隧道。

### 网络拓扑

```
Internet ←→ tbox 隧道 ←→ tbox0 (172.30.0.2/24) ←→ Pi
                                       ↕ (table 100: default via 172.30.0.1)
                                dnsmasq → 8.8.8.8/1.1.1.1
                                       ↕
                                 br-lan (10.6.8.1/24)
                                       ↕
                               WiFi/USB 客户端
```

### dnsmasq 工作方式

- **不是** systemd 管理 (`systemctl status dnsmasq` 显示 disabled/inactive 是正常的)
- 由 **NetworkManager 共享连接**启动（br-lan NAT 模式）
- 命令行特征：`--bind-interfaces --except-interface=lo --listen-address=10.6.8.1`
- upstream DNS 从 `/etc/resolv.conf` 读取（8.8.8.8, 1.1.1.1）

### table 100 路由丢失问题

**症状**：dnsmasq 不工作，Pi 本机 `nslookup` 也失败
**根因**：tbox 隧道重连 → tbox0 接口 down/up → 内核自动清除 table 100 中 tbox0 的路由 → DNS 查询无法走到 table 100 → 被 OUTPUT DROP 拦截
**修复**：`deploy/mode-apply.sh` 在 `/etc/NetworkManager/dispatcher.d/90-tbox0-route` 安装了 NM dispatcher，在 tbox0 up/dhcp4-change 时自动 `ip route replace default via <gw> dev tbox0 table 100`

### 路由配置脚本

路由规则在 `deploy/` 目录的脚本中，**不在 tbox Go 源码中**：
- `deploy/mode-apply.sh` — 主模式切换脚本，设置 ip rule / table 100 / iptables / redsocks
- `deploy/redsocks-watchdog.sh` — redsocks 存活监控

### 调试注意事项

1. **不要在 Pi 本机测试 dnsmasq**：`nslookup - 10.6.8.1` 走 lo 接口，被 dnsmasq `--except-interface=lo` 忽略。应**从 br-lan 客户端测试**或用 `tcpdump -i any port 53` 观察。
2. **不要删除 OUTPUT DROP 规则**：它们是强制 DNS 走隧道的关键。
3. **Pi 本机 DNS 正常但 dnsmasq 失败**：优先检查 `ip route show table 100` 是否为空。
4. **dnsmasq 上游可达性验证**：`sudo nsenter -t $(pgrep -f 'dnsmasq.*br-lan') -n nslookup baidu.com`
5. **部署到 Pi**：`scp deploy/mode-apply.sh pi:/home/orangepi/tbox/`
6. **webUI "no tunnel" 误报**：`wifi_server.py` 中 `get_exit_ip()` 使用 `--socks5-hostname`（代理端 DNS）而非 `--socks5`（本地 DNS），避免 Pi 本机 DNS 被 iptables 阻断导致隧道检查失败。`/api/status` 主动调用 `get_exit_ip()` 而非读缓存。
