# Docker Hardened Proxy 配置指南

## 目录

1. [配置文件位置](#配置文件位置)
2. [配置结构概览](#配置结构概览)
3. [详细配置项说明](#详细配置项说明)
   - [listeners](#listeners)
   - [upstream](#upstream)
   - [namespace](#namespace)
   - [audit](#audit)
   - [logging](#logging)
4. [配置示例](#配置示例)
5. [策略详解](#策略详解)
6. [安全配置建议](#安全配置建议)

---

## 配置文件位置

Docker Hardened Proxy 启动时会按以下顺序搜索配置文件：

1. `./config.yaml`（当前目录）
2. `~/.config/docker-hardened-proxy/config.yaml`（用户配置目录）
3. `/etc/docker-hardened-proxy/config.yaml`（系统配置）
4. `/usr/local/lib/docker-hardened-proxy/config.yaml`
5. `/usr/lib/docker-hardened-proxy/config.yaml`

**注意：** 也可以通过命令行参数 `-config` 显式指定配置文件路径：
```bash
./docker-hardened-proxy -config /path/to/config.yaml
```

---

## 配置结构概览

```yaml
listeners:
  tcp:
    address: ["127.0.0.1:2375"]  # 监听地址
  unix:
    path: "/var/run/docker-proxy.sock"  # Unix 套接字路径
    mode: 0660  # 权限模式

upstream:
  url: "unix:///var/run/docker.sock"  # 上游 Docker 守护进程地址
  tls:  # 可选：TLS 配置
    ca: "/path/to/ca.pem"
    cert: "/path/to/cert.pem"
    key: "/path/to/key.pem"

namespace: "default"  # 命名空间

audit:
  # 容器创建策略
  deny_privileged: true
  deny_host_network: true
  deny_host_pid: true
  deny_host_ipc: true
  deny_privileged_mounts: []
  deny_buildkit: true
  denied_response_mode: "reason"
  
  # BuildKit 细粒度策略（仅在 deny_buildkit: false 时生效）
  buildkit:
    allow_disk_usage: false
    allow_prune: false
    allow_history: false
    session:
      allow_filesync: true
      allow_upload: true
      allow_secrets: false
      allow_ssh: false
      allow_auth: false

logging:
  level: "info"   # 日志级别
  format: "json"  # 日志格式
```

---

## 详细配置项说明

### listeners

配置代理服务的监听方式。支持 TCP 和 Unix Socket 两种方式，至少配置一种。

#### listeners.tcp

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `address` | 字符串/字符串数组 | 是 | 无 | 监听的 TCP 地址和端口 |

**格式说明：**

- 支持单个地址（字符串）或多个地址（数组）
- 地址格式：`"IP:端口"`
- 可配置 `"0.0.0.0:2375"` 监听所有接口，或 `"127.0.0.1:2375"` 仅本地访问

**示例：**
```yaml
listeners:
  tcp:
    address: "127.0.0.1:2375"  # 单地址

# 或
listeners:
  tcp:
    address:
      - "127.0.0.1:2375"
      - "0.0.0.0:2376"  # 多地址
```

#### listeners.unix

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | 字符串 | 是 | 无 | Unix 域套接字文件路径 |
| `mode` | 八进制数字 | 否 | 无 | 套接字文件权限模式 |

**格式说明：**

- `path`：Unix 套接字文件的绝对路径
- `mode`：八进制权限（如 `0660`、`0600`）

**示例：**
```yaml
listeners:
  unix:
    path: "/var/run/docker-proxy.sock"
    mode: 0660  # 所有者可读写，组用户可读写
```

---

### upstream

配置上游 Docker 守护进程的连接信息。

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `url` | 字符串 | 是 | 无 | 上游 Docker 地址 |
| `tls` | 对象 | 否 | 无 | TLS 配置（TCP 连接时使用） |

#### upstream.url

**格式：**

- Unix 套接字：`unix:///path/to/docker.sock`
- TCP 连接：`tcp://host:port`
- TCP + TLS：`tcp://host:port`（配合 `tls` 配置）

**示例：**
```yaml
upstream:
  url: "unix:///var/run/docker.sock"  # 默认 Docker 套接字

# 或
upstream:
  url: "tcp://localhost:2376"  # 远程 Docker 守护进程
```

#### upstream.tls

当使用 TCP 连接且 Docker 守护进程启用 TLS 时配置。

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `ca` | 字符串 | 否 | 无 | CA 证书文件路径 |
| `cert` | 字符串 | 否 | 无 | 客户端证书文件路径 |
| `key` | 字符串 | 否 | 无 | 客户端私钥文件路径 |

**格式说明：**

- 所有路径均为 PEM 格式文件
- `cert` 和 `key` 必须同时提供或同时省略

**示例：**
```yaml
upstream:
  url: "tcp://docker.example.com:2376"
  tls:
    ca: "/etc/docker/ca.pem"
    cert: "/etc/docker/cert.pem"
    key: "/etc/docker/key.pem"
```

---

### namespace

配置命名空间，用于容器隔离和标签管理。

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `namespace` | 字符串 | 否 | `default` | 命名空间标识符 |

**格式说明：**

- 长度：1-63 个字符
- 允许字符：字母、数字、连字符（`-`）、下划线（`_`）
- 必须以字母或数字开头
- 用于自动注入容器标签 `ltkk.run/namespace`

**示例：**
```yaml
namespace: "production"
namespace: "team-a"
namespace: "dev-environment"
```

---

### audit

安全审计配置，控制各种容器操作的权限策略。

#### audit.deny_privileged

| 值 | 说明 |
|----|------|
| `true` | 禁止创建特权容器（默认） |
| `false` | 允许创建特权容器 |

**说明：** 特权容器拥有对主机系统的完全访问权限，在生产环境中应始终禁止。

#### audit.denied_response_mode

控制拒绝请求时的响应格式。

| 值 | 说明 |
|----|------|
| `reason` | 返回详细的拒绝原因（默认，兼容旧版本） |
| `generic` | 返回固定的 `denied by policy`，减少信息泄露 |

**注意：** 此设置不影响 BuildKit 控制流升级后的拒绝响应。

#### audit.deny_host_network / deny_host_pid / deny_host_ipc

| 值 | 说明 |
|----|------|
| `true` | 禁止使用主机网络/PID/IPC 命名空间 |
| `false` | 允许使用主机命名空间 |

**安全风险：**
- `host` 网络模式：容器可直接访问主机网络接口
- `host` PID 模式：容器可看到并操作主机进程
- `host` IPC 模式：容器可与主机进程共享内存

#### audit.deny_privileged_mounts

禁止特定的挂载类型。

**格式：** 字符串数组

**可配置值：**
- `"proc"` - proc 文件系统
- `"sysfs"` - sysfs 文件系统
- 其他内核支持的挂载类型

**示例：**
```yaml
audit:
  deny_privileged_mounts: ["proc", "sysfs"]
```

#### audit.deny_buildkit

| 值 | 说明 |
|----|------|
| `true` | 完全禁止 BuildKit/buildx 操作（默认） |
| `false` | 允许 BuildKit 操作（受 `audit.buildkit` 细粒度策略控制） |

#### audit.buildkit

BuildKit 细粒度策略，仅在 `deny_buildkit: false` 时生效。

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `allow_disk_usage` | 布尔值 | `false` | 允许磁盘使用查询 |
| `allow_prune` | 布尔值 | `false` | 允许清理操作 |
| `allow_history` | 布尔值 | `false` | 允许构建历史操作 |
| `session.allow_filesync` | 布尔值 | `true` | 允许文件同步（安全文件传输） |
| `session.allow_upload` | 布尔值 | `true` | 允许上传操作（安全文件传输） |
| `session.allow_secrets` | 布尔值 | `false` | 允许密钥转发 |
| `session.allow_ssh` | 布尔值 | `false` | 允许 SSH 代理转发 |
| `session.allow_auth` | 布尔值 | `false` | 允许认证令牌操作 |

**安全建议：**
- `allow_secrets`、`allow_ssh`、`allow_auth` 默认关闭，仅在需要时开启
- 这些功能涉及敏感凭证传输，需谨慎使用

**示例：**
```yaml
audit:
  deny_buildkit: false
  buildkit:
    allow_disk_usage: true
    allow_prune: true
    session:
      allow_secrets: true  # 仅在需要时使用
```

#### audit.sysctls

控制内核参数（sysctl）的设置。

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `default_action` | 字符串 | `deny` | 默认策略：`allow` 或 `deny` |
| `allowed` | 字符串数组 | `[]` | 允许的 sysctl 键列表 |

**说明：**

- `default_action: deny`：只允许列表中指定的 sysctl
- `default_action: allow`：允许所有 sysctl（除非在拒绝列表中）

**示例：**
```yaml
audit:
  sysctls:
    default_action: deny
    allowed:
      - "net.ipv4.ip_forward"
      - "net.core.somaxconn"
```

#### audit.bind_mounts

控制主机路径绑定挂载策略。

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `default_action` | 字符串 | `deny` | 默认策略：`allow` 或 `deny` |
| `rules` | 规则数组 | `[]` | 具体的挂载规则 |

##### bind_mounts.rules

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `source_prefix` | 字符串 | 是 | 主机路径前缀 |
| `rewrite_prefix` | 字符串 | 否 | 重写后的路径前缀（用于路径转换） |
| `action` | 字符串 | 是 | `allow` 或 `deny` |

**规则匹配逻辑：**

- 使用**最长前缀匹配**原则，更具体的规则优先
- 路径基于字符串匹配，不解析符号链接
- `rewrite_prefix` 可缓解符号链接攻击

**示例：**
```yaml
audit:
  bind_mounts:
    default_action: deny
    rules:
      # 允许挂载 /home/ubuntu 及其子目录
      - source_prefix: "/home/ubuntu"
        action: allow
      # 允许挂载 /data，但映射到 /mnt/sandbox
      - source_prefix: "/data"
        rewrite_prefix: "/mnt/sandbox"
        action: allow
      # 显式拒绝敏感目录
      - source_prefix: "/etc"
        action: deny
```

#### audit.denied_capabilities

禁止添加的 Linux 能力（capabilities）列表。

**格式：** 字符串数组

**常见危险能力：**
- `SYS_ADMIN` - 系统管理权限
- `NET_ADMIN` - 网络管理权限
- `SYS_PTRACE` - 进程跟踪
- `SYS_MODULE` - 加载内核模块
- `SYS_RAWIO` - 原始 I/O 访问
- `DAC_READ_SEARCH` - 绕过文件读取权限检查

**示例：**
```yaml
audit:
  denied_capabilities:
    - "SYS_ADMIN"
    - "NET_ADMIN"
    - "SYS_PTRACE"
```

#### audit.namespaces

控制 Linux 命名空间模式的策略。

| 字段 | 类型 | 说明 |
|------|------|------|
| `network_mode.deny_host` | 布尔值 | 禁止 host 网络模式 |
| `ipc_mode.deny_host` | 布尔值 | 禁止 host IPC 模式 |
| `pid_mode.deny_host` | 布尔值 | 禁止 host PID 模式 |
| `uts_mode.deny_host` | 布尔值 | 禁止 host UTS 模式 |
| `user_ns_mode.deny_host` | 布尔值 | 禁止 host 用户命名空间模式 |
| `cgroup_ns_mode.deny_host` | 布尔值 | 禁止 host cgroup 命名空间模式 |

**示例：**
```yaml
audit:
  namespaces:
    network_mode:
      deny_host: true
    pid_mode:
      deny_host: true
```

#### audit.build

控制镜像构建策略。

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `policy` | 字符串 | `deny` | 策略：`deny`、`allow`、`list` |
| `allowed` | 字符串数组 | `[]` | `list` 策略时允许的镜像前缀 |

**策略说明：**

- `deny`：禁止所有构建
- `allow`：允许所有构建（需通过其他安全检查）
- `list`：只允许为指定镜像名称/标签进行构建

**allowed 匹配规则：**

- 以 `/` 结尾：前缀匹配（如 `myregistry.com/` 匹配该仓库下所有镜像）
- 无后缀：仓库名匹配（匹配任何标签）
- 带标签：精确匹配该标签

**示例：**
```yaml
audit:
  build:
    policy: list
    allowed:
      - "myregistry.com/"      # 允许 myregistry.com 下的所有镜像
      - "alpine:latest"        # 只允许 alpine:latest
      - "ubuntu"               # 允许 ubuntu 的任何标签
```

#### audit.pull

控制镜像拉取策略。

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `policy` | 字符串 | `allow` | 策略：`deny`、`allow`、`list` |
| `allowed` | 字符串数组 | `[]` | `list` 策略时允许的镜像前缀 |

**策略说明：**

- `allow`：允许拉取任何镜像（默认）
- `deny`：禁止所有拉取
- `list`：只允许从指定的镜像/仓库拉取

**示例：**
```yaml
audit:
  pull:
    policy: list
    allowed:
      - "docker.io/library/alpine"
      - "docker.io/library/ubuntu:"
```

#### audit.registry

控制 Docker Registry 相关操作。

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `auth` | 字符串 | `deny` | 认证策略：`deny`、`allow`、`list` |
| `auth_allowed` | 字符串数组 | `[]` | `list` 策略时允许的仓库 URL 前缀 |
| `push` | 字符串 | `deny` | 推送策略：`deny`、`allow`、`list` |
| `push_allowed` | 字符串数组 | `[]` | `list` 策略时允许推送的镜像前缀 |

**示例：**
```yaml
audit:
  registry:
    auth: list
    auth_allowed:
      - "https://myregistry.com"
      - "https://hub.docker.com"
    push: list
    push_allowed:
      - "myregistry.com/myproject/"
```

---

### logging

日志配置。

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `level` | 字符串 | 否 | `info` | 日志级别 |
| `format` | 字符串 | 否 | `json` | 日志格式 |

#### logging.level

| 值 | 说明 |
|----|------|
| `debug` | 调试信息（最详细） |
| `info` | 一般信息（默认） |
| `warn` | 警告信息 |
| `error` | 错误信息（最简略） |

#### logging.format

| 值 | 说明 |
|----|------|
| `json` | JSON 格式（结构化，适合日志收集） |
| `text` | 纯文本格式（人类可读） |

**示例：**
```yaml
logging:
  level: warn
  format: text
```

---

## 配置示例

### 1. 最小化配置

仅允许本地访问，代理到本地 Docker：

```yaml
listeners:
  tcp:
    address: "127.0.0.1:2375"

upstream:
  url: "unix:///var/run/docker.sock"
```

### 2. 生产环境安全配置

```yaml
listeners:
  unix:
    path: "/var/run/docker-proxy.sock"
    mode: 0660
  tcp:
    address: "127.0.0.1:2375"

upstream:
  url: "unix:///var/run/docker.sock"

namespace: "production"

audit:
  deny_privileged: true
  deny_host_network: true
  deny_host_pid: true
  deny_host_ipc: true
  deny_buildkit: true
  denied_response_mode: "generic"
  
  denied_capabilities:
    - "SYS_ADMIN"
    - "NET_ADMIN"
    - "SYS_PTRACE"
    - "SYS_MODULE"
    - "SYS_RAWIO"
    - "DAC_READ_SEARCH"
    - "LINUX_IMMUTABLE"
    - "NET_BIND_SERVICE"
    - "NET_BROADCAST"
    - "NET_RAW"
    - "IPC_LOCK"
    - "IPC_OWNER"
    - "SYS_CHROOT"
    - "SYS_BOOT"
    - "LEASE"
    - "AUDIT_WRITE"
    - "AUDIT_CONTROL"
    - "SETFCAP"
    - "MAC_OVERRIDE"
    - "MAC_ADMIN"
    - "SYS_PACCT"
    - "SYS_NICE"
    - "SYS_RESOURCE"
    - "SYS_TIME"
    - "SYS_TTY_CONFIG"
    - "AUDIT_READ"
    - "PERFMON"
    - "BPF"
    - "CHECKPOINT_RESTORE"
  
  sysctls:
    default_action: deny
    allowed: []
  
  bind_mounts:
    default_action: deny
    rules:
      - source_prefix: "/data/readonly"
        action: allow
      - source_prefix: "/tmp"
        action: allow
  
  namespaces:
    network_mode:
      deny_host: true
    pid_mode:
      deny_host: true
    ipc_mode:
      deny_host: true
    uts_mode:
      deny_host: true
    user_ns_mode:
      deny_host: true
    cgroup_ns_mode:
      deny_host: true
  
  build:
    policy: deny
  
  pull:
    policy: list
    allowed:
      - "docker.io/library/"
  
  registry:
    auth: deny
    push: deny

logging:
  level: info
  format: json
```

### 3. 开发环境配置

```yaml
listeners:
  tcp:
    address: "0.0.0.0:2375"
  unix:
    path: "/var/run/docker-proxy.sock"
    mode: 0666

upstream:
  url: "unix:///var/run/docker.sock"

namespace: "development"

audit:
  deny_privileged: true
  deny_host_network: false  # 开发环境允许
  deny_host_pid: true
  deny_host_ipc: true
  deny_buildkit: false      # 允许构建
  denied_response_mode: "reason"
  
  bind_mounts:
    default_action: allow   # 开发环境更宽松
    rules:
      - source_prefix: "/etc"
        action: deny        # 但仍保护系统目录
      - source_prefix: "/root"
        action: deny
  
  buildkit:
    allow_disk_usage: true
    allow_prune: true
    allow_history: true
    session:
      allow_filesync: true
      allow_upload: true
      allow_secrets: false
      allow_ssh: true       # 开发环境可用 SSH 转发
      allow_auth: true      # 开发环境可用认证
  
  build:
    policy: allow
  
  pull:
    policy: allow

logging:
  level: debug
  format: text
```

### 4. CI/CD 流水线配置

```yaml
listeners:
  tcp:
    address: "127.0.0.1:2375"

upstream:
  url: "unix:///var/run/docker.sock"

namespace: "ci"

audit:
  deny_privileged: false    # CI 可能需要特权容器
  deny_host_network: true
  deny_host_pid: true
  deny_host_ipc: true
  deny_buildkit: false
  
  build:
    policy: list
    allowed:
      - "ci-registry.local/"
  
  pull:
    policy: list
    allowed:
      - "ci-registry.local/"
      - "docker.io/library/"
  
  registry:
    auth: list
    auth_allowed:
      - "https://ci-registry.local"
    push: list
    push_allowed:
      - "ci-registry.local/"

logging:
  level: info
  format: json
```

---

## 策略详解

### 三模式策略系统

大多数策略采用三种模式之一：

| 模式 | 含义 | 使用场景 |
|------|------|----------|
| `deny` | 完全禁止 | 默认安全策略，未知端点默认拒绝 |
| `allow` | 完全允许 | 受信任环境中的便捷选项 |
| `list` | 白名单控制 | 精确控制允许的操作 |

### Fail-Closed 设计

Docker Hardened Proxy 采用"默认拒绝"（fail-closed）设计原则：

1. **未知端点**：未明确配置的路由默认拒绝
2. **新功能**：新增 Docker API 端点需要显式配置
3. **配置缺失**：缺少配置时采取最安全的默认行为

### 审计检查顺序

容器创建时的审计检查按以下顺序执行：

1. **Privileged 检查** - 拒绝特权容器
2. **Capabilities 检查** - 验证添加的能力
3. **Sysctls 检查** - 验证内核参数
4. **Bind Mounts 检查** - 验证挂载路径
5. **Security Options 检查** - 阻止危险安全选项
6. **Devices 检查** - 阻止主机设备访问
7. **OOM Kill Disable 检查** - 阻止禁用 OOM 杀手
8. **PIDs Limit 检查** - 验证进程数限制
9. **LogConfig 检查** - 阻止自定义日志驱动
10. **Namespace Modes 检查** - 验证命名空间模式
11. **Label 注入** - 自动添加命名空间标签

---

## 安全配置建议

### 生产环境最佳实践

1. **网络隔离**
   ```yaml
   listeners:
     tcp:
       address: "127.0.0.1:2375"  # 绝不监听 0.0.0.0
   ```

2. **Unix Socket 权限**
   ```yaml
   listeners:
     unix:
       path: "/var/run/docker-proxy.sock"
       mode: 0660  # 限制组访问
   ```

3. **禁用特权功能**
   ```yaml
   audit:
     deny_privileged: true
     deny_buildkit: true  # 除非确实需要
   ```

4. **最小化 bind mount**
   ```yaml
   audit:
     bind_mounts:
       default_action: deny
       rules:
         - source_prefix: "/data"
           rewrite_prefix: "/mnt/sandbox"
           action: allow
   ```

5. **使用 generic 响应模式**
   ```yaml
   audit:
     denied_response_mode: "generic"
   ```

6. **限制镜像来源**
   ```yaml
   audit:
     pull:
       policy: list
       allowed:
         - "myregistry.internal/"
   ```

### 常见错误配置

❌ **危险配置示例：**

```yaml
# 不要这样做！
listeners:
  tcp:
    address: "0.0.0.0:2375"  # 暴露给所有接口，无认证！

audit:
  deny_privileged: false      # 允许特权容器
  deny_buildkit: false        # 允许 BuildKit，但未配置细粒度策略
  denied_response_mode: "reason"  # 泄露策略细节

bind_mounts:
  default_action: allow       # 允许任何挂载
```

### 配置验证

修改配置后，使用以下命令验证：

```bash
# 启动代理并检查日志
just run -- -config ./config.yaml

# 查看配置是否正确加载
curl -s http://localhost:2375/version

# 测试安全策略
docker -H tcp://localhost:2375 run --privileged hello-world
# 应该被拒绝
```

---

## 故障排除

### 配置加载失败

**症状：** 启动时报 `reading config file` 或 `validating config` 错误

**排查步骤：**
1. 检查配置文件路径是否正确
2. 验证 YAML 语法（使用 `yamllint` 等工具）
3. 检查必需的字段是否缺失（`upstream.url`）
4. 验证枚举字段值是否在允许范围内

### 策略未生效

**症状：** 配置的拒绝策略没有阻止请求

**排查步骤：**
1. 确认使用的是 `-config` 指定的配置文件
2. 检查配置项拼写是否正确
3. 查看代理日志确认审计行为
4. 验证 `deny_buildkit: false` 时 `buildkit` 配置是否正确

### 无法连接到上游

**症状：** 请求返回连接错误

**排查步骤：**
1. 确认 `upstream.url` 指向正确的 Docker 守护进程地址
2. 检查 Unix 套接字文件权限
3. 验证 TLS 证书配置（如使用 TCP + TLS）
4. 确认 Docker 守护进程正在运行

---

## 参考

- [Docker API 文档](https://docs.docker.com/engine/api/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Docker Security](https://docs.docker.com/engine/security/)
- [OCI Runtime Spec](https://github.com/opencontainers/runtime-spec)
