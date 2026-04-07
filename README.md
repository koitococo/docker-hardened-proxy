# Docker Hardened Proxy

一个面向 Docker 守护进程 API 的安全加固代理。通过在 Docker API 前端拦截容器操作请求，根据可配置的安全策略进行审计、拒绝或重写，实现基于命名空间的容器隔离和细粒度的安全控制。

## 核心特性

- **Fail-Closed 安全设计** - 默认拒绝所有未明确允许的 Docker API 端点
- **命名空间隔离** - 通过 `ltkk.run/namespace` 标签实现容器逻辑隔离
- **细粒度策略控制** - 支持 deny/allow/list 三种模式的安全策略
- **容器创建审计** - 检查特权模式、capabilities、bind mounts、sysctl 等 20+ 安全项
- **BuildKit 安全管控** - 完整的 BuildKit 会话和方法级审计
- **响应模式控制** - 可选择详细或泛化的拒绝响应，减少信息泄露

## 架构概述

```
客户端 (docker CLI) 
    ↓
Docker Hardened Proxy (监听 :2375)
    ↓
[路由分类] → [策略审计] → [请求重写]
    ↓
Docker 守护进程 (/var/run/docker.sock)
```

代理在请求转发前执行多层安全检查，拦截危险操作并自动注入命名空间标签。

## 快速开始

### 使用 Docker 运行

```bash
# 构建镜像
docker build -t docker-hardened-proxy .

# 运行代理（带配置）
docker run -d \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/config.yaml:/etc/docker-hardened-proxy/config.yaml \
  -p 127.0.0.1:2375:2375 \
  docker-hardened-proxy

# 使用代理访问 Docker
docker -H tcp://localhost:2375 ps
docker -H tcp://localhost:2375 run hello-world
```

### 本地开发

```bash
# 克隆项目
git clone <repo-url>
cd docker-hardened-proxy

# 构建二进制文件
just build

# 使用默认配置运行
just run

# 指定配置文件运行
just run -- -config ./config.yaml

# 运行测试
just test
```

## 配置指南

完整的配置文档请参阅 [**docs/configuration-guide.md**](docs/configuration-guide.md)，包含：

- 所有配置项的详细说明和格式要求
- 生产环境、开发环境、CI/CD 的完整配置示例
- 安全最佳实践和常见错误配置
- 故障排除指南

### 最小配置示例

```yaml
listeners:
  tcp:
    address: ["127.0.0.1:2375"]

upstream:
  url: "unix:///var/run/docker.sock"

namespace: "default"

audit:
  deny_privileged: true
  deny_buildkit: true

logging:
  level: "info"
  format: "json"
```

配置文件搜索顺序（未使用 `-config` 指定时）：
1. `./config.yaml`
2. `~/.config/docker-hardened-proxy/config.yaml`
3. `/etc/docker-hardened-proxy/config.yaml`

## 安全策略

### 三模式策略系统

所有策略均支持三种模式：

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| `deny` | 完全禁止（大多数策略的默认值） | 最小权限原则 |
| `allow` | 完全允许 | 受信任环境 |
| `list` | 仅允许白名单中的项目 | 精确控制 |

### 审计的 Docker 端点

| 端点 | 审计内容 | 配置位置 |
|------|----------|----------|
| `POST /containers/create` | 特权模式、capabilities、bind mounts、sysctl、namespace 模式、安全选项等 | `audit.*` |
| `POST /containers/{id}/exec` | 安全选项检查 | `audit.*` |
| `POST /build` | 构建策略、危险权限、网络模式 | `audit.build` |
| `POST /images/create` (pull) | 镜像拉取白名单 | `audit.pull` |
| `POST /auth` | 仓库认证白名单 | `audit.registry.auth` |
| `POST /images/{name}/push` | 镜像推送白名单 | `audit.registry.push` |
| BuildKit `/session` | 会话服务方法审计 | `audit.buildkit.session` |
| BuildKit `/grpc` | Solve 请求和 LLB 定义审计 | `audit.buildkit` |

### 容器创建审计检查项（按顺序）

1. **Privileged** - 拒绝 `--privileged` 容器
2. **Capabilities** - 检查 `CapAdd` 是否在拒绝列表
3. **Sysctls** - 验证内核参数白名单
4. **Bind Mounts** - 路径前缀匹配和重写
5. **Security Options** - 阻止危险选项（如 `seccomp=unconfined`）
6. **Devices** - 拒绝主机设备访问
7. **OOM Kill Disable** - 阻止禁用 OOM 杀手
8. **PIDs Limit** - 验证进程数限制
9. **LogConfig** - 阻止自定义日志驱动
10. **Namespace Modes** - 拒绝 `host` 模式，跟踪 `container:{id}` 引用
11. **Label 注入** - 自动添加 `ltkk.run/namespace` 和 `ltkk.run/managed-by`

## 命名空间隔离

容器自动被标记命名空间标签：

```yaml
# 配置
namespace: "team-a"

# 容器将自动获得标签：
# ltkk.run/namespace=team-a
# ltkk.run/managed-by=docker-hardened-proxy
```

跨命名空间操作会被拒绝，实现多租户隔离。

## 拒绝响应模式

`audit.denied_response_mode` 控制 HTTP 403 响应内容：

- **`reason`** (默认) - 返回详细拒绝原因，如 `"privileged mode is denied"`，兼容现有工具
- **`generic`** - 返回固定 `"denied by policy"`，减少信息泄露

> 注意：此设置不影响 BuildKit 控制流升级后的拒绝响应。

## 安全默认值

- **Bind mounts** - 默认拒绝，需显式配置允许规则
- **Privileged 容器** - 默认拒绝
- **危险 capabilities** (SYS_ADMIN 等) - 可配置拒绝列表
- **BuildKit** - 默认完全拒绝
- **未知端点** - 默认拒绝（Fail-Closed）
- **Host 命名空间模式** - 可配置拒绝

## 文档

- [完整配置指南](docs/configuration-guide.md) - 所有配置选项的详细说明
- [config.example.yaml](config.example.yaml) - 支持的配置项参考
- [internal/audit/AGENTS.md](internal/audit/AGENTS.md) - 审计模块开发指南
- [AGENTS.md](AGENTS.md) - 项目开发指南

## 开发

```bash
just test      # 运行完整测试套件
go test -v ./...  # 详细测试输出

just lint      # 运行代码检查
go vet ./...   # 标准 linter

just build     # 构建二进制文件
just run       # 使用默认配置运行
```

### 常用测试命令

```bash
# 测试特定功能
go test -v ./internal/audit -run TestAuditCreatePrivilegedDenied
go test -v ./internal/audit/...
go test -v ./internal/proxy/...
go test -v ./internal/config/...
```

## 许可证

[添加许可证信息]
