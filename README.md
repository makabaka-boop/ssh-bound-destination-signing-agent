# 受限 SSH Agent 演示

本项目实现一个最小化、路径受限的 SSH agent。它启动时固定载入：

- 一把演示用 Ed25519 用户私钥；
- 固定跳板机主机公钥；
- 固定目标主机公钥；
- 固定目标用户名（默认 `deploy`）。

Agent 只允许证明这条路径：

```text
本机/已授权客户端 --(agent forwarding)--> 固定跳板机 --(SSH 认证)--> deploy@固定目标
```

容器只暴露 Unix domain socket，不发布 TCP 端口，也不主动连接任何真实 SSH 主机。

## 授权规则

每个 Unix socket 连接拥有独立绑定状态，关闭即销毁。连接必须严格按顺序收到两个 `session-bind@openssh.com`：

1. 固定跳板机主机钥，`is_forwarding = true`；
2. 固定目标主机钥，`is_forwarding = false`。

每次绑定都会验证主机钥对会话标识的 SSH 线编码 Ed25519 签名。以下请求均返回失败且不修改已有绑定：

- 主机钥、会话标识或签名不匹配；
- 目标先于跳板、认证绑定先于转发绑定等错序请求；
- 重复会话标识；
- 第二个非 forwarding 认证绑定之后再次绑定；
- 超过两个绑定；
- 任何加钥、删钥、加智能卡、证书、锁/解锁或其他未实现消息。

签名请求只有在两个绑定都完成后才可能成功。Agent 不接受任意字节，而是完整解析并逐项检查 host-bound SSH 用户认证载荷：

- 最前面的会话标识必须等于目标绑定会话标识；
- 消息类型必须是 `SSH_MSG_USERAUTH_REQUEST`；
- 用户名必须是配置的目标用户；
- service 必须是 `ssh-connection`；
- method 必须是 `publickey-hostbound-v00@openssh.com`；
- `sig-follows` 必须为 true；
- 算法必须是 `ssh-ed25519`；
- 用户公钥必须是启动时载入的演示公钥；
- 载荷末尾目标主机钥必须是固定目标主机钥并与绑定一致；
- 载荷不能有额外或缺失字段。

检查通过后，Agent 对客户端实际提交的原始载荷字节签名，不重新规范化或重建载荷。密码学签名/验签使用 Node.js `crypto`，授权状态机和字段裁决由本项目代码实现。

## 本地运行

要求 Node.js 20+，无需第三方 npm 依赖。

```bash
npm test
mkdir -p /tmp/restricted-ssh-agent
SOCKET_PATH=/tmp/restricted-ssh-agent/agent.sock \
USER_KEY_PATH=./keys/user_ed25519.pem \
JUMP_HOST_PUBLIC_KEY=./keys/jump_host_ed25519.pub \
TARGET_HOST_PUBLIC_KEY=./keys/target_host_ed25519.pub \
TARGET_USER=deploy \
npm start
```

仓库中的 `keys/` 是演示生成物，不应在生产环境使用。重新生成：

```bash
rm -rf keys
npm run generate-demo-keys -- keys
```

测试覆盖真实 Ed25519 密钥产生的合法跳板/目标绑定和 host-bound 认证载荷，并交换连接、会话、主机钥、用户名、用户钥、service、method，同时尝试任意字节签名。

## Compose

容器内 socket 固定位于：

```text
/run/restricted-ssh-agent/agent.sock
```

`docker-compose.yml` 使用 `network_mode: "none"` 和容器内 tmpfs。实际把 Unix socket 提供给同容器进程即可；这个演示不连接真实 SSH 主机。

```bash
docker compose build
docker compose up -d
docker compose exec restricted-agent test -S /run/restricted-ssh-agent/agent.sock
```

镜像构建阶段会生成一套一次性演示钥。若要使用你自己的演示钥，可修改 Dockerfile/Compose 的只读密钥挂载和以下环境变量：

- `USER_KEY_PATH`
- `JUMP_HOST_PUBLIC_KEY`
- `TARGET_HOST_PUBLIC_KEY`
- `TARGET_USER`
- `SOCKET_PATH`

## 支持的 agent 消息

- `SSH2_AGENTC_REQUEST_IDENTITIES` (11)：返回固定 Ed25519 公钥；
- `SSH2_AGENTC_SIGN_REQUEST` (13)：仅授权完整 host-bound 认证载荷；
- `SSH_AGENTC_EXTENSION` (27)：
  - `query`
  - `session-bind@openssh.com`

其他消息和扩展，包括加钥、智能卡、证书、destination constraint 加钥扩展等，均拒绝。
