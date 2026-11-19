# Quickstart

## 安装

```bash
cd trustgate
uv sync --extra dev
```

## 1. 生成身份

```bash
uv run trustgate identity gen -o /tmp/root.json --agent-id tg:web:acme.com/root
uv run trustgate identity gen -o /tmp/worker.json --agent-id tg:web:acme.com/worker
```

## 2. 签发 compact token

```bash
uv run trustgate token issue \
  -i /tmp/root.json \
  -s user:alice \
  -a mcp:tools \
  --scope "tools.read tools.search" \
  -o /tmp/parent.tok
```

## 3. 衰减委托

```bash
uv run trustgate token delegate \
  -p /tmp/parent.tok \
  -i /tmp/worker.json \
  -a mcp:search-server \
  --scope tools.search \
  -o /tmp/child.tok
```

## 4. 校验

```bash
uv run trustgate token verify /tmp/child.tok -a mcp:search-server --scope tools.search
```

## 5. MCP Auth Proxy

终端 A — 上游回显：

```bash
uv run python examples/upstream_echo.py
```

终端 B — TrustGate proxy：

```bash
uv run trustgate proxy \
  --upstream http://127.0.0.1:9000 \
  --audience mcp:search-server \
  --scope tools.search \
  --port 8080
```

终端 C — 带 token 调用：

```bash
curl -s http://127.0.0.1:8080/tool \
  -H "X-TrustGate-Token: $(cat /tmp/child.tok)" \
  -H "Content-Type: application/json" \
  -d '{"q":"hello"}'
```

无 token 时应返回 `401 token_missing`。
