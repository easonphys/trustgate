# TrustGate 威胁模型 v0

## 资产

- Agent 身份私钥
- 委托 token（compact / chained）
- 审计日志（谁以何种范围调用了什么）
- 上游 MCP/工具服务

## 信任假设

- 根身份私钥由运营方安全保管（HSM/密钥库在后续版本）。
- 生产环境应使用 **trust map / 注册表** 解析公钥，而不仅依赖 token 内嵌 `pk`。
- 时钟大致同步（允许小偏差；严格 skew 后续加）。

## 威胁与缓解

| 威胁 | 缓解（v0.1） |
|------|----------------|
| 伪造 token | Ed25519 签名校验 |
| 篡改 scope/aud | 签名覆盖全部声明 |
| 委托扩权 | 每跳 `attenuate`：子 scope 必须被父允许 |
| 委托过深 | `max_depth` 强制 |
| 过期后复用 | `exp` 校验 |
| 重放 | 可选 `seen_jti`；proxy 默认启用进程内集合 |
| 撤销 | jti / agent 撤销列表 |
| 密钥进 LLM | proxy 剥离 Authorization/token，仅向上游传身份头 |

## 明确不在 v0.1 范围

- 抗量子算法
- 完整 Biscuit/Datalog 策略语言（当前为 scope 集合 + 通配）
- 跨组织联邦根与证书透明日志
- 侧信道与 DoS 完整防护

## 攻击拒识集（自动化）

见 `tests/test_adversarial.py`：篡改载荷、伪造签名、扩权委托、深度绕过、空 token。
