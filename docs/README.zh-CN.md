# agent-audit-gateway（中文）

> **AI 智能体调用的 HTTP 审计网关** —— 传输 + Bearer 认证 + 限流，前置一个
> **故障即拒绝（fail-closed）** 的审计引擎。**默认不监听端口，默认只绑 loopback；
> 网关自身故障永远不可能放行（ALLOW）。**

```bash
pip install agent-audit-gateway          # 零依赖，Python 3.9+
```

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-34%20passed-green)
![Deps](https://img.shields.io/badge/runtime%20deps-0-green)
![Status](https://img.shields.io/badge/status-research%20prototype-orange)

<a href="https://gitcode.com/gcw_MKhSyoGN/agent-audit-gateway"><img src="https://img.shields.io/badge/GitCode-gcw_MKhSyoGN%2Fagent-audit-gateway-blue" alt="GitCode"></a>
<a href="https://github.com/langarden/agent-audit-gateway"><img src="https://img.shields.io/badge/GitHub-langarden%2Fagent-audit-gateway-black" alt="GitHub"></a>

> 研究报告级 / AI 辅助开发 · MIT 许可 · 维护者：`agent-audit-gateway maintainers`

---

部署一个端点 `POST /audit_call`，每次 Agent 工具调用都拿到裁决
（allow / deny / human）+ 可验证留痕，**无需改造你的 Agent 框架**。网关
**绝不重写裁决逻辑**——它只做传输、认证、限流。

## 为什么需要网关

你的 Agent 有能力，缺的是"调用者 → 动作"之间的**强制检查点**：

- **纯传输层**：裁决始终在 vendored 引擎里
- **只存哈希**：调用方注册表只存 sha256，明文凭据永不落盘
- **超时即拒绝**：裁决超预算直接 `ERR_TIMEOUT`，不等待引擎（fail-closed）
- **默认关闭**：不显式开启（`AUDIT_GATEWAY_ENABLE=1`）不监听任何端口

## 产品家族（Verifiable-agent 家族）

| 仓库 | 角色 |
|:--|:--|
| agent-call-audit | Agent 调用**审计引擎** |
| agent-memory-ledger | 可验证**记忆层** |
| **agent-audit-gateway** | 引擎的 HTTP **网关**（本仓库） |
| agent-route-grid | 多 Agent **路由编排** |

引擎以 **vendored** 方式原样内置（`audit_guard/` = agent-call-audit v0.1.0，
同 MIT 维护者），本仓库零依赖、可独立安装。

## 安装与快速开始

```bash
pip install agent-audit-gateway
# 或源码安装
pip install -e .
```

```python
from aag import AuditPipeline, CallerRegistry

pipeline = AuditPipeline(
    registry=CallerRegistry.from_file("rules/callers.registry.example.json"),
    timeout_ms=2000,
)
out = pipeline.adjudicate({
    "caller_id": "agent-alpha", "credential": "gateway-token-alpha-2026",
    "target_capability": "data.lookup", "action_type": "read",
    "data_class": "public", "request_hash": "…", "nonce": "n-1",
    "timestamp": 1700000000.0,
})
print(out)  # decision=allow
```

启动网关（默认关闭）：

```bash
set AUDIT_GATEWAY_ENABLE=1
set AUDIT_GATEWAY_PORT=12787
python -m aag.server
```

## 7 条失败封闭不变量

1. 默认不监听：除非 `AUDIT_GATEWAY_ENABLE=1`，且默认只绑 loopback
2. 纯传输层：裁决在引擎内，网关绝不 ALLOW
3. 认证失败即拒：Bearer token 对照 sha256 注册表，缺失/未知/禁用 → deny
4. 超时即拒：超过 `timeout_ms` → `ERR_TIMEOUT`（不咨询引擎）
5. 异常即拒：任何意外异常 → `ERR_INTERNAL` deny
6. 限流：每 IP 固定窗口，纯传输层
7. 密钥不落盘：注册表只存 sha256 哈希

## 安全与边界

- 参考实现，生产使用前请审阅代码
- 漏洞请私信 `2307788504@qq.com`（勿开公开 issue）

## 相关

- 家族体系：agent-call-audit（引擎）· agent-memory-ledger（记忆）· agent-route-grid（路由）