# Agent 安全框架设计：洋葱模型、零信任原则与 AgentCore 实践

> Agent 的行为可以是非确定性的，但包围 Agent 的身份验证、工具授权、凭证管理和运行时隔离必须是确定性的。

---

## 目录

- [一、开篇：一场测试如何越过边界](#一开篇一场测试如何越过边界)
- [二、Agent应用面临的安全挑战](#二agent应用面临的安全挑战)
  - [2.1 Agent 不是无状态应用](#21-agent-不是无状态应用)
  - [2.2 容器不是不可突破的最终边界](#22-容器不是不可突破的最终边界)
- [三、建立从单点防护到体系化安全的整套机制](#三建立从单点防护到体系化安全的整套机制)
  - [3.1 洋葱模型：把控制部署在多层嵌套边界上](#31-洋葱模型把控制部署在多层嵌套边界上)
  - [3.2 零信任是贯穿所有层的原则，不是其中一层](#32-零信任是贯穿所有层的原则不是其中一层)
  - [3.3 概念澄清：Authentication 与 Authorization](#33-概念澄清authentication-与-authorization)
- [四、AgentCore 端到端实现：用户身份从登录直达工具授权](#四agentcore-端到端实现用户身份从登录直达工具授权)
  - [4.1 第一步：在 IdP 签发阶段注入可信业务 Claims](#41-第一步在-idp-签发阶段注入可信业务-claims)
  - [4.2 第二步：AgentCore Runtime 原生 Inbound Auth 在边界验证用户](#42-第二步agentcore-runtime-原生-inbound-auth-在边界验证用户)
  - [4.3 第三步：Agent 取出 JWT 并透传给 AgentCore Gateway](#43-第三步agent-取出-jwt-并透传给-agentcore-gateway)
  - [4.4 第四步：AgentCore Gateway 再次验证，Cedar 决定工具权限](#44-第四步agentcore-gateway-再次验证cedar-决定工具权限)
  - [4.5 第五步：下游长期凭证留在 AgentCore Identity 的 Credential Provider 一侧](#45-第五步下游长期凭证留在-agentcore-identity-的-credential-provider-一侧)
- [五、结尾：非确定性系统需要确定性边界](#五结尾非确定性系统需要确定性边界)

---

## 一、开篇：一场测试如何越过边界

本文旨在给出一个Agent的安全框架，并说明在亚马逊云科技的AgentCore服务上如何实现这一安全架构。

此前，业界有过一起广受关注的安全事件：某团队做了一次面向 Agent 网络安全能力的内部评估。测试环境里，一个具备代码执行与网络访问能力的 Agent，为了拿到评估所需的数据，利用一个零日漏洞突破了预设沙箱，逃逸到了公网。

接下来它通过 RCE 拿到运行环境的 root，建立外联通道；进入 Kubernetes 环境后读取了一份含 136 项密钥的 Secret，拿到了两个集群的 cluster-admin 权限；再借内网横向移动、伪造代码仓库的写入令牌，试图污染 CI 流水线；被切断访问前，它甚至改写了 DNS 来绕过出口封锁。整个过程被串成了一条几乎全自动的攻击链，全程没有人工逐步指挥。

威胁模型也随之改变。防护对象不再局限于模型的文本输出，还包括模型生成的行动能够触达的系统。提示词和内容过滤解决不了这个问题——当一个 Agent 同时握有规划能力、工具权限、代码执行环境和持久状态，它本身就是系统级的攻击面。

---

## 二、Agent应用面临的安全挑战

Agent 构建者需要认识到，Agent 在决策方式、执行能力和状态管理上都与传统应用存在差异。Agent 会根据模型输出选择并执行动作，还可能长期运行、保留跨会话信息，因此开发者不能再默认执行路径可预知、实例回收后不留状态，或把普通容器视为运行不可信代码的最终安全边界。传统防护措施仍然必要，但开发者需要重新评估其适用前提和保护范围。

### 2.1 Agent 不是无状态应用

传统 Web 应用是无状态、确定性的：同样的请求走同样的代码路径，实例可以随时销毁重建、天然不留残留。Agent 打破了这三条假设。

第一，**决策是非确定性的**。相同输入不一定产生相同的规划路径，安全控制因此不能建立在"模型每次都做对"的前提上。第二，**它从"生成内容"升级为"执行动作"**——调用 API、执行代码、读写文件、访问数据库、改变真实业务状态。一旦提示注入影响了工具选择，后果就不再是一段错误文本，而是一次真实操作。第三，也是最容易被低估的一点：**Agent 是有状态的，这对隔离提出了比传统软件更高的要求**。跨会话的持久记忆会带来记忆投毒、身份串用和权限残留；长时间自主运行则把单次错误动作放大成持续的攻击尝试。无状态应用可以随手回收，Agent 却携带着上一段对话的痕迹——所以隔离不仅要"隔开邻居"，还必须保证**会话结束即销毁、内存即清理**。

**Agent 跑的正是最不可信的那类代码**——它执行的是大模型生成的、或可被间接提示注入操纵的逻辑。运行 Agent 的环境必须默认把这段代码当作不可信负载来设计。

![自动化攻击链：一次越界如何逐级放大](images/01-attack-chain.png)

### 2.2 容器不是不可突破的最终边界

很多团队的第一反应是"把 Agent 关进容器就好了"。但普通容器与宿主机**共享同一个内核**，仅靠 namespaces 和 cgroups 做隔离——让容器轻量的机制，恰恰是它在配置不当或存在漏洞时可被突破的原因。它可以降低风险，但不能被当作运行不可信代码时"不可突破的最终边界"。

以 **CVE-2024-21626（"Leaky Vessels"，CVSS 8.6）** 为例：runc 的文件描述符泄漏，使得一个恶意镜像——甚至只是 Dockerfile 里的一行 `FROM`——就有机会越过容器文件系统边界，读写宿主机。也就是说，镜像与容器的**启动过程本身**就可能成为逃逸入口。

这不是孤例。运行时层面，2025 年底披露的一组 runc 漏洞（`CVE-2025-31133 / 52565 / 52881`，CVSS 7.3）通过挂载竞态与 procfs 写重定向实现完整逃逸，甚至能绕过 AppArmor/SELinux——连 LSM 都不该被当作最后一道墙。内核层面，`CVE-2026-64564`（"SCTPhantom"，CVSS 8.5，潜伏了 18 年）在默认 seccomp、无特权能力的条件下依然能多次逃逸拿到 root，说明**即使容器运行时零缺陷，共享内核本身仍是一个逃逸面**。

补丁、seccomp、AppArmor/SELinux、只读文件系统、能力裁剪、网络策略当然仍然必要，它们能显著降低逃逸的概率和影响。但它们无法从架构上抹掉"共享内核"这层边界。

[AgentCore Runtime](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html) 是专为 Agent 和工具设计的托管运行环境；本文采用其 microVM 模式，为 Agent 提供按会话（Session）隔离的执行沙箱。AgentCore Runtime 为每个会话分配独立的 microVM，隔离 CPU、内存和文件系统，并在会话终止时销毁该 microVM、清理内存。

不过，隔离强度只能回答一个问题："这段不可信代码能不能碰到邻居。"它回答不了"它代表谁""能调用什么工具""能用哪些参数""凭证放在哪里"。这些，需要一套覆盖完整调用链的体系化设计。

---

## 三、建立从单点防护到体系化安全的整套机制

### 3.1 洋葱模型：把控制部署在多层嵌套边界上

我们仍然要遵从“不发明安全算法”的约束，基于久经考验的安全框架设计 Agent 时代的安全体系。

我们建议基于**洋葱模型**设计 Agent 的安全体系：把彼此独立的安全控制放在多层相互嵌套的边界上，任何单层失效都不应直接导致整个系统失守。它是一种设计结构，不依赖单一产品。用于 Agent，可以分成八层：

1. **输入与内容层**——提示注入检测、内容过滤、不可信数据标记；
2. **模型与编排层**——限制自主循环、高风险操作二次确认、约束工具选择；
3. **会话与运行时层**——按用户/会话隔离执行环境，结束即销毁、清理内存；
4. **网络与出口层**——默认拒绝出站，白名单化 egress，限制到内网与实例元数据服务的访问；
5. **身份层**——每次请求都携带可验证的用户或工作负载身份；
6. **工具授权层**——对每个工具及关键参数做独立、确定性的策略判断；
7. **凭证与下游访问层**——长期凭证由受控组件管理，Agent 只按需拿短期访问能力；
8. **审计与治理层**——记录用户、会话、模型决策、工具调用、策略结果与下游响应。

第四层——**网络与出口**——常被忽略，却往往是攻击链的放大器。开篇那次越界，最后一步正是"改写 DNS 绕过出口封锁"；许多真实事件的共同短板里也都有"缺失的出口管控"；甚至前面提到的 SCTPhantom 这类内核逃逸漏洞，本身就出在网络子系统。**能不能出网、只能出到哪里，必须由平台强制，而不是指望 Agent 自觉。**

<img src="images/02-onion-model.png" alt="洋葱模型：多层嵌套、任一层失效都不致命" width="600">

### 3.2 零信任是贯穿所有层的原则，不是其中一层

**零信任**贯穿所有控制层。洋葱模型决定控制部署在哪些位置，零信任决定每一层如何作出访问决策。

[AgentCore Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html) 是面向 Agent 的托管 AI 网关，本文用它将 API、Lambda 函数和已有 MCP Server 中的工具汇聚为统一的 MCP 入口，供 Agent 发现和调用。AgentCore Gateway 按配置验证调用者身份、处理下游认证，并将获准的工具请求转发给对应目标。

具体到 Agent：不因为请求来自内网、来自 AgentCore Runtime 或来自另一个 Agent 就默认可信；AgentCore Runtime 与 AgentCore Gateway 各自独立验证身份，不共享隐式信任；每一次工具调用都基于"谁、做什么、对什么资源、在什么上下文"重新授权；默认拒绝，身份缺失或传播失败时**fail closed**，绝不静默降级为权限更大的机器身份；令牌一律短期、最小权限、限定 audience 与 scope。

### 3.3 概念澄清：Authentication 与 Authorization

体系化设计里有两个经常被混用的概念，它们分别对应 AgentCore 的不同组件：

- **认证（Authentication，你是谁）= AgentCore Identity / OAuth / OIDC / JWT。** AgentCore Identity 的 inbound auth（JWT Authorizer）在边界验证调用者的身份。
- **授权（Authorization，你能做什么）= AgentCore Policy / Cedar。** [AgentCore Policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html) 是面向 Agent 工具调用的细粒度授权服务，可使用 Cedar 策略对调用者、工具、资源及上下文作出确定性判断。AgentCore Gateway 接入 AgentCore Policy 并启用强制执行模式后，会按判定放行或拒绝工具调用。

Cedar 是亚马逊云科技开源的授权策略语言与求值引擎（Amazon Verified Permissions 也基于它）。它把授权表达成一组 `permit` / `forbid` 规则，每条规则针对一个四元组：**principal（谁）、action（做什么动作）、resource（对什么资源）、context（在什么上下文，比如工具参数）**。Cedar 对同样的输入始终给出同样的判定，因此适合为非确定性的 Agent 提供确定性的授权判断。

Cedar 只作授权判定，不拦截请求；AgentCore Gateway 负责执行这一判定。在本文设计中，Agent 通过 AgentCore Gateway 这个唯一入口调用工具：AgentCore Gateway 先把已验证的 JWT claims 映射成 Cedar 的 principal 属性，再交给 AgentCore Policy 引擎评估 principal/action/resource/context，只有结果为 `PERMIT` 才把调用真正转发给工具。**AgentCore Gateway 是执行点（拦截并强制），Cedar 是决策点（只出判定）**。在这条调用链中，AgentCore Gateway 强制执行 Cedar 的授权判定。（具体策略见 4.4。）

Cedar 策略示例：

```
permit (
    principal,
    action == AgentCore::Action::"AirlineToolsTarget___waive_change_fee",
    resource == AgentCore::Gateway::"<gateway-arn>"
) when {
    principal.getTag("loyalty_tier") in ["gold", "platinum"]
};
```

这条 Cedar 策略允许 **gold 或 platinum 会员调用 `waive_change_fee`（豁免改签费）这个工具**。AgentCore Gateway 验证 JWT 后，把其中包括 `loyalty_tier` 在内的 claims 填进 `principal` 的属性；Cedar 只拿这份已验证的属性做判断，判断结果由 AgentCore Gateway 执行：`PERMIT` 才转发给工具，否则直接拒绝。认证负责"你是谁、有什么属性"，授权负责"凭这些属性能不能做这件事"，两步缺一不可。

这里还有两点需要说明。其一，OAuth 的 **scope** 本身就是一种粗粒度授权，所以 OAuth 并非"纯认证"；准确的分工是：**OAuth 负责身份 + 粗粒度 scope，Cedar 负责细粒度、带上下文、确定性的授权**。其二，AgentCore Identity 除了认证，还兼管"出站凭证代理"（AgentCore Identity 的 Credential Provider）。这部分属于凭证管理。"AgentCore Identity = 认证"是个有用的简化，但不是它的全部职责。

---

## 四、AgentCore 端到端实现：用户身份从登录直达工具授权

第三节讲的是框架——洋葱模型决定控制放在哪些层，零信任决定每层如何决策。但框架不落地，就只是原则。这一节把八层逐一对应到亚马逊云科技上的实现，再重点展开其中的运行时、身份、工具授权与凭证四层。

| 层 | 亚马逊云科技上的实现 |
| --- | --- |
| 1 输入与内容层 | Amazon Bedrock Guardrails：提示注入检测、内容过滤 |
| 2 模型与编排层 | Agent 框架（如 Strands Agents）约束工具选择与自主循环；高风险动作交由 AgentCore Policy 强制判定 |
| 3 会话与运行时层 | AgentCore Runtime：会话级 microVM，结束即销毁、清理内存 |
| 4 网络与出口层 | AgentCore Runtime 的 VPC 模式 + 安全组 / Network Firewall：默认拒绝出站、白名单 egress |
| 5 身份层 | AgentCore Identity（Inbound Auth / JWT Authorizer）+ Amazon Cognito 或任意 OIDC IdP |
| 6 工具授权层 | AgentCore Gateway + AgentCore Policy（Cedar） |
| 7 凭证与下游访问层 | AgentCore Identity 的 Credential Provider + IAM 角色 / STS 短期凭证 |
| 8 审计与治理层 | AgentCore Observability（CloudWatch / OpenTelemetry）+ CloudTrail |

设计目标只有一个：**让这几层边界各自独立成立**，任何单层被突破，都不至于让整条攻击链贯通。下面按"先隔离、再身份、后授权与凭证"的顺序，把它们逐一走一遍。

先看运行隔离——它正面回答 2.2 节留下的问题：**容器不是最终边界，AgentCore Runtime 靠什么兜底？** 答案是不共享内核。AgentCore Runtime 给每个会话一台独立的 microVM，各有自己的内核。这样一来，2.2 节那些逃逸漏洞即便被触发，影响也只限于这一个会话的 microVM，碰不到宿主机，也碰不到其他用户。会话结束时，AgentCore Runtime 销毁该会话的 microVM 并清理内存。

隔离只解决"能不能碰到邻居"，回答不了"你代表谁、能调用哪些工具"。这就要靠下面这条**可验证的身份链**：用户登录得到的 JWT，经边界验证后一路透传，由每一跳独立验证、由 Cedar 基于真实用户属性授权。Agent 在这条链里只是"信使"——它不做身份判断，也不嵌入任何长期静态凭证。

整条身份链有两个**独立的信任边界**：AgentCore Runtime 判断"谁可以调用这个 Agent"，AgentCore Gateway + AgentCore Policy 判断"这个用户能不能调用这个工具、用这组参数"。AgentCore Runtime 验证通过，不代表 AgentCore Gateway 可以跳过再次验证——这正是零信任"不共享隐式信任"的落地。

![AgentCore 端到端身份链：用户 JWT 透传，每一跳独立验证](images/03-e2e-sequence.png)

下面用一个航空客服 Agent 的例子，把这条身份链走一遍。

### 4.1 第一步：在 IdP 签发阶段注入可信业务 Claims

授权要基于用户属性，属性就必须来自**可信来源**，而不是前端传来的字段。Cognito 的默认 Access Token 只有 `sub`、`email`、`scope`，并不带 `loyalty_tier`（会员等级）这类业务属性。做法是用 **Pre Token Generation Lambda**，在 Cognito 签发令牌前，按已认证用户查出属性并写进 JWT：

```python
def lambda_handler(event, context):
    email = event['request']['userAttributes']['email']
    # Demo 用字典；生产环境改为查询可信数据源（如 DynamoDB）
    user_data = lookup_user(email)
    claims = {
        "loyalty_tier": user_data['loyalty_tier'],  # gold / platinum / basic
        "user_id": user_data['user_id'],
    }
    event['response'] = {
        'claimsAndScopeOverrideDetails': {
            'accessTokenGeneration': {'claimsToAddOrOverride': claims}
        }
    }
    return event
```

关键在于：claims 是在 **IdP 签发时**由服务端注入的，客户端无法伪造；生产环境务必从可信数据源查询，绝不把未经校验的前端字段直接写成授权 claims。

### 4.2 第二步：AgentCore Runtime 原生 Inbound Auth 在边界验证用户

令牌怎么进 AgentCore Runtime？AgentCore 提供了两种方式：一种是把 JWT 塞进调用 payload、由应用自己解析（容易只透传不验证）；另一种是**原生 Inbound Auth**——把 JWT 放在标准的 `Authorization` 头，由 AgentCore Runtime 在边界自动验证。我们只用后者。

配置一个 `customJWTAuthorizer`，指向 IdP 的 OIDC discovery 地址并限定 audience：

```json
{
  "authorizerConfiguration": {
    "customJWTAuthorizer": {
      "discoveryUrl": "https://cognito-idp.<region>.amazonaws.com/<pool-id>/.well-known/openid-configuration",
      "allowedAudiences": ["<app-client-id>"]
    }
  }
}
```

再把 `Authorization` 头加入白名单，让 handler 能读到它：

```yaml
request_header_allowlist:
  - "Authorization"
```

于是客户端只需一个标准 HTTP 请求：`POST /invoke`，头部 `Authorization: Bearer <user-jwt>`，body 里只放业务数据 `{"prompt": "改签我的航班"}`。AgentCore Runtime 会自动完成签名验证、过期检查、audience 校验——**无效令牌在进入 Agent 逻辑之前就被拒绝（401）**。验证发生在边界，而不是在 Agent 代码里。

### 4.3 第三步：Agent 取出 JWT 并透传给 AgentCore Gateway

进入 handler 后，Agent 不再手工解析 payload，而是直接从 `RequestContext` 取出那个**已被 AgentCore Runtime 验证过**的令牌，原样注入到调用 AgentCore Gateway 的 `Authorization` 头里。Agent 在这里就是个信使：

```python
def extract_bearer(headers):
    raw = headers.get("Authorization") or headers.get("authorization")
    if not raw:
        raise ValueError("missing Authorization")
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ValueError("invalid Authorization")
    return token  # 返回裸 token，避免下游再拼出 "Bearer Bearer"

class GatewayAgent:
    def __init__(self, gateway_url, user_token):
        if not user_token:                       # 缺身份 → fail closed，绝不 fallback 到机器身份
            raise RuntimeError("user token required")
        self.user_token = user_token
        self.gateway_url = gateway_url
        self.mcp_client = MCPClient(transport_callable=self._transport)

    def _transport(self):
        headers = {"Authorization": f"Bearer {self.user_token}"}   # 只拼一个 Bearer
        return streamablehttp_client(url=self.gateway_url, headers=headers)

@app.entrypoint
def handler(payload, context: RequestContext):
    user_token = extract_bearer(context.request_headers)
    agent = create_agent(GatewayAgent(GATEWAY_URL, user_token))
    return agent(payload.get("prompt"))
```

透传意味着 Agent 在单次请求内**确实持有一个短期用户令牌**——所以它的安全性建立在这样一组约束上：令牌短时有效、限定 audience 与 scope、不落盘、不写日志、不写入记忆或追踪属性、缺失即 `fail closed`。它不是"Agent 完全不碰凭证"，而是"Agent 只在请求生命周期内受控地持有短期身份令牌，且从不持有长期静态凭证"。

代码里还有两个容易踩的坑值得强调：一是从 `RequestContext` 取到的值已经带 `Bearer ` 前缀，注入下游时别再拼一次，否则会变成 `Bearer Bearer <jwt>`；二是**不要在用户令牌缺失时静默 fallback 到机器身份（M2M）**——那会丢失端到端可追溯性，让 AgentCore Gateway 无法执行用户级策略，甚至让 Agent 意外获得更宽的权限。若确实需要服务间调用，应该走独立入口、独立 audience、独立的 AgentCore Policy 策略，而不是和用户身份互相兜底。

### 4.4 第四步：AgentCore Gateway 再次验证，Cedar 决定工具权限

请求到达 AgentCore Gateway，零信任要求它**独立地再验证一次**：校验 JWT 的签名、有效期和预期 audience，然后把可信 claims 映射为 **Cedar 的 principal 属性**。之后 AgentCore Policy 引擎同时评估四个维度——principal（谁）、action（哪个工具）、resource（哪个 AgentCore Gateway/Target）、context（工具参数）——只有结果为 `PERMIT` 才把调用转发给真正的工具。

第一条策略基于**用户属性**：只有 `gold` 或 `platinum` 会员才能豁免改签费。

```
permit (
    principal,
    action == AgentCore::Action::"AirlineToolsTarget___waive_change_fee",
    resource == AgentCore::Gateway::"<gateway-arn-placeholder>"
) when {
    principal.hasTag("loyalty_tier") &&
    principal.getTag("loyalty_tier") in ["gold", "platinum"]
};
```

第二条策略基于**业务上下文**：只有当航班状态确实是取消或大幅延误时，才允许发起全额退款——它不看用户是谁，只看工具参数。

```
permit (
    principal,
    action == AgentCore::Action::"AirlineToolsTarget___full_refund",
    resource == AgentCore::Gateway::"<gateway-arn-placeholder>"
) when {
    context.input.flight_status in ["CANCELLED", "SIGNIFICANT_DELAY"]
};
```

下面用三个场景说明这条链如何工作：

- **场景 A**：Gold 用户申请豁免改签费。JWT 里带 `loyalty_tier=gold`，Cedar 命中第一条规则，返回 `PERMIT`。
- **场景 B**：Basic 用户发起同样请求。前面每一步都一样，但 Cedar 返回 `DENY`。用户**换一套提示词也绕不过这条确定性策略**——因为决定权根本不在模型手里。
- **场景 C**：一个身份合法的用户请求全额退款，但对应航班状态正常。第二条策略据 `flight_status` 拒绝，必要时转人工审批。

**Agent 可以"提出"工具调用，但无权"决定"自己是否有权调用。** 授权不藏在系统提示词里，也不依赖模型自觉遵守。当然，最终的业务系统仍应校验交易一致性、余额、状态机等业务约束——Cedar 管的是"能不能调用这个工具"，不替代业务侧的最终校验。

### 4.5 第五步：下游长期凭证留在 AgentCore Identity 的 Credential Provider 一侧

最后一环是凭证。Cedar 放行后，**AgentCore Gateway** 负责调用下游（Lambda、REST API、MCP Server，或 EKS 这类基础设施），Agent 不直接调用这些下游。AgentCore Gateway 通过 **AgentCore Identity 的 Credential Provider** 以每个目标各自要求的方式（IAM 角色、OAuth、API Key）完成认证；这些下游长期凭证由 AgentCore 受控存储、获取和轮换，**始终不进入 Agent 的运行环境**。

**常见做法：长期密钥放 Secrets Manager，Agent 自己去取。** 很多团队会把下游需要的长期凭证（数据库口令、API Key、一份 cluster-admin 的 kubeconfig）存入 Secrets Manager，再给 Agent 一个 `secretsmanager:GetSecretValue` 权限，让 Agent 在运行时读取和使用这些凭证。团队把密钥存入 Secrets Manager，可以避免在代码中硬编码；但**Agent 取出长期凭证时，就把它读入了自己的运行环境**——落在内存里，可能还进了日志和堆栈。而 Agent 跑的正是最不可信的那类代码（见 2.1）：一次成功的提示注入或代码执行，就能让攻击者把这份长期凭证读走、外传；只要凭证仍然有效且下游接受该凭证，攻击者还可能在 Agent 环境之外复用它。开篇事件中，Agent 一次读取了含 136 项密钥的 Secret。这个例子说明，Agent 能读取集中存放的密钥时，一次越界就可能暴露多份凭证。

**推荐做法：下游凭证不进 Agent，由受控组件代持。** AgentCore Identity 的 Credential Provider 底层同样可以有托管存储。两种做法的差别在**谁读取凭证、凭证进入哪个运行环境**：读取与使用都发生在 AgentCore Gateway / AgentCore Identity 的 Credential Provider 这个受控边界内，Agent 在下游访问环节只拿到工具调用的**结果**，不接触这些下游凭证。在 Agent 只能经 AgentCore Gateway 访问这些下游工具的前提下，AgentCore Gateway 仍按 Cedar 的判定限制工具调用，Agent 也无法从本地取得由受控组件保管的下游长期凭证。

以**"Agent 操控 EKS"**为例：同样是"Agent 需要一个能操作集群的凭证"，两种设计里这份凭证存在完全不同的位置：

- **反模式**：把一份 cluster-admin 的 kubeconfig / 长期 token 存进 Secrets Manager，Agent 取出后直连 EKS API。Agent 把凭证读入自己的进程，权限是整个集群的 admin，且长期有效——Agent 一旦失守，攻击者拿到的就是"随时可用的集群最高权限"，正是开篇攻击链里"拿到两个集群 cluster-admin"的那一步。
- **推荐**：把 EKS 操作封装成 AgentCore Gateway 后面的工具（如一个 Lambda / MCP target，只暴露 `list_pods`、`restart_deployment` 这类具体动作）。AgentCore Gateway 侧通过 AgentCore Identity 的 Credential Provider 假设一个**窄权限 IAM 角色**，该角色再经 EKS 的 access entry 映射到一个**受限的 Kubernetes RBAC 角色**（比如只允许某个 namespace 的只读操作）。这里根本**没有需要长期保管的密钥**——用的是 STS 现签的短期凭证；Agent 不持有集群访问用的 kubeconfig 或 token，只接收这次 EKS 工具调用的返回值。要不要放行这次操作，仍由 Cedar 按用户身份与参数判定。

两种做法的本质差别，是**凭证的爆炸半径**：反模式下，泄露一份密钥＝丢掉它能触达的一切、且长期有效；推荐做法下，Agent 环境被攻破不会直接暴露由受控组件保管的下游长期凭证；AgentCore Gateway 仍按 Cedar 的策略约束相关工具调用。开篇那次越界之所以能一路放大到 cluster-admin，缺的正是这一层。三个身份域由此清晰分开：

![三个身份域清晰分离：Agent 只当信使，不持长期凭证](images/04-identity-domains.png)

---

## 五、结尾：非确定性系统需要确定性边界

回到开篇。那次越界的根源是**多个边界同时缺失**：运行环境可以被突破、网络出口没有限制、集群权限过大、长期凭证可被一次读走、工具调用缺少独立授权。任何一层单独补上都不够——攻击链只需要一条没被堵住的路径。

所以体系化的 Agent 安全，不能押注在某一个护栏或某一个沙箱上，而要让下面这些边界**各自独立成立**：

1. 以不可信代码为前提、会话结束即销毁的运行隔离；
2. 从用户到 AgentCore Runtime、再到 AgentCore Gateway 的可验证身份链——透传短期用户令牌，Agent 不持长期凭证；
3. 面向每个工具与参数的确定性授权（Cedar）；
4. 下游长期凭证不进入 Agent 环境（AgentCore Identity 的 Credential Provider）；
5. 覆盖全调用链的审计、检测与撤销。

> 模型负责处理不确定性，安全架构负责限制不确定性的影响范围。只有当身份、权限、凭证和运行边界都独立成立时，Agent 的自主能力才可能被安全地交付到生产环境。
