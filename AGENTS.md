# AGENTS.md — astrbot_plugin_tooling_guard

面向在本目录工作的 AI agent 的项目约定、公开契约与待办。基线：AstrBot 4.29.4（decision 接口在 4.29.4 引入，最低宿主因此抬到该版本；4.29.3 commit `0e997cc` 仍是其余契约的核对基准）。

## 这是什么

一个 AstrBot 插件：在模型真正执行工具之前做判定，把 Computer Use 类高危动作（shell / python /
文件读写 / 浏览器 / CUA）纳入一条可审计的「放行 / 挂起 / 拒绝」链路。默认 `mode=observe`（只审计
不阻断），`enforce` 需先有 observe 期数据且 `admins` 非空。实现已落地，不再是脚手架。

行为语义、模式与不保证项的权威描述在 `README.md`；分层与硬约束在 `ARCHITECTURE.md`；47 个核心工具
的逐个处置在 `TOOL-MATRIX.md`；设计取舍在 `openspec/changes/archive/2026-10-30-add-computer-use-tool-gateway/design.md`。

## 机制（改动前必须先读）

- AstrBot **没有**「工具执行前」钩子。唯一能改工具集的公开钩子是 `@filter.on_llm_request`，调用点
  `astrbot/core/pipeline/process_stage/method/agent_sub_stages/internal.py:307`；钩子内改
  `req.func_tool` 与 `req.system_prompt` 会进入本次循环。
- 所以判定在**代理**里：`tooling_guard/interface/wrapper.py` 的 `ManagedToolProxy` 接管 `call`，先
  判定再决定是否转发；`tooling_guard/interface/hooks.py` 只负责安装代理，不含策略。
- 安装时机：根 `main.py` 用 `@filter.on_llm_request(priority=-1_000_000_000)` 注册，**故意最后一个装**。
  宿主按 `priority` 降序执行（`astrbot/core/star/star_handler.py` 的排序 key 是 `-priority`，默认 0），
  而 `ToolSet.add_tool` 对同名 active 工具是**就地覆盖**（`astrbot/core/agent/tool.py`）——早装就会被后注册
  的原工具夺回名字。同一 priority 之间按注册顺序，所以这个数必须是**所有插件里最小的**，改大等于把代理让出去。
- 受管范围：可识别的内置静态 FunctionTool（14 个 Computer Use 工具类，导入自
  `astrbot/core/astr_agent_tool_exec.py:35-50`），以及能读出**任一**归属线索（`handler` 非空，或
  `handler_module_path` 非空，任一即可）的插件工具。安装期按**三路分流**（`install_proxies`，`tooling_guard/interface/install.py:384`；形状判据
  `_surface_kind` `:27`，判定顺序 `:59-84`，循环 `:418-430`）：
  1. **可纳管** → 装 `ManagedToolProxy`（`:425-426`）；
  2. **一切不可纳管（五类）** → 由**唯一**开关 `strip_unmanaged_tools`（`_conf_schema.json:14`，默认 `false`）
     决定 passthrough 还是 stripped（`:427-430`）。五类是 `mcp`、`handoff`（`transfer_to_*`，
     `tooling_guard/compat.py:58` 的 `HANDOFF_NAME_PREFIX`）、`background`、`future_task`（`install.py:21`）、
     `unknown`——形态认不出只是其中一类，**不再**是唯一能放行的一类：
     - 开关 **off（出厂默认）** ⇒ 五类全部留在本轮工具集：不装代理、不审计、不落策略，打**唯一**一条
       披露 WARN（`:466-471`）：「%d 个不可纳管工具原样放行（不进入审计与策略）：%s」；
     - 开关 **on** ⇒ 五类全部删除，打**唯一**一条剥离 WARN（`:459-465`）：「开关 strip_unmanaged_tools
       已开启，剥离 %d 个不可纳管工具（这些工具本轮不可用，也不留审计行）：%s」。
     读不出开关时按默认不剥离处理并记 `logger.error`（`:227`）。
  认知代价：放行是**放过即放过**——`observe` 下也不记 `would_be`，审计里没有它的行，所以任何
  「已覆盖 / 已审阅」的统计都不能把这些工具算进去；开关是**单向全有或全无**，不能只剥 MCP 而保留
  `future_task`。降级剥离失败时钩子改走
  同模块的 `clear_toolset`（`:309`，三级梯子，每级核对条目数为 0），失败后缀会折进复合 degraded kind
  （`tooling_guard/interface/hooks.py` 的 `_strip` `:228` / `_degraded_kind` `:282`），见
  `ARCHITECTURE.md` §1b。
- 覆盖边界：cron、后台唤醒、子 agent 内部的工具调用**不经过**该钩子，网关看不到也管不到。不要把
  它们算作「已覆盖」或「已审阅」。
- 行号锚点随实现增长而漂移：定位以符号名为准，文档里引用的行号只在核对当时成立。

## 目录结构

```
astrbot_plugin_tooling_guard/
  metadata.yaml        # AstrBot 靠它识别插件；astrbot_version 必须 >=4.29.4（decision 实体）
  main.py              # Star 子类，注册 /toolguard、/guard，挂 on_llm_request，装配 Gateway
  requirements.txt     # 仅 httpx>=0.27,<1.0
  _conf_schema.json    # 配置 UI（mode/admins/jev/保留期/名单/审查器/Web/信任域等 42 个键，全中文）
  views/guard/index.html # Web 页面；宿主只发现 views/<目录>/index.html，裸 views/index.html 永不显示
  tooling_guard/       # 网关实现
    compat.py          # GATE_FINGERPRINT、unwrap、上游属性名
    anonymize.py       # 入库前脱敏（单次扫描上限 MAX_REDACT_SCAN = 262144）
    digest.py          # 参数摘要
    main.py            # Gateway：guard_call / handle_call / set_mode / shutdown
    core/              # 审查器流水线：registry 注册表与展示序、pipeline 并发扇出、verdict 合成、reviewer 协议
    reviewers/         # 具体审查器：policy、base_check、rules、jev_fast、llm_deep
    approval/          # 票据挂起与等待、迟到裁决
    interface/         # hooks.py 钩子适配、install.py 安装与剥离、wrapper.py 代理
    jev/               # 快审客户端（单次 HTTP，jev_timeout_s 默认 10 秒、上限 30）
    notify/            # 管理员通知与回帖
    policy/            # 配置快照、允许/拒绝名单、路径与目的地、敏感目标
    prompts/           # 提示词
    provider/          # LLM 端点
    store/             # sqlite、票据、审计、保留期
    trace/             # 轨迹、R12 污点归一与升级
    triage/            # classify、rules R1–R11、engine 判定合成
    ui/                # /guard 文本命令
    web/               # Web 控制台后端：__init__.py 注册、api.py 路由、queries.py 纯只读查询
  tests/unit/          # 无需宿主的单元测试（85 个套件，逐套件数字见 tests/unit/README.md）
  tests/gate1/         # 需要真实 AstrBot 源码树的探测（见下）
  tests/manual/        # 人工验收脚本（纯 stdlib，不需要宿主）
  tests/e2e/           # 真实宿主台架：AstrBot 4.29.3 + aiocqhttp 反向 WS，非 hermetic
  ARCHITECTURE.md  TOOL-MATRIX.md  README.md  AGENTS.md
  openspec/changes/archive/2026-10-30-add-computer-use-tool-gateway/   # proposal / design / tasks / specs
```

AstrBot 认可但尚未创建的可选文件：`logo.png`（1:1，256x256）、`skills/<name>/SKILL.md`。

## 公开契约（改动这些等于改契约，必须同步 `README.md`）

### C1 · 钩子处理器必须是协程函数

`astrbot/core/pipeline/context_utils.py:115` 断言 `inspect.iscoroutinefunction(handler.handler)`，
失败分支（`context_utils.py:114-121`）只记 traceback、不中断请求。同步 handler 等于钩子从未执行
——静默 fail-open。当前实现：`tooling_guard/interface/hooks.py:385` 的 `on_llm_request` 是协程，
函数体内没有 `await`；机制函数保持同步，所有失败在 `_dispatch`（`hooks.py:322`）里降级为结果。

### C2 · 网关判定入口

```python
# tooling_guard/main.py:1422
async def guard_call(
    self,
    *,
    inner: Any,
    tool_name: str,
    args: Mapping[str, Any] | None = None,
    context: Any = None,
) -> CallOutcome: ...


# tooling_guard/main.py:1457
async def handle_call(
    self, tool: Any, arguments: Mapping[str, Any] | None = None, *, context: Any = None
) -> CallOutcome: ...
```

`handle_call` 是代理调用面，内部委托给 `guard_call`（唯一判定入口）。契约：`asyncio.CancelledError`
原样重抛（`:1452-1453`）；任何其它异常一律转成 `deny`（`REASON_FAIL_CLOSED`，`:1454-1455`）。调用方不得
绕过 `guard_call` 直接调用 `inner`。

### C3 · 模式切换

```python
# tooling_guard/main.py:1106
def set_mode(self, mode: str) -> bool: ...
```

配置未加载或 `mode` 不在 `observe` / `enforce` 时抛 `ValueError`；已是该模式、或目标为 `enforce` 而
`config.admins` 为空时返回 `False`（`:1135-1139`）。配置侧同样告警并不启用
（`tooling_guard/policy/config.py:293-295`）。

### D1 · 审计存储 API（`tooling_guard/store/audit.py`）

- `record_event(conn, event: Mapping[str, Any]) -> int`（`:252`）——单条审计写入，返回行 id。
- `class AuditWriter`（`:327`）——FIFO 提交/抽取队列，无线程无定时器，`sink` 与 `retention` 回调可注入。
- `record_side_observation(...)`（`:442`）、`record_trajectory_snippet(...)`（`:714`）。
- `apply_retention(conn, *, audit_days=None, per_subject_keep=None, trajectory_keep=None, subjects=None, now=None) -> dict[str, int]`
  （`:868`）——保留期清理，返回 `{"audit_events": n, "trajectory_snippets": m}`，幂等；仍被未结算票据引用
  的审计行会保留。默认 `DEFAULT_AUDIT_RETENTION_DAYS = 7`（`:861`）、`DEFAULT_TRAJECTORY_KEEP = 50`（`:864`）。
- `scan_for_secrets(conn) -> tuple[int, int]`（`:619`）——只读取证：库内命中的审计行数与轨迹片段数，
  用来证明脱敏发生在写入之前（脱敏在 `tooling_guard/anonymize.py`）。

### D2 · 票据与重试绑定

`find_approved(conn, *, subject_key, session_key, tool_name, args_digest, now=None) -> Ticket | None`
（`tooling_guard/store/tickets.py:602`）：只读四元精确匹配（主体、会话、工具名、参数摘要），要求
`state=approved`、`retry_consumed=0`、批准窗口未过期，返回最早的一张票据；它自己**不授权任何调用**，
匹配结果还必须经 `consume_approved` 原子消费（`tooling_guard/main.py:4302` `_consume_approved_retry`；调用点 `:2709`）。

`consume_approved(conn, ticket_id, *, subject_key, session_key, tool_name, args_digest, now=None) -> bool`
（`tooling_guard/store/tickets.py:664`）：单条 UPDATE，要求 `state=approved`、`retry_consumed=0`、四项
完全匹配、批准窗口未过期；成功则置 `state=consumed` 并写状态迁移。不匹配、重复消费、窗口过期都返回
`False` 且不改状态。`args_digest` 必须是 32 位小写十六进制（`_check_digest` `:277-296`）。

**批准只豁免挂起**：只有 `SUSPENDED` 分支会去消费批准（`tooling_guard/main.py:2113-2120`），所以
`deny_rule` / `deny_policy` / `deny_judge` 永远不会被一张已批准票据覆盖。消费之后的同参数调用找不到
可用授权，会重新判定并重新建票（放行判定名为 `allow_approved_retry`）。

### D3 · 22 键轨迹摘要记录与四个相关列

每次受管调用**只构造一个** `CallSummary`，同一实例既写审计行也进轨迹窗口：`_call_summary`
（`tooling_guard/main.py:3250`）→ `_record(summary=...)`（`:3309`）→
`_append_trajectory(summary, session=...)`（`:3482`），所以两处永不键漂移。

- 22 键 schema 是 `tooling_guard/trace/summary.py:20` 的 `TRAJECTORY_KEYS`，与
  `openspec/changes/archive/2026-10-30-add-computer-use-tool-gateway/specs/call-triage/spec.md:50` 逐字同序：`ts_seq`、
  `call_id`、`at`、`user`、`session`、`tool`、`origin`、`verb`、`targets`、`tier`、`args_digest`、
  `args_head`、`content_len`、`content_lines`、`rule_hits`、`single`、`links`、`summary_line`、
  `decision`、`ticket`、`labels`、`delegated`。`as_dict()`（`summary.py:124`）按该顺序返回全 22 键，
  未知显式 `None`；`summary_line` ≤160 字符、`args_head` ≤512（`summary.py:45-46`）。
- `audit_events` 现 18 列，新增 4 列**追加在末尾**：`args_digest TEXT`、`labels TEXT`、`delegated TEXT`、
  `summary_json TEXT`（`tooling_guard/store/db.py:79-82`、`tooling_guard/store/audit.py:68-71`）。迁移
  **不提升** `SCHEMA_VERSION`（仍为 1，`db.py:46`）：旧库靠 `PRAGMA table_info` 判定存在性后用
  `ALTER TABLE ADD COLUMN` 自动补列（`db.py:347`）。
- `labels`：排序后逗号连接（`main.py:2484`），三类正交标签同列共存；来源链 `TriageOutcome.labels`
  （frozenset）→ `_labels_of`（`main.py:3124`）→ `_Plan.labels`（`main.py:293`，排序 tuple）→
  `CallSummary.labels`。
- `delegated` 三态（`tooling_guard/store/audit.py:88-95`）：`"yes"` = 该调用被放行到真实工具
  （enforce 下 allow 系列；observe 下按 allow 放行，原判在 `would_be`）；`"no"` = 未放行（deny /
  suspend / timeout / cancel）；`NULL` = 无调用语义的行。
- `summary_json` 为 `NULL` 的**唯一**合法情形：`/guard`、`/toolguard` 命令面自身的审计行
  （`source=manual`，如模式切换，`tooling_guard/ui/commands.py:713`）；这类行 `delegated` 与 `labels`
  同为 `NULL`。
- 调用行的 `summary_line` 尾部按 `intent_unpaired` → `deep_cache=hit` → `degraded=<kind>` 顺序带标记，
  与 `audit_events.degraded` 布尔槽（`tooling_guard/store/db.py:76`，库里没有降级文本列）**并存**：槽说
  「这次降级了」，行说「为什么」。整段尾标记先预留、正文只截到 `SUMMARY_LINE_LIMIT - len(tail)`
  （`_audited_summary_line`，`tooling_guard/main.py:4369`，尾标记在 `:4407-4430` 组装），所以截断只压缩参数
  摘要、永不吞标记；每个标记**只从 plan 派生**，正文里出现的同名文本不再抑制标记（R12-02）。

### U1 · 命令集（`tooling_guard/ui/commands.py`）

`/toolguard` 报版本、网关状态、mode、judge 路由。`/guard` 子命令：`status [ticket_id]`、
`stats [24h|7d|all]`、`approve <ticket_id>`、`deny <ticket_id> [原因]`、`mode`、`mode observe|enforce`
（`ui/commands.py` 的 `_HELP`）。仅 `admins` 可用；非管理员每次调用都留一条 `deny_requester` 审计行
并收到固定拒绝文本（`:177-179`）。海报文本经 `finalize_reply`（`:130`）脱敏并截断到 `REPLY_LIMIT 2000`。

`approve` 把票据从 `pending` 推到 `approved` 并留一条 `allow_approved_retry` 审计行
（`tooling_guard/ui/commands.py:437-444`）；批准只豁免挂起，且只能被一次四元完全相同的调用消费。
迟到的 `approve` 不改写已结算票据（`_late_reply`，`:503-510`）。

### U2 · 钩子降级的可见面

`on_llm_request` 不再丢弃适配器返回值：`outcome = self._request_hook(event, request)` 之后转交
`_note_hook_outcome`（`tooling_guard/main.py:1039-1045`）。降级事实写一行审计
（`_record_hook_degraded`，`main.py:1070`）：`decision=allow_passthrough`、`source=native`、
`degraded=1`、带 `rule_set_version`，`summary_line` 形如 `hook degraded=<kind> skipped=<kind>`
（先脱敏再截断）；按 kind 限频 600 秒窗口告警管理员（`_alert_hook_degraded`，`main.py:1108`；限频键把
kind 并入 `tool_name`，`HOOK_ALERT_TOOL = "on_llm_request"`，`main.py:187`；窗口
`DEGRADED_WINDOW_S = 600.0`，`tooling_guard/notify/ratelimit.py:22`），不同 kind 各自独立。存储不可用时
钩子只记日志、不抛异常（钩子内抛异常会让整个 LLM 请求失败），工具集剥离（fail-closed）不受影响。

可见面：`GatewayStatus.hook_degraded`（`tooling_guard/ui/contracts.py:14`）→ `/guard status` 输出
「上次工具集安装降级：<kind>/未观察到」（`tooling_guard/ui/commands.py:250`），并附 `_COVERAGE` 的诚实
声明（`commands.py:90-98`，`:261` 输出）：「canary 与本次钩子执行只证明本进程当前行为，不能证明每个
真实请求都触发了钩子：钩子安装失败、cron/后台唤醒与子 agent 内部调用都不会留下「已覆盖」的证据。」

### U3 · 回复即审批（`tooling_guard/ui/reply_approval.py` + 仓库根 `main.py`）

审批通知固定 6 行，最后两行给「回复「同意 <前 8 位>」批准或「拒绝 <前 8 位> 原因」拒绝；
等价命令「/guard approve <ticket>」」与覆盖边界；**通知里不再出现 /guard deny、/guard status、「如非预期请拒绝」**。
三条决定入口（命令面、Web、私聊回复）都必须走 `ui/commands.py` 的 `decide_ticket`（同一 CAS、同一
`_late_result` 迟到路径），回复面审计 `tool_name=guard/reply`、`source=manual`，**MUST NOT 另写状态机**。
回复只在「私聊 + 管理员 + 有待批票据」时生效，否则返回 `None` 让消息照常进 LLM；裸词只在恰好一条
待批票据时执行，多条必须写 ≥4 字符票号前缀。`handle_reply` 是**同步**函数，`await` 它运行时会抛
`object str can't be used in 'await' expression`（e2e 抓到过一次）。

### V0 · 三层共识（0.6.0 起；与本文任何旧段落冲突时以本节为准）

判定只有三层，看的是**同一份输入**（`triage/engine.judge_payload` 的 state，`prompts/state.build_state`
唯一构造点已逐字段脱敏）：静态（`policy`+`base_check`+`rules`）→ 快审 `jev_fast` → 深审 `llm_deep`。
折叠在 `tooling_guard/core/consensus.py`（纯函数 `consensus(verdicts) -> Consensus`）。

- **只有静态层能自动拒绝**。静态层只做「必须直接拒绝」的判定：用户黑名单、`path_deny`、私钥/凭据内容、
  敏感配置读取（R6）、`strict_path_whitelist`、`download/decode + powershell/cmd 执行`（R3/R4）。
  其余一律 `PolicyDecision.PASS`（中性，不是批准）。**没有 T-strong/T-weak 分级判决了**：
  `policy/tools.py` 的 `T_STRONG_TOOLS`/`T_WEAK_TOOLS` 只剩标签用途。
- **白名单是唯一的静态通过**：`policy.layers` 的 `LAYER_WHITELIST` 分支记 `ALLOW`，两个模型审查器
  直接 `skip`（`reviewers/_common.skips_model_review` 只看这一层）。`AllowHints`（含域内=in_project_root、
  destination_allowed）**不再是批准**，`policy_verdict` 已删掉 `whitelisted` 参数——否则「目标在域内」
  就会自我放行。
- **一票批准即放行，全部弃权才问人**：任一模型 `allow`（`ReviewOutcome.ALLOW`；`SKIP`≠批准）且无模型
  `deny` → `allow`。模型 `deny` → `SUSPENDED` + `ticket_kind=model_deny`（高风险，需管理员显式放行）；
  两个模型都没结论 → `SUSPENDED` + `ticket_kind=all_abstain`（非常规操作）。措辞在
  `notify/messages.py` 的 `TICKET_KIND_LINES`，由 `_Plan.ticket_kind` 传入，**不进 tickets 表**。
- **弃权不是拒绝**：模型超时/异常/回答不可解析都折成「没有意见」（`judge_verdict` 写
  `DETAIL_SKIPPED=abstained`），`core/pipeline._timeout_verdict` 也已改为 `ReviewOutcome.SKIP`。
  `engine.judge_stage` 只在静态 `DENY` 时跳过模型（`SKIP_POLICY_DECIDED`），规则命中不再挡模型。
- **两轮编排**：`main._decide` 轮 1 = `_STATIC_ROUND`（policy/base_check/rules/jev_fast）；轮 2 只跑
  `llm_deep`，条件是「jev 不参与 / jev 弃权 / jev 要求深审（`DETAIL_FORCE_DEEP`）」，jev 自己拒绝时
  **不跑深审**（`_needs_deep`）。两轮 verdict 用 `core/pipeline.merge_outcomes` 合并后统一折叠；
  `ReviewPipeline(only=...)` 做子集选择，`only` 为空 → `DENY_RULE`（空集不能静默放行）。
- **预算**：`decision_budget_s`（默认 120、上限 120）三层共享，入口再留 `DECISION_RESERVE_S=30s`；
  `jev_timeout_s`（默认 10、上限 50）、`deep_analysis_timeout_s`（默认 60、上限 60）。超预算或轮内
  异常**不再硬拒**，按「没有结论」问人（`Gateway._ask_human_plan`，observe 下只记 `would_be`）。
- **observe 不建票**：`consensus` 不看 mode；`Gateway._observed_plan` 把任何非放行结论改写成
  `ALLOW_PASSTHROUGH` + `would_be`（`_plan_from_pipeline`、`_ask_human_plan` 都过它），所以观察模式
  下模型永远拿不到阻塞票。`_judge_route_of` 在 verdict 的 `consulted` 处记 route，不再从 decision 反推。
- **深审拿到了完整输入**：`main._deep_judge_callable` 用 `prompts/deep_call.py` 的 system prompt + JSON
  schema 喂同一份 state，返回过 `jev/schema.parse_text_answer`。旧路径（`build_trajectory_prompt` 无 schema、
  返回散文 → 全落 `unreadable`）是 0.5.0「深审 232 条全 uncertain」的成因；`deep_review`/`_deep_dispatch`
  已是死代码，不要复活。

- **0.6.1–0.6.2**：快审中间档与低置信度都弃权（`jev/score.decide` 返回 `None`，`judge_stage` 仍写 `degraded=fast_low_confidence`）；
  `JudgeStage.score/confidence/note` → `_review_report` → `_Plan.review` → `summary_json.review`（Web 票据详情读它，审计表列不变）；
  `build_sender` 记 `send.attempts`，成功写 `notify_sent`、失败写 `notify_failed: <reason> | <admin>=<result>`（宿主 `Context.send_message` 对不存在的 umo 也返回 True）；裸管理员 id 走 `admin_sessions` 逐个试宿主平台，`EPHEMERAL_PLATFORMS={"webchat"}` 上的成功记 `ephemeral` 不算送达；`_record_notify_sent(self, notice, ...)` 参数曾叫 `audit` 遮蔽 `.store.audit`；`web/queries.pick_ticket_event` 先取「suspended 且带 summary」的行；`ui/commands._late_disclosure_due` 按 `(ticket, verb)` 去重。
- **0.6.4：历史进了模型输入**。`Gateway` 自己建 `TrajectoryRecorder`（`_build_recorder`，读 `trajectory_retention_per_user`）——旧代码只在注入时才有 recorder，生产恒为 `None`，窗口永远空、R7/R9/R11 从不触发；`_trajectory_view` 把裸 tuple 包成 `TrajectoryView(entries, session_key, now=time.time())`；`triage/rules._entry_at` 认 ISO 文本（`CallSummary.at` 是文本，过去被当成没有时间＝永远在窗口内）；`triage/engine.trajectory_history` 取最近 8 条渲染成 `trajectory_summary` 塞进 `judge_payload`，jev 与 deep 看同一份历史；**0.6.5** 起记录带上 `targets=self._targets_of(tool, args)`（否则 `_sensitive_read_name` 恒空，R7 生产永不触发）；**0.6.6** 起 R7 命中必写 `DETAIL_FORCE_DEEP`（`reviewers/jev_fast.FORCED_DEEP_RULES`）——R7 仍只标不拒，但一定惊动深审，深审 deny 才落 `model_deny` 票。
### V1 · 审查器流水线与观测面（`core/` + `reviewers/`）

判定不再是一段硬编码顺序，而是「注册表 + 并发流水线 + 内置审查器」。改这一节任何一条都要同步 `README.md`
的「审查器流水线与观测面」。

- **启用集与顺序来自注册表**：`core/registry.py` 决定谁被启用、按什么顺序展示；`core/pipeline.py` 让
  本轮选中的审查器**并发启动**（`only=...` 选子集，0.6.0 起分两轮跑），只在第一个 `deny` 时早停；
  折叠口径见 V0（**一票 allow 即放行**，不再是「全员 allow 才放行」）。五个内置审查器是 `reviewers/policy.py`
  （`NAME="policy"`、`ORDER_POLICY=-10`、`core/registry.py` 的 `_PROTECTED_NAMES` 拒绝注销、
  `_ALWAYS_ON_NAMES` 拒绝停用）、`reviewers/base_check.py`（`order=0`、拒绝注销、可停用）、
  `reviewers/rules.py`、`reviewers/jev_fast.py`、`reviewers/llm_deep.py`。
- **基础检查器可以停用，但它只关白名单提示**：`base_check_enabled`（`_conf_schema.json:10`，默认 `true`）
  关掉后只有 `base_check` 从流水线移除——它独占的那一档是「白名单命中把 `skip` 提升成显式 `ALLOW`」，
  所以停用只损失这句提示：路径黑名单、用户黑名单、私钥/PEM、`strict_path_whitelist` 与敏感配置等
  **静态拒绝项**仍由**不可停用**的 `policy` 审查器判定（`reviewers/policy.py`；R8 S1 的修复就是把它拆成独立审查器）。
  停用绝不静默：网关写一条降级审计行（`summary_line` 形如
  `reviewer degraded=base_check_disabled base_check=disabled`，常量 `DEGRADED_BASE_CHECK_DISABLED`；恢复写
  `DEGRADED_BASE_CHECK_RESTORED`），并按 kind 600 秒限频告警管理员（`_schedule_reviewer_alert`）。写行由
  `_note_reviewer_state` 判定「真的发生切换」，重启后配置没变不重放。配置值不是布尔时
  `tooling_guard/policy/config.py:272` 的 `boolean()` 记一条「必须是布尔值」告警并返回 `False`——**类型写错
  等于停用**（同样只掉白名单提示），并且 `/guard status` 会显示 `enabled=否`，不会退化成
  「照旧生效但没人知道」。
- **忙是三态**：`core/reviewer.py` 的 `BusyPolicy` 有 `SKIP` → `skip`、`FAIL_CLOSED` → `suspend`、
  `DENY` → `deny`（策略读不出时按 `deny` 折叠），折表是 `BUSY_OUTCOMES` / `outcome_for_busy`。忙时流水线在
  结果里追加 `degraded=reviewer_busy:<name>`（`BUSY_MARKER`），超时追加
  `degraded=reviewer_timeout:<name>`（`TIMEOUT_MARKER`），并按**弃权**（`ReviewOutcome.SKIP`）计。流水线不会替「忙」发明放行默认值。
- **观测面同源、`last_error` 不上屏**：`/guard status` 的审查器块（`ui.commands._reviewer_lines`，
  `tooling_guard/ui/commands.py:282`）逐个打印 名字 / `order` / `enabled` / `busy` / `in_flight` / 最近结果，
  另给状态词「已停用 / 正忙 / 就绪」；数据来自 `Gateway.reviewer_statuses`，Web 的 `/status` 经
  `web.queries.serialize_reviewer`（`tooling_guard/web/queries.py:382`）读同一个来源，所以两个面不会互相
  矛盾。`last_error` 可能引用宿主异常原文，永不上屏——降级 kind 已经说明发生了什么。

### X1 · 信任域、模型审查器开关与配置降级观察

本节记录信任域、两个模型审查器开关与配置降级观察，每条都标了实测行号与**代价**。判决语义以 V0 为准，本节只讲开关与降级。

- **信任域不再放行，只剩标签**（开关 `trust_project_roots`，`_conf_schema.json:40`，默认 `false`）。
  0.6.0 删掉了策略层的 `LAYER_TRUSTED_ROOT` 分支与 `skips_model_review` 的域内例外，所以
  `trusted_in_project_roots`（`tooling_guard/policy/allowlists.py:520`）现在只产生 `AllowHints`（
  `in_project_root` 等标签），**既不放行也不跳过模型审查**——放行只有白名单一条路（见 V0）。状态面
  `_trust_line`（`tooling_guard/ui/commands.py`）照旧展示开关值。**代价**：打开它不再减少模型调用次数，
  它的唯一作用是不再把「目标在域内」当成可疑信号。
- **两个模型审查器各有一个开关，策略与规则关不掉**。`jev_enabled` 默认 `False`（`tooling_guard/policy/config.py:155`，
  解析 `:442-443`）、`llm_enabled` 默认 `True`（`:159`）。两个都关只产生一条 advisory
  `deep_reviewers_disabled`（`:478-486`，code 登记在 `ISSUE_CODES` `:34`），**不会**让流水线放行全体：
  `policy` / `base_check` / `rules` 照跑，`_PROTECTED_NAMES`（`tooling_guard/core/registry.py:54`）拒注销、
  `_ALWAYS_ON_NAMES`（`:58`）拒停用。装配门在 `main.py:1903`（`_jev_enabled`）与 `:1915`（`_llm_enabled`），
  客户端建造点 `:4956` / `:4997`；状态词 `ui/commands.py:146-149`，行生成 `:1863` / `:1882`。
  快审协议由 `fast_judge_backend`（`_conf_schema.json:18`，默认 `jev`，可选 `llm`）选择，两种后端都**只发一次请求**、
  从同一次响应取回风险分 + 深审建议 + confidence：`jev` 把结构化 JSON 状态原样 POST 到 `jev_base_url`（**完整 endpoint**，
  不追加路径段；只填基址会 404 且不报错），`llm` 走 OpenAI 兼容 `chat/completions`。分档只看 `tooling_guard/jev/score.py`
  的纯函数（`fast_allow_score` / `fast_block_score` / `fast_min_confidence`）；读不出一律弃权——弃权不是拒绝（V0）。
  单次上限是配置键 `jev_timeout_s`（默认 10，1–50；`jev/client.py` 的 `MAX_TIMEOUT_S=50` 是绝对上限），
  因为本机 Ollama 冷启动约 15 秒、写死 5 秒会让每次快审都超时。**深审客户端必须拿到宿主 Context**
  （`_build_deep_client` 传 `context=self._context`）：`llm_provider_id` 留空时 `astrbot_provider` 只能靠它解析
  宿主默认模型，缺了就是每次请求 `TypeError`，再被断路器统一报成 `judge_unavailable`（诊断包实测）。
  **代价**：`llm_enabled=false` 只是不注册深审（`_build_reviewers` 里 `registry.disable(DEEP_REVIEWER_NAME)`），
  快审弃权时就没人再给第二票，判定落到 `all_abstain` 问管理员——这是**可用性代价**，不是安全放松。
- **配置校验失败降级为观察，不阻断**。`REASON_GATEWAY_OBSERVED`（`tooling_guard/main.py:253-255`）与
  `DEGRADED_GATEWAY_DISABLED`（`:258`）；判定入口 `:2903-2904` 在 `not self.enabled` 时走
  `_observe_disabled`（`:3949`），写一条 `decision=allow_passthrough`、`degraded=gateway_disabled` 并带
  致命 `key` 名的审计行（行文本 `:3984-3989`，返回 `:4024-4026`），管理员告警走 `_alert_disabled`
  （`:4028`，正文 `:4062-4066`、投递 `:4073-4088`，与其它降级共用 600 秒限频
  `DEGRADED_WINDOW_S`，`tooling_guard/notify/ratelimit.py:22`）。`/guard status` 明写「降级观察（不拦截）」
  （`ui/commands.py:486-491`）。**代价**：配置写错时受管工具**照常执行**，安全只剩审计与告警，不是拦截。
- **`llm_provider_id` 留空即用宿主默认模型**。`llm_mode = text(llm_mode) or astrbot_provider`
  （`tooling_guard/policy/config.py:454`，注释 `:473-477` 明说空值是合法选择）；
  `tooling_guard/provider/llm.py:157-169` 的 `_generate` 在 `provider_id` 为空时调 `:171` 起的
  `_default_provider_id`（失败抛 `TypeError` / `RuntimeError`）。**代价**：宿主没有可用 chat provider 时
  深审一律弃权（异常折成「没有意见」，degraded 前缀 `triage_error:` 在
  `tooling_guard/reviewers/_common.py:102`），于是每条调用都退化成 `all_abstain` 问管理员。

- **未配置项目根不再是致命项**。`project_roots` 空表只报 advisory（code 仍是 `root_missing`，
  `tooling_guard/policy/config.py:394-404`）；非空但不可解析的条目仍在 `:405-418` 报致命、网关不启用。后果：
  出厂默认现在是 `enabled=True` + `mode=observe` 的**真判定**，审计行**不带** `degraded=gateway_disabled`——
  那条降级观察只留给相对 `path_deny` / 无法编译的正则 / `enforce` 缺管理员等真致命项。**代价**：没有项目根 ⇒
  `trust_project_roots` 的域内标签永不出、`outside_project_roots` 污点不覆盖任何路径；`/guard status` 会一直挂着这条
  advisory，别把「能启动」读成「配置正确」。
- **不可纳管工具默认放行，开关可整体改回剥离**。`strip_unmanaged_tools`（`_conf_schema.json:14`，默认
  `false`）：`tooling_guard/interface/install.py:206` 的 `strip_unmanaged` 读属性 `:225`（读不出就记
  `logger.error` `:227` 并当不剥离），决定 `mcp` / `handoff` / `background` / `future_task` / `unknown`
  **五类**统一走 passthrough 还是 stripped（分支 `:427-430`）；值来自 `Gateway.strip_unmanaged_tools`
  （`tooling_guard/main.py:1509-1521`）。两条 WARN 各只有一条：剥离 `:459-465`、放行披露 `:466-471`。
  打开时出 advisory `strip_unmanaged_tools_enabled`（`tooling_guard/policy/config.py:559-569`，code 登记
  `ISSUE_CODES` `:64`；字段 `:165`、透传 `:635`；非致命）。**硬边界**：开关是**单向全有或全无**——
  不能只剥 MCP 而保留 `future_task`；两条路都**不写审计行**，所以「放行」与「剥掉」都不是「审过」。

### W1 · Web 面的最小契约（`tooling_guard/web/` + `views/guard/index.html`）

改这四条里任何一条都等于改 Web 契约：路由前缀、两个配置键、共用 `decide_ticket`、输出白名单。

- **路由恒带插件名前缀**。`base = f"/{plugin_name}/guard/api"`（`tooling_guard/web/api.py:396`），
  六条路由是 `/events`、`/tickets`、`/tickets/<ticket_id>`、`/tickets/<ticket_id>/approve`、
  `/tickets/<ticket_id>/deny`、`/status`。前缀不是可选项：宿主按插件挂载路径首段取插件名
  （仪表盘插件接口里的 `plugin_name = plugin_path...split("/", 1)[0]`），裸 `/guard/api/...` 永远
  不会命中。注册入口 `register_web_apis`（`api.py:457`）经根 `main.py` 的
  `context.register_web_api`（`getattr` 探测）挂上；注册失败只 `logger.warning`，不阻断插件加载。
- **两个配置键只做收窄，不做放行**（`_conf_schema.json`）：宿主注入的用户名（`request.username`）非空，就视为
  已登录运维者，**默认读全部主体且不写任何拒绝行**。`web_subject_map`（`<dashboard_username>=<platform_id>:<user_id>`）
  只在该用户名被映射时把可见范围收窄到那个 `subject_key`，空映射 = 不收窄；`web_admin_usernames` 空 = 任何已登录
  用户可 approve/deny，非空才限定名单（`tooling_guard/web/queries.py:149 resolve_scope`）。只有拿不到身份才 fail-closed。
- **两通道共用同一个迁移**：Web 的 approve/deny 与命令面 `/guard approve|deny` 都只调
  `tooling_guard/ui/commands.py:539` 的 `decide_ticket(...)`（内部走 `tickets.transition` 的 CAS 与
  迟到路径）。Web 只做 `PENDING → APPROVED/DENIED`，消费仍由网关的 `consume_approved` 完成
  （`tooling_guard/store/tickets.py:664`）；Web 永不授权调用。
- **`/guard whoami` 是唯一对任何发送者开放的只读命令**（`tooling_guard/ui/commands.py:1698 WHOAMI_COMMAND`、
  `:1840 _whoami_reply`）：不写审计行、不读不建票据、不改配置、不跑日常到期维护；拒绝回复首句仍是逐字
  `REFUSAL_TEXT`，其后只追加只描述请求者自己的诊断（`:1872 _diagnosis_note`），名单条目永不出现在回复里。
- **白名单字段**：审计行只出 `queries.EVENT_FIELDS`、票据只出 `queries.TICKET_FIELDS`
  （`tooling_guard/web/queries.py:39`、`:63`），`args_digest` 与原始 `summary_json` **永不出网**；
  票据详情里的「执行了什么 / 三层结论」走 `serialize_call_context`（0.6.1 起，脱敏后的 `args_head` +
  `review`），不是把 summary_json 塞进列表接口。分页默认 50、硬上限 200；时间窗默认 24 小时、最大跨度
  7 天，超跨度返回 400。
- **状态码语义**：已登录用户读接口 → **200 + 全量行**（除被 `web_subject_map` 收窄）且**零拒绝行**；无身份的读 →
  **403 + 提示从本机面板登录**，并写一条 `deny_requester` 审计（`source=web`，`tooling_guard/store/audit.py:43`），
  同主体同动作 60 秒最多一行、折叠计数打在窗口之后的下一条上（`_read_refusal` `tooling_guard/web/api.py:177`）；
  票据详情不存在或不可见 → **404**；决策被拒 → **403**，在读写票据**之前**返回且**每次都写行、永不折叠**；
  `/status` 拿不到宿主注入的用户名 → **401**；存储不可用 → **503**。

### T1 · 深度分析分流（已废弃，勿信）

0.5.x 的「同步 / 后台深审」分流（`_deep_dispatch`、`_schedule_deep_review`、深审结论缓存等）在 0.6.0
已无调用方：深审是 `_decide` 的第二轮，触发条件 `_needs_deep`。函数仍在 `main.py` 但**不要复活**，判决以 V0 为准。

### S1 · 会话挂起策略：群会话一律等待、名单整键精确、上限是活配置

挂起资格只看**会话**，与工具、与发起人身份都无关；这几条都是契约级行为，改任何一条都要同步 `README.md` 的
「挂起与超时语义」。

- **群会话一律等待，唯一例外是显式名单**。会话键形如 `platform_id:message_type:session_id[:group_id]`
  （`session_key`，`tooling_guard/interface/identity.py:44`），群事件只在键尾多一段群 id，`GroupMessage`
  只是键里的标签（`GROUP_MESSAGE`，`tooling_guard/notify/sender.py:36`）。**任何发起人**发起的群调用都走
  普通挂起路径：票据照建、`session_key` 仍是群会话键、私信通知给回复词与票据短码、附一个等价 `/guard approve <id>`（`notify/messages.py:211`）、批准后经同一套 `consume_approved`
  消费一次。**「能等」从来不是权限**：批准门槛一字未动，仍是宿主 `event.is_admin()` **与**插件
  `config.admins` 双条件（`_admin_actor`，`tooling_guard/ui/commands.py:1588`；名单匹配器
  `is_admin_subject`，`tooling_guard/notify/sender.py:207`，与命令面 `_listed_admin`（`ui/commands.py:1660`）
  是同一份实现）。代价：整群模型的回合最长停 110 秒；每次挂起都给每位管理员发私信且**没有** 600 秒限频
  （`limit_key`，`tooling_guard/notify/ratelimit.py:105-135`，票据进键所以不同票据不合并）；非管理员拿到的票
  自己批不了，结局只能是管理员批准或超时 `timeout_deny`；想让某个群回到立即拒绝就把它整键写进去。
- **唯一能取消等待的是 `suspend_disabled_sessions` 整键精确条目**。名单元素必须与 `audit_events.session_key`
  **完全相等**（`x:1` 不命中 `x:10`），绝不前缀、绝不子串（入口 `_suspend_suppression`，
  `main.py:3409`；逐字比较 `:3436-3438`）。命中即 `decision=deny_policy`、`reason=REASON_SUSPEND_DISABLED`
  （`main.py:267`）、零票据、零等待（`_suppress_suspend`，`main.py:3441`；标记 `:3465-3466`，单一 `replace`
  分支 `:3467-3475`），审计行带 `degraded=suspend_disabled_session`（`main.py:269`），并给管理员发一条
  按会话限频的抑制告警（`_alert_suspend_suppressed`，`main.py:3477`；正文 `:3513-3526`；
  `alert_scope=session`，`:3538`）。显式条目**压过任何发起人**：被点名的会话连 `config.admins` 里的管理员
  也立即拒绝；而且配置只能撤掉等待，永远不能把拒绝改写成允许。
- **`suspend_timeout_s` 是活配置**（`_conf_schema.json:3`，默认 110；取值区间 1–110 由
  `tooling_guard/policy/config.py:84` 的 `INT_BOUNDS`（条目 `:86`）拒绝而非钳制）。挂起结束时刻
  `effective_suspend_deadline`（`main.py:1173`）=`min(deadline, now + min(suspend_timeout_s, 110))`，
  上限来自 `suspension_cap_seconds`（`main.py:1146`、`:1170`，`MAX_SUSPEND_WAIT_S = 110.0` 在
  `tooling_guard/approval/waiter.py:40`）——**只会缩短，绝不放大**。同一时刻同时是票据 pending 窗口
  终点、等待方超时、通知里「剩余 N 秒」的终点（`suspension_wait_seconds`，`main.py:1131`、
  `:3605`；「剩余」在 `tooling_guard/notify/messages.py:203`）。剩余不足
  `MIN_SUSPEND_REMAINING_S = 30.0`（`waiter.py:43`）时零票据、立即 `timeout_deny` +
  `degraded=suspend_budget_exhausted`（`main.py:2992-3002`）。
- 抑制判定先于批准查票（`main.py:2969-2973`）：一张已批准票据不可能让被抑制的会话进入等待。

### H1 · 硬约束：运行时只 import `astrbot.api.*`

任何进入运行时路径的代码**不得** import `astrbot.core.*`；`astrbot.core` 只允许以字符串形式出现在
`GATE_FINGERPRINT` 里（`tooling_guard/compat.py:30-35`），或在 `tests/gate1/*` 的宿主内探测中真实
import。宿主内部符号变化靠 `GATE_FINGERPRINT` 的 canary 兜底（`tooling_guard/interface/hooks.py:109`）：
任一符号失配即 fail-closed（本轮受管工具从请求工具集移除）并告警，绝不退化成放行。

### R9 · 复核修复的硬规则（每条都对应一处代码，不许只改文档）

1. **自定义脱敏正则只接受可证明线性的子集**。判据只有一处：`validate_secret_pattern`
   （`tooling_guard/anonymize.py:601`，判据函数 `_finalize` `:542`），它返回稳定 code 而不抛异常——`pattern_too_long`（`:107`）、
   `pattern_nested_quantifier`（`:110`）、`pattern_nested_alternation`（`:113`）、
   `pattern_repeat_too_large`（`:116`）、`pattern_ambiguous_repeat`（`:119`）、
   `pattern_unsafe_construct`（`:122`）、`pattern_unbounded_wildcard`（`:125`）、
   `pattern_uncompilable`（`:128`）。三个上限是
   `MAX_SECRET_PATTERN_LENGTH = 512`（`:80`）、`MAX_SECRET_PATTERN_REPEAT = 64`（`:89`）、
   `MAX_SECRET_PATTERN_AMBIGUITY = 64`（`:97`）。**保守代价**：被拒的运营方模式**不会生效**，
   `/guard status` 只出一条 advisory，`GatewayConfig.secret_patterns` 仍保留运营方原文以便诊断；
   三个消费者各自过滤——`tooling_guard/policy/snapshot.py:268-272`（全被拒时 `:284` 明说「本次快照
   没有生效的脱敏扫描正则，网关仍会启用」）、`Anonymizer.__init__`（`tooling_guard/anonymize.py:1153`）、
   `TaintStore`（`tooling_guard/trace/taint.py:333-340`，可观测计数 `refused_secret_patterns`，`:365`）。
   内置默认规则不经过这台校验机，不受此限制。
2. **名单条目必须是绝对路径**。issue code `path_not_absolute`（`tooling_guard/policy/config.py:41`）
   是**致命**项：`path_deny` / `path_whitelist` 里出现 `~`、`%VAR%` 或相对路径即网关不启用
   （判定循环 `config.py:303-319`，形状判据 `_ABSOLUTE_ENTRY_RE` `config.py:59-61`：盘符绝对、UNC、
   POSIX 绝对）。不猜基准是刻意的：猜出来的基准与宿主真实打开的绝对目标永远比不上，规则会静默失效。
3. **敏感 glob 语义**。`tooling_guard/triage/classify.py` 自带一份手写 globset（`_glob_regex`，
   `:584`）：`*`→`[^/]*`、`?`→`[^/]`、`**/`→`(?:[^/]+/)*`、`**`→`.*`、`[...]`/`[!...]`
   字符类、`{a,b}` 先展开（`_glob_alternatives`，`:572`）。含文件名字符的凭据 glob（`id_rsa`、
   `**/*.pem`）判 `deny` / `deny_secret`；不含任何文件名字符的形态（`*`、`*.*`、`**`）判
   **suspend 而非 deny**（`_glob_credential` `:639`，无名字字符时返回
   `_GLOB_TOTAL_WILDCARD_WITNESS = ".env"`，`:230`）——宿主 `astrbot_grep_tool` 用同一参数读同一批
   文件，判 deny 会造成「同一参数在 file_read 与 grep 上判定不同」。
4. **启动 sweep 先过期、后作废**。`startup_sweep`（`tooling_guard/store/tickets.py:892`）先
   `expire_stale`（`:751`）再 `invalidate_on_startup`（`:836`，顺序就在 `tickets.py:937-938`），
   由 `open_db`（`tooling_guard/store/db.py:736`，包装函数 `run_startup_sweep` `:677`、调用点 `:775`）
   负责调。后果：窗口已自然关死的 approved 票据重启后保持 `expired`，不会变成 `canceled_external`
   ——只有还能被消费的票据才按「启动作废」处理。
5. **被取消的审查器必须归还忙计数**。`ReviewerSlot` / `begin` / `leave` / `record`
   （`tooling_guard/reviewers/_common.py:377`、`:418`、`:428`、`:452`）：`leave` 按 slot 幂等
   （`:444-450`，同一 slot 第二次调用不动计数），`record` 与计数分离（`:452-463`，没有 verdict 的
   调用不写 `last_outcome`）。`tooling_guard/core/pipeline.py` 在早停 / 超时 / 外层取消三条路径上都
   `await` 被取消的任务（`_await_cancelled` `:400`，上限 `PREEMPT_GRACE_S = 0.05` `:94`）。
   **硬规则：审查器适配器 MUST NOT 吞 `asyncio.CancelledError`**（内层 `finally` 只给计数、不写统计，
   `_common.py:542-544`、`:560-562`），否则 `reviewer_busy:<name>`（`BUSY_MARKER`，
   `pipeline.py:85`）残留、后续调用被误判为忙。超时 deny 触发的早停会连带取消仍在飞的**其余**适配器，
   不只是 jev。
6. **通知投递计入调用预算**。单次投递上限 = `min(5 秒, 本调用剩余预算)`（`NOTIFY_TIMEOUT_S = 5.0`，
   `tooling_guard/notify/admin.py:12`），夹取点在**唯一投递边界** `Gateway._send_notice`
   （`tooling_guard/main.py:3676`），上限由 `_delivery_cap`（`:3414`）算出、`_notify_timeout`
   （`:3442`）只剩薄包装；拿不到预算时仍有 5 秒上限。超时记 `notify_timeout`（`NOTIFY_TIMEOUT_REASON`，
   `main.py:139`）。投递失败**不得**被当作同意，也不得因此提前放行——审计与判决
   都不依赖送达。完整边界见下面的 R10 第 3 条。
7. **调用预算以一次调用为作用域**。`CallScope`（`main.py:966`）、`begin_call_scope`（`:1927`）、
   `end_call_scope`（`:1946`）在判定入口写死一个 deadline，`Gateway.remaining_seconds(context)`
   （`:1353`）只读这个作用域；**没有作用域时返回 `None`**，绝不用当前时钟重算（重算就是 R9-01 那个
   bug，`:1363-1370` 的 docstring 写明）。`_clamp_yield_time`（`tooling_guard/interface/wrapper.py:240`）
   据此钳 `yield_time_ms`；拿不到预算时**不钳制**、只记日志（`:269`）。
8. **配置解析层保留运营方原文**。被拒的自定义正则只出 advisory、不进生效集合，`GatewayConfig` 形状
   不变；但显式把 `secret_patterns` 置空仍是致命项（`tooling_guard/policy/snapshot.py:265-266`
   「secret_patterns 为空；拒绝构建策略快照。」，配置侧 code `secret_patterns_empty`，`config.py:48`）。

### R10 · 提交所有者与投递边界

R10 的五处修复都落在「共享状态」上。改这一节任何一条都要同步 `README.md` 的模式与安全语义 / 不保证项。

1. **一个连接只有一个提交所有者**。`sqlite3.connect(check_same_thread=False)` 只去掉线程亲和，**不**串行化
   事务：两个线程共用同一连接（因而共用一个事务）时，一方 `rollback` 会丢掉另一方未提交的行，一方
   `commit` 会把另一方的半成品一起提交。现在每连接一把可重入的 `threading.RLock`——`_CommitOwner`
   （`tooling_guard/store/db.py:382`；必须可重入，因为写函数会调写函数），入口 `write_lock`（`:450`），
   `write_transaction`（`:484`）在锁内 begin/commit/rollback，`serialized_write`（`:514`）是装饰器。
   `tooling_guard/store/audit.py` 的 5 个写函数与 `tooling_guard/store/tickets.py` 的 7 个写函数全部经
   `@serialized_write`；旁路观测 worker 线程也取同一把锁（`tooling_guard/observation.py:426`
   `_probe_worker_read`），所以它在别的线程里读写时同样排在同一条队列上。被挡住的写者计数在
   `blocked_writers`（`db.py:466`）。**已知边界**：事件循环上的写最多等一个 worker 持有的锁，上界由
   `BUSY_TIMEOUT_MS = 150`（`db.py:58`）与语句耗时共同决定——没有硬实时保证，别把它当超时契约。
2. **启动 sweep 失败 → 批准侧 fail closed，但进程照常启动**。`run_startup_sweep`（`db.py:719`）捕获异常
   并记下失败（`StartupSweepState`，`db.py:363`：`ok` / `error` / `attempts`），启动不阻塞；但
   `require_startup_sweep`（`db.py:571`）在 `startup_sweep_state(conn).ok`（`:537`）为假时抛既有
   `StorageUnavailableError`，而 `find_approved`（`tooling_guard/store/tickets.py:602`）与
   `consume_approved`（`:664`）都先过这道闸：网关抑制存储异常后一律拒绝，sweep 重试成功后才放行。
   **从未尝试过 sweep 的连接不算 fail-closed**（`StartupSweepState` 的 docstring 写明，生产路径必经
   `open_db` `:832`）——刻意的，好让只读工具与测试连接不必先跑 sweep。**R11 补全**：这个失败现在
   可观测（`/guard status` 与 Web `/status` 的 `startup_sweep{ok,attempts,error,approvals_closed}`）
   且有唯一受控恢复入口 `/guard sweep`，见 R11 第 4 条。
3. **通知投递上限只在一个投递边界夹取**。`Gateway._send_notice`（`tooling_guard/main.py:3676`）是唯一
   投递出口，每次投递上限 = `min(5 秒, 本调用剩余预算)`：上限由 `_delivery_cap`（`:3414`）算，
   `_notify_timeout`（`:3442`）只剩薄包装。hook degraded / reviewer state / gateway disabled /
   closing notice 四条告警路径与挂起通知全部命中同一个 `await self._send_notice(`（R11 之后共 6 处：
   `1844` / `1993` / `2074` / `3635` / `3947` / `4085`，第 6 处是启动清理告警）。**拿不到预算时仍有 5 秒上限**——预算未知不等于零预算。
   超时只记投递失败（`degraded=notify_timeout`），**不改判决**：审计与判决都不依赖送达。告警失败行的
   `reason` 带 label（形如 `delivery failed (hook degraded=canary_failed)`），仍以既有口径词开头。
4. **管理员看到的剩余秒数是保守值**。`_announced_remaining`（`main.py:3458`，渲染点 `:3628`）显示
   `真实窗口 − 单次投递上限`，恒有「显示 ≤ 实际剩余」，代价是最多低估 5 秒。真实窗口由
   `effective_suspend_deadline`（`:808`）与 `suspension_wait_seconds`（`:766`）决定，通知文本不参与
   超时判定，所以低估不会提前结束等待。
5. **judge payload 的 `deadline_monotonic` 是绝对时刻**。`tooling_guard/triage/engine.py:404` 传的是调用方
   单调时钟的**绝对时刻**，不是剩余秒数；键名不变，语义按此读（一致性断言已同步）。
6. **无界通配符是第八个稳定 code**。`pattern_unbounded_wildcard`（`tooling_guard/anonymize.py:125`，在
   `__all__` 里）——`_atom`（`:278`）把 `.` 归为**未知宽度**原子，`_finalize`（`:542`）只接受一种
   位置：该分支的**最后一个原子，且其后什么都不许跟**（零宽原子也算后继，R12 收紧，见 R11 第 1 条）。
   R11 把当时的两条额外豁免（整体锚定、前方有它匹配不到的字面 barrier）删掉了；其余位置按未知宽度抛
   `pattern_ambiguous_repeat`（`:587-593`）。所以 `a.*x` / `foo.*bar` 与锚定形态 `^.*x` 现在都被拒，
   而 `sk-[A-Za-z0-9]{16,}`、`hunter2\d+` 与有界重复仍接受。
7. **deny 侧秘密扫描不完整必须 fail closed**。`MAX_SECRET_SCAN = MAX_REDACT_SCAN = 262144`（`tooling_guard/
   policy/allowlists.py:27`）：`scan_secret_patterns`（`:432`）超限即截断，`SecretScan`（`:389`）带出
   `truncated` 与 `length` / `scanned` / `limit`，`secret_pattern_hit`（`:470`）据此拼 marker
   `secret_scan_truncated length=… scanned=… limit=…`（常量 `SECRET_SCAN_TRUNCATED`，`:38`）。截断
   **一定可见**：函数内部 `logger.warning`，层内 `reason` 带同一个 marker，`FragmentFilter.truncated_marker`
   （`tooling_guard/main.py:563`，赋值 `:1328`）也把它折进降级文案。R11 把「读满窗口仍没命中」
   单列为 `incomplete`（`:419-422`）/ `incomplete_marker`（`:424-429`，编码 `SECRET_SCAN_INCOMPLETE`，
   `:41`），策略层据此判 `deny_policy` + `degraded=secret_scan_incomplete`，**不再把窗口内未命中当成
   「无秘密」**：单参数超过 256 KiB 且秘密落在窗口之后时，调用是被**拒绝**而不是被漏放。见 R11 第 3 条。
8. **脱敏键名扩面**。env 前缀密码（`PGPASSWORD` / `PGPASS` / `MYSQLPASSWORD` 等，
   `_ENV_PASSWORD_KEY_ALIASES`，`anonymize.py:797`）、`passphrase` / `passcode`
   （`_PASSWORD_KEY_ALIASES`，`:780`，条目 `:782` / `:784`）、`Authorization: Basic <base64>` 与
   `Proxy-Authorization: Basic`（`_HTTP_BASIC_HEADER_RE`，`:929`）。别名表是封闭列举、不做子串匹配，所以 `compass` / `bypass`
   这类含 `pass` 但非密码的键仍然可读。
9. **批准票据的启动清理已订正**。仍按 R9 第 4 条的顺序（先 `expire_stale` 后 `invalidate_on_startup`）：
   窗口已自然关死的 approved 保持 `expired`，只有仍能被消费的才作废成 `canceled_external`。规格侧
   `openspec/changes/archive/2026-10-30-add-computer-use-tool-gateway/specs/audit-store/spec.md` 的 Ticket Persistence 与
   两个新增 Scenario（过期批准保持 `expired`、sweep 失败时批准侧 fail closed）与此一致。
10. **R8 的域内只读例外与深审片段保留**。只读判据在 `triage/classify.py`：`READ_ONLY_COMMANDS`（`:327`）、
   `WRITE_EXEC_WORDS`（`:391`）、`_read_only_line`（`:1135`）按每段首词判只读；`triage/engine.py` 的
   `_mark_read_in_roots`（`:253`）用 `paths.is_in_project_roots` 打上 `read_in_project_roots`（`classify.py:55`），
   `triage/rules.py` 的 `_rule_r8`（`:535-545`）见标签即 `return None`，其余判据与 `absolute_paths=<n>` 不变。
   写/删/执行动词、重定向、未加引号 `>`/`$(`、词表外工具、空 `project_roots` 照旧触发。深审片段只保留域外：
   `FragmentFilter`（`main.py:535`）+ `filter_fragments`（`:1241`）先丢秘密命中、把域外路径换成
   `<EXT>/<basename>`、重扫、2 KB 截断后进 `kept`；census 与 `_record_fragment_census`（`:4615`）记账，
   `no_fragment_in_scope` 只在 `kept` 为空时出现（`:2530`）。

回归覆盖（`tests/`，不随 zip 分发）：`test_concurrency`、`test_startup_gate`、`test_notify_cap`。

### R11 · 可证明的子集与清理闸门

R11 的五处修复都落在「证明」上。改这一节任何一条都要同步 `README.md` 的模式与安全语义 / 不保证项。

1. **证明从「末尾 / 锚定 / barrier」收紧成「只许分支末尾」**，R12 再收紧成「其后什么都不许跟」。判据仍只有一处：`_finalize`
   （`tooling_guard/anonymize.py:542`），入口 `validate_secret_pattern`（`:601`）。一个 top-level
   分支里，无界重复（`*` / `+` / `{n,}`）只允许作为该分支**最后一个原子**，其后**什么都不许跟**。
   **`^` / `A` 不再豁免**：锚定只减少起点数，不能把两个重复互相分配给同一个重复的输入解开。
   **R12 的关键一步是零宽原子也清标志**（`_branch`，`anonymize.py:268-276` 的
   `if kind == "zero": self._tail_open = False`）：零宽断言同样可能失败（`$` / `\Z` / `\z` / `\b` /
   `\B`），失配会把手上的长串退回量词、让每个起点重跑同一段，实测每翻倍约四倍耗时。所以
   锚定形态（`a+$`、`[a-z]+$`、`^sk-[A-Za-z0-9]{16,}$`）与 `(?i)x+$` 全被拒
   （判 `pattern_ambiguous_repeat`）。**保守代价**：`^.*x`、`a+b`、`a+^`、`(?i:a+)` 也被拒；仍接受 `sk-[A-Za-z0-9]{16,}`、`hunter2\d+`、`a+`。8 个稳定 code 不变
   （`:107` / `:110` / `:113` / `:116` / `:119` / `:122` / `:125` / `:128`）。
2. **出厂默认必须自己落在同一个子集内**。`_conf_schema.json:28` 的两条默认已改为
   `(?i)-----BEGIN [A-Z ]{0,63}PRIVATE KEY-----` 与
   `(?i)(?:api[_-]?key|token|secret)[ ]{0,4}[:=][ ]{0,4}[A-Za-z0-9_-]{12,}`。**规则没有放宽，改的是
   默认值**：旧形态 `[A-Z ]*` 实测每翻倍字符数约四倍耗时，262144 字符约两分钟——默认值自己就是那条
   二次方回溯。默认规则仍不过校验机，但形态必须与子集一致。
3. **deny 侧秘密扫描不完整必须 fail closed**。`MAX_SECRET_SCAN = MAX_REDACT_SCAN = 262144`
   （`tooling_guard/policy/allowlists.py:27`）；`SecretScan.incomplete`（`:419-422`，判据
   `self.pattern is None and self.truncated`）与 `incomplete_marker`（`:424-429`，编码
   `SECRET_SCAN_INCOMPLETE`，`:41`）把「读满窗口仍没命中」与「命中」分开。`tooling_guard/policy/
   layers.py:235-253` 因此判 `deny_policy` + `degraded=secret_scan_incomplete`，**不建票、不经可批准
   的敏感配置挂起**（那条分支在 `:260-270`，故意排在其后），observe 下只记 `would_be` 拒绝。语义：
   **窗口内未命中不能被当成「无秘密」**。残余不变：单参数超 256 KiB 且秘密落在其后时，它是被**拒绝**
   而不是被漏放。
4. **启动清理可观测，且只有一个受控恢复入口**。`PROCESS_STARTED_AT`（`tooling_guard/store/db.py:218`）
   记进程启动时刻；`startup_sweep_state`（`:537`）/ `require_startup_sweep`（`:571`）/
   `run_startup_sweep(conn, *, created_before=None)`（`:719`）/ `recover_startup_sweep`（`:800`）。
   `/guard status` 与 Web `/status` 同源打印 `startup_sweep{ok,attempts,error,approvals_closed}`
   （`ui/commands.py:377` 视图、`:408` 渲染，`web/api.py:367-375`），失败按 kind 600 秒限频告警
   （`main.py:201` / `:203` / `:2030`）。恢复命令 `/guard sweep`（`ui/commands.py:1353`，同一管理员
   60 秒一次，`RECOVERY_WINDOW_S` `:114`）只作废 `created_at < 进程启动时刻` 的票据：**不取消本进程
   活票、不复活旧授权**，窗口已关死的 `approved` 保持 `expired`；状态查询**绝不**触发**启动恢复清理**
   （`:383` docstring）；非预期异常会注销坏连接（`db.py:698 _abandon_connection`），不留按 id() 可达的锁。
   **不要把它读成「命令路径是纯只读」**：每个已授权命令执行前仍跑一次日常票据维护（`_sweep_note`
   `ui/commands.py:254` → `:1280` → `_sweep_summary` `:1228`），过期票据会迁 `expired` 并写审计行；
   窄口径只有一条 —— 没有任何命令会重跑启动恢复 sweep（R13-D2）。
5. **任何工具 stdout 不得直接写回源码路径**。反面教材就在本仓库：一次「把 ruff 的空 stdout 写回源码」
   把 `tests/unit/gateway/test_gateway.py` 截成 0 字节。硬规则：写源码前必须校验 exit code == 0、
   输出非空、写入字节数 > 0——缺一条就当作没跑。

顺带订正（都不改行为，只对齐事实）：网关侧 `pop_intent` 消费在 `tooling_guard/main.py:2801`（旧记录的 `:2681` 是漂移值）；密码键名仍是
**有限集合**（`MSSQLPASSWORD`/`REDISPASSWORD` 未列）；每连接 RLock 不是异步执行器，上界
`BUSY_TIMEOUT_MS = 150`（`db.py:58`）。

回归覆盖（`tests/`，不随 zip 分发）：`test_regex_safety`、`test_secret_scan_incomplete`、`test_startup_gate`、`test_startup_recovery`、`test_startup_sweep_alert`、`test_startup_sweep_recovery`、`test_gateway`。

### 其它既有硬规则（摘自 `ARCHITECTURE.md` §3）

- `_wrapped`、`mcp_*`、`transfer_to_` 这类上游实现细节只许出现在 `tooling_guard/compat.py`。
- 只用 `httpx.AsyncClient`；禁止 `requests`，也禁止同步 `httpx.Client`。
- 持久化数据只经 `StarTools.get_data_dir` 落到 AstrBot data 目录（`data/plugin_data/astrbot_plugin_tooling_guard`，
  插件根目录 `_data_dir()` `main.py:221` 解析），绝不写插件目录；改名前的 `plugin_data/astrbot_tooling_guard`
  在首次加载时由 `tooling_guard/store/db.py` 的 `migrate_legacy_data_dir` 一次性重命名迁入（见下节）。
- 平台相关读取只经 `get_platform_id` / `get_sender_id` / `get_group_id` / `is_admin` / `send`；OneBot v11 优先。
- 时间预算：`deadline = now + tool_call_timeout - 10`（`call_deadline`，`tooling_guard/main.py:709`）；
  挂起结束时刻 `min(deadline, now + min(suspend_timeout_s, 110))`（`effective_suspend_deadline`，
  `main.py:808`），即 `suspend_timeout_s` 只会缩短上限、绝不放大；剩余不足 30 秒不建票据；超时一律按拒绝处理。

## 命令

```powershell
ruff check .                  # 门禁一：必须 exit 0
ruff format --check .         # 门禁二：必须 exit 0（只检查，不要跑写模式）
py -3 -m py_compile main.py   # 无需宿主即可做的语法检查
openspec validate --specs             # 门禁三：主规格结构校验
openspec validate --all --strict      # 门禁四：变更 + 主规格严格模式
```

两条 `openspec validate` 都必须 **退出码 0**、**零 WARNING**，末行都是
`Totals: 9 passed, 0 failed (9 items)`（归档后变更已不在 `changes/` 下，只剩 9 个主规格）。本机 openspec CLI **可用**：
`openspec --version` 报 `1.15.0`，裸命令直接跑；`npx --yes openspec ...` 这条路仍然失败，不要用它。
规格结构因此有机器门禁，不必靠人工核对；但门禁只证明「结构合法」，语义仍以
`openspec/changes/archive/2026-10-30-add-computer-use-tool-gateway/specs/**/spec.md` 正文为准。

**不要去掉 `--check` 跑写模式**：ruff 0.17 会重排 Markdown 里的 python 代码块。要格式化某个 `.py` 就复制到
`$env:TEMP` 格式化后贴回。既然 `--check` 也查 Markdown 围栏，本文件与 `README.md` 的 Python 签名必须本身
format-clean，否则门禁二全红。

单元测试是**纯标准库脚本**，没有 pytest：本机 `py -3 -m pytest --version` 返回
`No module named pytest`（退出码 1），`tests/` 下也没有任何 `pytest` 关键字。每个测试文件自带断言
函数与末行结果，直接在仓库根用宿主 venv 的 Python 跑：

```powershell
$env:PYTHONPATH='.'                                   # 仓库根 = 插件包父目录
$py = '.venv/Scripts/python.exe'  # Python 3.12.13
Get-ChildItem -Recurse -Filter 'test_*.py' tests/unit | ForEach-Object { & $py $_.FullName }
```

判定标准：退出码 0，且末行是 `RESULT: all assertions passed (N checks)`、`ALL CHECKS PASSED` 或 `RESULT: PASS`。
`tests/unit` 现 **85 个**套件、合计 **7104** checks（6491 来自逐脚本计数，613 来自 `passed=N` 报数的三个脚本，两个 chokepoint 脚本只打印 `RESULT: all assertions passed`）。
**断言数以实跑为准**，改代码后重跑而不是照抄。

人工验收脚本不进单元门禁：`tests/manual/acceptance_rules.py`（54 checks）、
`tests/manual/budget_shared.py`（67 checks，共享预算）、`tests/manual/enforce_readiness.py`
（退出码 `0` = PASS / INSUFFICIENT DATA、`1` = FAIL、`2` = 脚本异常）。跑法同单元脚本。

`tests/gate1/*` 必须在真实 AstrBot 源码树里跑（它们 import `astrbot.core.*`）。当前机器上的宿主源码树是一份本地克隆
（AstrBot 4.29.3，commit `0e997cc`）；AstrBot 升版必须先跑归档 change 的 1.1–1.11 回归清单
（`openspec/changes/archive/2026-10-30-add-computer-use-tool-gateway/tasks.md`），再检查
`GATE_FINGERPRINT` 的九个符号。

`tests/e2e/` 是**真实宿主台架**，不是单元测试，也不进单元门禁：它用那份本地克隆的
AstrBot 4.29.3 加载本插件（路径写死在 `tests/e2e/harness.py:24-26` 的 `ASTRBOT_TREE`），经 aiocqhttp
反向 WebSocket 往返 `/guard` 命令面，并用 `tests/e2e/mock_provider.py` / `tests/e2e/mock_jev.py` 观测
「钩子之后、provider 看到」的工具集与判定器答复。**15 个场景**分三组：S1–S3（加载与命令面）、A1–A6（工具
清单 / 不可纳管工具默认放行与开关剥离、委派保真含剩余 5 个受管工具、剥离名调用、observe vs enforce、深审在真实路径上跑）、
B1–B5（挂起审批往返、deadline 记账、群消息里成员也照常挂起且用 `/guard deny` 结算、`suspend_disabled_sessions` 整键精确匹配、挂起上限
被等满），外加 C（A5+A6 的原组合路径复跑）。跑法 `& $py tests/e2e/run_e2e.py --scenario all`，末行
`RESULT: e2e passed (N checks)`，实测 228 checks；超时预算的权威值是代码里的 `SCENARIO_TIMEOUT_S = 360.0` / `TOTAL_TIMEOUT_S = 1800.0` /
`REPLY_TIMEOUT_S = 60.0`（`tests/e2e/run_e2e.py:43-45`），预算耗尽与场景超时都记成**失败**断言而
**不静默跳过**。未证明清单在 `tests/e2e/README.md`。
它**不是 hermetic 的**：需要本机真实宿主与那个固定路径，缺环境时应明说跳过，不能拿 mock 结果或
单元测试冒充端到端证据。

## Open items（待办，别自己拍）

1. **目录名（已完成）**：插件身份与仓库目录均已改成 `astrbot_plugin_tooling_guard`（`metadata.yaml`
   的 `name:`、根 `main.py:28` 与 `store/db.py:49` 的 `PLUGIN_NAME`；旧名只留在 `LEGACY_PLUGIN_NAME`）；
   数据目录由 `store/db.py` 的 `migrate_legacy_data_dir` 迁移（旧目录在新目录空时整体 `Path.rename`，
   否则只 warn 不合并，永不抛异常）。回归 `tests/unit/store/test_data_dir_migration.py`（44 checks）。
