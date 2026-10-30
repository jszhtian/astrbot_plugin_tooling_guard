# 模块架构（实现层布局）

本文件是已归档 change `openspec/changes/archive/2026-10-30-add-computer-use-tool-gateway/` 的**实现层**架构基准：只规定代码放置、模块职责与依赖方向。
语义（判定规则、预算公式、decision/would_be 取值、票据状态机、白名单语义）一律以 `design.md` 与 `specs/*` 为准；两者冲突时以 spec/design 为准，本文件只补「代码放哪、谁调谁」。

基线：AstrBot 4.29.3（commit `0e997cc`），插件只使用公开面 `astrbot.api`。

## 1. 分层与目录

~~~
astrbot_plugin_tooling_guard/
├── main.py                  # AstrBot 入口（文件名不可改）：ToolingGuard(Star)，只做钩子注册与生命周期转调
├── _conf_schema.json        # 插件配置 schema 与默认值
├── metadata.yaml            # 插件元信息（改名见 tasks 10.8）；含 views: 声明（tasks 11.7）
├── requirements.txt         # 仅 httpx（AsyncClient），禁 requests
├── views/guard/index.html   # 插件页面前端（tasks 11.7）：宿主只发现 views/<目录>/index.html；列表/筛选/详情/批准拒绝，不自建端口
├── ARCHITECTURE.md          # 本文件
├── TOOL-MATRIX.md           # 工具清单/分级/汇点矩阵（规格证据）
└── tooling_guard/           # 业务包：根 main.py 之外的一切实现
    ├── __init__.py
    ├── main.py              # 装配入口与主流程编排：Gateway（from_config :849 / set_mode :935 / on_llm_request :1017 / guard_call :1154 / handle_call :1189 / shutdown :1217）；_guard 改为注册表驱动（tasks 11.3）
    ├── core/                # 【目标态·契约与编排】审查器只依赖这里，自身不 import 具体审查器（tasks 11.1/11.2）
    │   ├── call.py          # GuardCall：一次受管调用的不可变输入（工具名、参数、主体/会话键、deadline）
    │   ├── verdict.py       # Verdict 与决策折算（allow/suspend/deny、rule_id、degraded；只收紧不放宽）
    │   ├── reviewer.py      # Reviewer 协议 + ReviewerStatus（order/enabled/removable/busy 三态/自有时间预算）
    │   ├── registry.py      # ReviewerRegistry：注册与启用集、拒绝注销、停用事实上交（不发通知不落库）
    │   ├── consensus.py     # Layered Consensus：把各层 Verdict 折成 (decision, ticket_kind)，静态拒绝唯一硬拒（0.6.0 新增）
    │   ├── pipeline.py      # ReviewPipeline：并发启动、only 子集、仅 deny 早停、超时按「没有意见」折叠（tasks 11.2）
    │   ├── budget.py        # 共享时间预算：deadline 记账、每审查器预算、110s 挂起上限
    │   └── guard.py         # 只读视图（状态/票据/taint），ui/ 与 web/ 共用同一来源
    ├── reviewers/           # 【目标态·内置审查器】只调 core 契约与只读视图（tasks 11.3–11.5）
    │   ├── policy.py       # 静态层：只做「必须直接拒绝」的判定（黑名单/路径/私钥/秘密/敏感配置/strict 白名单），其余一律 PASS 交给模型；order=-10、拒绝注销与停用（R8 S1）
    │   ├── base_check.py    # 白名单提示：命中把 skip 提升成显式 ALLOW（黑名单优先，永不覆盖 deny）；order=0、拒绝注销、可停用（tasks 11.4）
    │   ├── rules.py         # 规则审查器：包装 triage/rules.py 的 R1–R12
    │   ├── jev_fast.py      # 快审审查器：包装 jev/*，单次 HTTP、超时可配（≤50s）、失败与超时即「没有意见」而不是拒绝（后端由 fast_judge_backend 决定）
    │   └── llm_deep.py      # 深审审查器：包装 provider/*，吃与快审同一份 judge_payload，由快审弃权或 force_deep 触发，结论是 allow/deny/弃权
    ├── web/                 # 【已落地·宿主插件页面后端】register_web_api（tasks 11.6）
    │   ├── __init__.py      # 出口：只 re-export api/queries 的注册函数与 Scope/QueryError，不含逻辑
    │   ├── api.py           # 路由注册与鉴权：已登录即读全量、被映射才收窄，决策按名单（610 行，本轮实测）
    │   └── queries.py       # 列表与筛选：subject / session / decision / rule_id / 时间窗（466 行，纯 stdlib 只读）
    ├── compat.py            # 唯一允许触碰脆弱线索（_wrapped、MCP 属性、handoff 前缀）与版本指纹常量
    ├── anonymize.py         # 脱敏出口统一入口（审计、通知、模型、深度分析片段）；单次扫描上限 MAX_REDACT_SCAN = 262144（R8 S13）
    ├── interface/           # 插件交互层：唯一直接面向 AstrBot 运行时对象的层
    │   ├── hooks.py         # on_llm_request 与命令钩子适配器（薄，只转换与转调）
    │   ├── identity.py      # platform_id:sender_id、最小会话键、CronMessageEvent 判别
    │   ├── install.py       # proxy install/terminate：遍历 req.func_tool、装配计数、gate_fingerprint 自检
    │   ├── wrapper.py       # 受管工具代理（FunctionTool 子类，覆写 call）
    │   └── results.py       # 拒绝/挂起/批准结果构造（CallToolResult(isError=True) 与真实非空字符串）
    ├── policy/              # 能力库，被审查器调用（policy / base_check 经 allowlists）：配置与策略层
    │   ├── config.py        # 配置加载 + 严格校验 fail-closed（tasks 2.3）
    │   ├── layers.py        # 求值顺序：豁免 → deny 侧（含敏感配置）→ 白名单（唯一静态通过）→ PASS（其余交给 jev/deep）
    │   ├── paths.py         # Windows 路径规范化（.. \?\ UNC ADS 8.3 Junction）
    │   ├── allowlists.py    # user/path/destination_allowlist 语义（只降延迟或深度，不直通）
    │   ├── snapshot.py      # 不可变策略快照 + policy_version
    │   └── tools.py         # 工具名表与分类标签来源（T-strong/T-weak 只作标签，不再参与判决，来源 TOOL-MATRIX.md）
    ├── triage/              # 能力库，被审查器调用（rules / jev_fast）：单条审核（同步路径）
    │   ├── classify.py      # 分类标签（T-strong/T-weak 仅作标签）、untrusted_source、sink_read/sink_deliver、目标抽取、
    │   │                    # 只读命令词表 READ_ONLY_COMMANDS / 写执行词 WRITE_EXEC_WORDS、域内只读标签
    │   ├── rules.py         # 规则目录 R1–R12（只判定，不做 I/O）
    │   ├── decisions.py     # decision / would_be 枚举与词形映射
    │   └── engine.py        # 判定编排：静态 → 快审 →（弃权或要求时）深审 → 决策；模型失败/超时/读不出＝弃权
    ├── trace/               # 能力库，被 main 与审查器调用：指令与操作轨迹（异步路径）
    │   ├── intent.py        # 执行前意图记录（call_id UUID、FIFO 配对、intent_unpaired）
    │   ├── recorder.py      # 轨迹追加（同会话保序、跨会话并行）
    │   ├── summary.py       # 固定 22 键摘要 schema（以 specs/call-triage 为准）
    │   ├── taint.py         # 会话 taint 与私有 shingle 集合（TTL 30 分钟 / 4096 LRU / 三不）
    │   ├── escalation.py    # R12 三触发评估（A 内容回传 / B 目的地来源 / C 密钥模式）
    │   └── retention.py     # 保留期与清理
    ├── store/               # 能力库，被 main 与 web 调用：持久层（仅 sqlite3，data 目录，非插件目录）
    │   ├── db.py            # 打开/迁移/可用性探针；不可用 → 受管调用一律 deny
    │   ├── audit.py         # 逐次判决与审计（含 observe 的 would_be 两列）
    │   └── tickets.py       # 审批票据持久化与 CAS 状态机
    ├── jev/                 # 能力库，被审查器调用（jev_fast）：快审客户端（不含提示词正文）
    │   ├── client.py        # 完整 endpoint、async HTTP、超时可配（≤50s）、不重试、失败即弃权；jev/llm 双后端
    │   ├── score.py         # 纯函数：分数归一化、阈值分档、confidence 下限、强制深审判定
    │   └── schema.py       # 响应解析（score / noul / confidence）与安全默认（读不出按弃权，不按拒绝）
    ├── prompts/             # 能力库，被审查器调用：提示词构建（无网络 I/O）
    │   ├── state.py         # 结构化判定状态（唯一构造点、脱敏、超长瘦身）
    │   ├── systemone.py     # jev 后端请求体：questions 里 risk(score) + deep(noul)
    │   ├── single_call.py   # llm 后端提示词：只要一段 {"score","noul","confidence"} JSON
    │   ├── deep_call.py     # 深审提示词：system prompt + {"score","noul","confidence"} schema，正文是同一份 state（0.6.0 新增）
    │   ├── trajectory.py    # 轨迹深审判定提示词（0.6.0 起深审不再走这条路）
    │   └── templates/       # 固定格式片段
    ├── provider/            # 能力库，被审查器调用（llm_deep）：LLM 接入（深度分析）
    │   ├── llm.py           # llm_mode = endpoint | astrbot_provider 统一接口
    │   └── archive.py       # 深审结论归档与后台任务句柄
    ├── notify/              # 能力库，被 main 与 core 调用：管理员通知
    │   ├── admin.py         # 通道选择、失败不视作同意、重试边界
    │   └── messages.py      # 文案渲染（先脱敏后渲染）
    ├── approval/            # 能力库，被 main 调用：审批交互与迟到决定
    │   ├── waiter.py        # 代理 call 内同步等待（deadline 记账）
    │   └── lateness.py      # 迟到决定：拒绝、保持 timeout（system_prompt 回填未落地，见 README 不保证项）
    └── ui/                  # 命令面（/guard、/toolguard）：视图数据类迁往 core/guard.py，页面由 web/ + 根 views/ 承担（tasks 11.6/11.7）
        ├── contracts.py     # 状态/票据/taint 视图数据类
        └── README.md        # WebUI 行为需先加 spec requirement 才能实现
~~~

## 1a. 三层共识（0.6.0 起）：静态 → 快审 → 深审

判定只有三层，三层看的是**同一份输入**：`triage/engine.judge_payload` 生成的 state
（`prompts/state.build_state` 唯一构造点，逐字段脱敏并截断）。模型出口统一走脱敏；
**落库的审计行保留原文**，脱敏只发生在对外出口。

| 层 | 实现 | 输出 |
|---|---|---|
| 静态 | `reviewers/policy.py` + `base_check.py` + `rules.py`（`policy/layers.py`） | 只回答一个问题：是否属于**必须直接拒绝**的高危形态。命中即 `DENY`；白名单命中是唯一的静态通过（`ALLOW`，跳过两个模型）；其余一律 `PASS`（中性，不是批准） |
| 快审 | `reviewers/jev_fast.py`（`jev/*`） | `allow` / `deny` / `abstain`（弃权），并决定是否需要深审（`force_deep`） |
| 深审 | `reviewers/llm_deep.py`（`provider/*`） | 同上，独立于快审给结论；`approve` 计为放行票 |

判决折叠在 `core/consensus.py`（纯函数 `consensus(verdicts) -> Consensus`）：

| 静态 | 快审 | 深审 | 结果 |
|---|---|---|---|
| 命中 deny 条件 | 不问 | 不问 | `deny_*`（唯一自动硬拒） |
| 白名单 | skip | skip | `allow` |
| PASS | allow（不要求深审） | 不问 | `allow` |
| PASS | deny | **不问** | `SUSPENDED` + `ticket_kind=model_deny`（高风险操作，需管理员显式放行） |
| PASS | 弃权 / 要求深审 | allow | `allow` |
| PASS | 弃权 / 要求深审 | deny | `SUSPENDED` + `ticket_kind=model_deny` |
| PASS | 弃权 / 要求深审 | 弃权 | `SUSPENDED` + `ticket_kind=all_abstain`（非常规操作） |

三条不变量：

1. **只有静态层能自动拒绝**。模型的 `deny` 不是硬拒，它只把调用变成一张「要人显式放行」的票据
   （`notify/messages.py` 的 `TICKET_KIND_LINES` 负责措辞）。静态 `deny` 压过任何模型放行。
2. **一票批准即放行**：任一模型给出 `allow`（`ReviewOutcome.ALLOW`，`SKIP` 不算），且没有模型 `deny`，
   调用直接放行。全部弃权才问人。
3. **弃权不是拒绝**：模型超时、异常、回答不可解析都折成「没有意见」（`reviewers/_common.judge_verdict`
   写 `DETAIL_SKIPPED=abstained`），既不放行也不拒绝，只让共识去问人。

编排：`main._decide` 分两轮跑同一个 registry。轮 1 = `_STATIC_ROUND`（policy/base_check/rules/jev_fast），
轮 2 = 仅 `llm_deep`，且只在「jev 不参与 / jev 弃权 / jev 要求深审」时开，jev 自己拒绝时不跑深审；
两轮 verdict 用 `core/pipeline.merge_outcomes` 合并后统一折叠。`core/pipeline.ReviewPipeline(only=...)`
提供子集选择，`only` 为空时按「空集＝无可放行者」处理（`DENY_RULE`），不会静默放行。

预算：`decision_budget_s`（默认 120s，上限 120）是三层共享的总预算，且入口会再留
`DECISION_RESERVE_S = 30s` 给审批/委派；`jev_timeout_s`（默认 10s，上限 50）给快审，
`deep_analysis_timeout_s`（默认 60s，上限 60）给深审，深审实际预算取 `min(配置, 总预算剩余 - 30s)`。
超预算或轮内异常不再硬拒，而是按「没有结论」问人（observe 下只记 `would_be`）。

0.6.1 / 0.6.2 / 0.6.4 / 0.6.6 增量（不改判决表，只补证据、去噪、投递可靠性、历史输入与序列强审）：

- **快审中间档不投票**：`jev/score.decide` 在 `allow_score <= score < block_score` 时返回 `None`，`judge_stage`
  的弃权分支仍带 `force_deep`。后果：中间档一定进深审，深审也弃权才落 `ticket_kind=all_abstain`。
- **判决可视化**：`JudgeStage.score/confidence/note` → `reviewers/_common.judge_verdict` 写
  `DETAIL_SCORE`/`DETAIL_CONFIDENCE`/`DETAIL_NOTE` → `Gateway._review_report` 汇总成
  `{reviewer: {outcome, decision, reason, ...}}` → `_Plan.review` → 审计 `summary_json.review` → Web 票据详情
  （`web/queries.serialize_call_context`）。**审计表列不变**，这些字段只在 JSON 里。
- **投递留痕**：`notify/sender.build_sender` 把每一次尝试写进 `send.attempts`（`delivery_attempts()` 取出），
  `main._send_notice` 成功后写 `notify_sent: <admin>=<result>`、失败写
  `notify_failed: <reason> | <admin>=<result>`；`_notify` 的异常也不再静默。理由是宿主 `Context.send_message`
  对不存在的 umo 同样返回真，布尔值不是送达证据。
- **0.6.4：历史真的进了模型输入**。三个断点一起修：`Gateway._build_recorder` 现在**自己建**
  `TrajectoryRecorder`（读 `trajectory_retention_per_user`，默认 50）——旧代码只在构造参数里收 recorder，
  生产路径从不注入，于是 `_append_trajectory` 每次都返回、R7/R9/R11 从不触发、模型一次历史都没见过；
  `Gateway._trajectory_view` 把 `recorder.snapshot()` 的裸 tuple 包成
  `triage.rules.TrajectoryView(entries, session_key, now=time.time())`（旧代码把 tuple 直接交给
  `evaluate_rules`，一旦出现窗口就是 `AttributeError: 'tuple' object has no attribute 'entries'`）；
  `triage.rules._entry_at` 认 ISO 文本（`_instant_of`：`Z` 换 `+00:00`、naive 补 UTC）——`CallSummary.at`
  存的是文本，旧实现只认数字，于是每条记录都被当成「没有时间」而恒在 30 秒窗口内。
  `triage.engine.trajectory_history` 取最近 `HISTORY_LIMIT = 8` 条渲染成 `tool verb -> targets (decision)`
  （旧→新，每条最多 `HISTORY_TARGETS = 2` 个目标），由 `judge_payload` 写进 state 的
  `trajectory_summary`，所以快审与深审看的是同一份历史，且它按 `prompts.state._shrink` 的顺序最先被砍。
- **0.6.6：R7 命中必强审**。`reviewers/jev_fast.FORCED_DEEP_RULES = frozenset({RULE_R7})` +
  `forces_deep_by_rule(rules)`：`_answer` 把它与 `stage.force_deep` 取并集写 `DETAIL_FORCE_DEEP`，
  快审判 allow 也照写，`main._needs_deep` 见标记就跑第二轮。规则动作仍是 `ACTION_OBSERVE`（静态拒绝项
  未变），所以这是「只标不拒 + 一定惊动深审」：深审 deny 才落 `ticket_kind=model_deny`，深审弃权时快审那张
  allow 票依然有效（一票放行）。0.6.5 之前 R7 连标签都出不来（记录不带 targets），0.6.6 之前它出了标签也
  没人再看一眼。
  提示词同步要求两层先读这段序列（`prompts/systemone.RISK_INSTRUCTIONS`、
  `prompts/deep_call.SYSTEM_PROMPT`、`prompts/single_call.SYSTEM_PROMPT`）。
- **迟到决定去重**：`ui/commands._late_disclosure_due` 按 `(ticket, verb)` 只留一次痕（`OrderedDict`，128 键上界）。
- **低置信度也弃权**（0.6.2）：`jev/score.decide` 在 `below_confidence_floor` 为真时直接返回 `None`，
  放行档与拒绝档都失效；`triage/engine.judge_stage` 的弃权分支保留 `degraded=fast_low_confidence` 当证据。
  旧行为是低置信度返回 `SUSPENDED`，于是无害调用直接开票、深审也救不回来（`consensus` 先落 `model_suspend`）。
- **管理员私信按宿主平台逐个尝试**（0.6.2）：`notify/sender.py` 新增
  `EPHEMERAL_PLATFORMS = frozenset({"webchat"})`、`is_ephemeral_platform`、`host_platforms`（读宿主
  `platform_manager.platform_insts` 的 `meta().id`，全 getattr 探测）、`delivery_platforms`、`admin_sessions`。
  裸管理员 id 不再盲用触发调用的平台（从面板/webchat 测出来的调用会把私信发到不存在的
  `webchat:FriendMessage:<id>`，宿主仍返回成功），而是先试聊天平台、再逐个试宿主平台；只落在面板平台上的
  成功记 `ATTEMPT_EPHEMERAL`、不算送达。
- **`_record_notify_sent` 参数遮蔽**（0.6.2）：参数名从 `audit` 改成 `notice`——它遮蔽了模块级
  `store.audit`，函数体里的 `audit.SOURCE_NATIVE` 每次都抛 `AttributeError`，于是**每次成功投递都被写成
  `notify_failed: notify_error:AttributeError`** 并返回 `False`。
- **票据详情不再为 `null`**（0.6.2）：`web/queries.pick_ticket_event` 改为优先返回「`decision=suspended`
  且带 `summary_json`」的行（`notify_failed` 侧行同样是 `suspended` 却没有 summary，旧逻辑选中它，
  `serialize_call_context` 拿到空摘要就返回 `None`）。
- **通知里的动作/层级说中文**（0.6.2）：`notify/messages.py` 的 `VERB_LABELS` / `TIER_LABELS` 把
  `verb` / `tier` 渲染成「查询 / 执行 / 未定级」，`main._deliver_notice` 传入 `verb_of` / `tier_of`。

observe 模式：`consensus` 是纯函数，不看 mode；`main._observed_plan` 在返回前把任何非放行结论
改写成 `ALLOW_PASSTHROUGH` + `would_be`（`Gateway._plan_from_pipeline` / `_ask_human_plan` 都经过它），
所以观察模式下**模型永远拿不到阻塞票**，也从不建票据。

## 1b. 代理 ↔ 网关契约（已落地，改动须同步 `interface/wrapper.py`）

`ManagedToolProxy.call` 只做两件事：先问网关，再委派。网关必须提供
`async def guard_call(*, inner, tool_name, args) -> outcome`；`outcome` 可以是对象或映射，字段为
`decision`（前缀匹配：`allow*` 放行 / `deny*` 拦截 / `suspend*` 挂起）、`text`、`ticket_id`、
`state`、`result`（已构造好的返回结果，优先级最高）。

- 判定必须先于委派；网关抛异常、缺 `decision` 字段、决策不可识别，一律按拦截处理。
- 放行时委派目标是工具集里的**原始项**（可能是宿主 `_PermissionGuardedTool` 包装层），原生权限检查因此仍会执行；分类与参数过滤用 `compat.unwrap` 后的内层元数据。
- 代理构造时 `handler=None`，runner 不再按 schema 过滤参数；代理在委派前用内层 schema 自行过滤，网关看到的是原始参数。
- 非放行分支必须返回非空结果（`CallToolResult(isError=True)` 或非空字符串）；放行分支逐字返回内层结果（含 `None`），不改写。
- 请求钩子适配器 `interface/hooks.on_llm_request(event, request, gateway) -> HookOutcome` **必须是协程函数**：宿主在 `astrbot/core/pipeline/context_utils.py:115` 断言 `inspect.iscoroutinefunction(handler.handler)`，失败只记日志不中断，同步 handler 等于钩子从未执行（静默 fail-open）。函数体只做 return，机制层 `_dispatch` 及全部辅助函数保持同步、文件内不得出现 `await`。只做机制：canary 校验公开 `ToolSet` 形状与 `compat.GATE_FINGERPRINT`、按 `identity.is_cron_event` 跳过 cron、身份缺失或 canary/install 失败即 `install.strip_untrusted_candidates(request, exempt=install.exempt_tool_names(gateway))`（`hooks._strip`，`tooling_guard/interface/hooks.py:228`）——**只保留豁免项**，其余一律剥离，不可读与无名条目一并移除（fail-closed）；四个降级分支（canary_failed / identity_missing / install_failed / hook_error）与 `install_proxies` 的两个 except 全部走这条路径；`_strip` 自己失败（返回 `+strip_failed`，再失败 `+strip_failed+empty_failed`）时改调 `install.clear_toolset(request)`（`tooling_guard/interface/install.py:282`）兜底：三级梯子 `tools[:] = []` → `func_tool.tools = []` → 逐个 `remove_tool`，每级都用 `remaining()` 核对条目数为 0，三级都没证明为空才记 `logger.error("兜底清空后仍无法证明工具集为空")` 并返回 `False`。失败后缀由 `hooks._degraded_kind`（`hooks.py:282`）折成 `canary_failed+strip_failed` 这类**复合 kind**，复合 kind 因此各有自己的审计行与自己的 600 秒限频窗口（`DEGRADED_WINDOW_S`）。`HookOutcome` 字段：`installed`/`subject_key`/`session_key`/`degraded`/`skipped`；降级原因由网关负责审计告警，适配器不得吞掉降级事实，也不得调用 `gateway.*` 任何方法。
- 幂等键是 `(request, func_tool)` 双弱引用对，不是 `id(request)`：同一 request 换绑新 `ToolSet` 必须重新安装（新工具集里一个代理都没有），同一对只装一次；记录写安装之后真实的 `request.func_tool`，避免宿主中途重建工具集留下陈旧对。
- 单条判定契约：`triage/decisions.py` 独占词形（`Decision` 12 值、`WouldBe` 5 值、`coerce_decision` 非枚举/未知→`deny_rule`、`decision_from_policy(outcome, *, mode)`）；`triage/classify.py` 独占分类（`classify_call(tool_name, arguments, *, schema=None, origin="model") -> CallFeatures`，未知动作一律 `T-strong`）；`triage/rules.py` 独占 R1–R11（纯函数、不读 config、不做 I/O，R12 只在 `trace/escalation`）；`triage/engine.py` 的 `TriageEngine.decide(...)` 只做编排与 fail-closed（异常→`deny_policy` + `degraded=triage_error:<类型>`），不等待、不 sleep、不落库。policy deny 不得被规则命中降低；observe 下 `decision` 恒为 allow 变体、`would_be` 承载潜在拒绝/挂起。
- `args_digest` 全仓库只有一个实现：`tooling_guard/digest.args_digest(schema, arguments)`（SHA-256 前 16 字节 = 32 位小写 hex，schema 缺失时保留全部传入键）；`trace/intent.py` 的 `args_digest`/`canonical_arguments` 已改为委托它，票据、意图记录、轨迹条目必须共用，禁止各自实现。

- 委托预算与参数钳制（`interface/wrapper.py`）：`BUDGET_MARGIN_S = 5.0`（`:25`）；`_remaining_seconds(gateway, context)`（`:169`）用鸭子类型调 `gateway.remaining_seconds`，缺失 / 非数值 / NaN / 抛异常一律视为「剩余未知」；`_clamp_yield_time(arguments, remaining)`（`:200`）仅在参数含 `yield_time_ms` 且为 int 时按 `max(0, int(min(原值, (remaining - BUDGET_MARGIN_S) * 1000)))`（`:222`）钳制；剩余未知时**不改参数**，并打一条 `logger.info("yield_time_ms=%s left unclamped: this call reports no remaining budget")`（`:227-232`）——旧行为是静默跳过、看起来像钳过了。剩余预算取自 `Gateway.remaining_seconds(context)`（公开方法，`tooling_guard/main.py:1322`），由 `_remaining_seconds` 按鸭子类型调用，所以网关换实现也不会把钳制变成死路径。
- 安装顺序：根 `main.py` 用 `@filter.on_llm_request(priority=-1_000_000_000)` 注册。宿主按 `priority` **降序**执行（`astrbot/core/star/star_handler.py` 的排序 key 是 `-priority`，缺省 0），而 `ToolSet.add_tool` 对同名 active 工具**就地覆盖**——后注册的原工具会夺回名字，所以守卫必须**最后一个**装；同 priority 之间按注册顺序，因此该值必须是所有插件里最小的。写文档或改装饰器时不要回到「数字越大越先跑」的口径。
- 委托结果转发（`async def _forward(value, event)`，`tooling_guard/interface/wrapper.py:268`）与宿主 `astrbot/core/astr_agent_tool_exec.py:860-878` 逐项语义一致：生成器逐项处理，`MessageEventResult`/`CommandResult` 逐项 `event.send(MessageChain(type="tool_direct_result"))`（发不出去就作为返回值保留，不丢），其余项取最后一个作为工具结果。
- 委托期异常**透传**：只有 `PermissionError` 仍转成 `isError` 拦截结果（`:462`）；`ValueError`、`asyncio.CancelledError` 等一律原样上抛，不得改写成「工具执行失败」的拦截结果——那会把上游错误伪装成网关拦截，污染审计与重试语义。
- 调用预算与通知预算共用**一次调用**的作用域：`CallScope` 由判定入口开合，`Gateway.remaining_seconds(context)`
  只读该作用域，**作用域缺失时返回 `None`**，不得用当前时钟重算——重算会让「剩余预算」在一次调用内自我
  延长，正是 R9-01 修掉的那条路径。消费者只有两个：`wrapper._clamp_yield_time`（拿不到预算就不钳制、
  只记 `logger.info`）与 `Gateway._send_notice`（唯一投递边界）。R10 把投递上限**下沉到这一个出口**：
  `_delivery_cap` 算出 `min(NOTIFY_TIMEOUT_S, 本调用剩余预算)`，**拿不到预算时仍有 `NOTIFY_TIMEOUT_S` 上限**
  （预算未知不等于零预算），`_notify_timeout` 只剩薄包装；超时只记投递失败 `notify_timeout`，投递失败
  既不改判也不提前放行。hook degraded / reviewer state / gateway disabled / closing notice 四条告警路径与
  挂起通知全部命中同一个 `await self._send_notice(`，新加告警不得自建超时夹取。
- **审查器适配器 MUST NOT 吞 `asyncio.CancelledError`**：内层 `finally` 只归还忙计数、不写统计
  （`reviewers/_common.py` 的 `leave` 与 `record` 是两件事）；吞掉会让 `reviewer_busy:<name>` 残留，
  后续调用被误判为忙。`ReviewPipeline.run` 在早停 / 超时 / 外层取消三条路径上都 `await` 被取消的任务
  （`_await_cancelled`，上限 `PREEMPT_GRACE_S`），所以超时 deny 触发的早停会连带取消仍在飞的**其余**
  适配器，不只是 jev。

## 1c. 行号锚点（源码移动后必须同步刷新本表与 `AGENTS.md`）

下表已于本轮（第六批改动后）逐行重新实测；**本节数字与后面任何旧段落冲突时，一律以本节为准**。

| 符号 | 当前位置 |
|---|---|
| `Gateway.from_config` | `tooling_guard/main.py:1414` |
| `Gateway.set_mode` | `tooling_guard/main.py:1529` |
| `Gateway.on_llm_request` | `tooling_guard/main.py:1640` |
| `Gateway.guard_call` | `tooling_guard/main.py:2218` |
| `Gateway.handle_call` | `tooling_guard/main.py:2256` |
| `Gateway.shutdown` | `tooling_guard/main.py:2284` |
| `_surface_kind`（分类顺序 `managed` / `passthrough` / `stripped`） | `tooling_guard/interface/install.py:27`（判定顺序 `:58-83`） |
| `strip_managed_candidates`（无调用方，保留待清理） | `tooling_guard/interface/install.py:119` |
| `install_proxies` | `tooling_guard/interface/install.py:357`（三路分流循环 `:386-402`） |
| `remove_proxies` | `tooling_guard/interface/install.py:446` |
| `hooks._strip` | `tooling_guard/interface/hooks.py:228` |
| `hooks._degraded_kind` | `tooling_guard/interface/hooks.py:282` |
| `hooks._dispatch` | `tooling_guard/interface/hooks.py:379` |
| `hooks.on_llm_request`（协程） | `tooling_guard/interface/hooks.py:449` |
| `audit.record_event` | `tooling_guard/store/audit.py:264` |
| `audit.AuditWriter` | `tooling_guard/store/audit.py:347` |
| `audit.record_side_observation` | `tooling_guard/store/audit.py:462` |
| `audit.scan_for_secrets` | `tooling_guard/store/audit.py:712` |
| `audit.record_trajectory_snippet` | `tooling_guard/store/audit.py:817` |
| `audit.apply_retention` | `tooling_guard/store/audit.py:973` |
| `tickets.find_approved` | `tooling_guard/store/tickets.py:602` |
| `tickets.consume_approved` | `tooling_guard/store/tickets.py:664` |
| `jev/client.MAX_TIMEOUT_S = 50.0` | `tooling_guard/jev/client.py:40` |
| 协程断言 `inspect.iscoroutinefunction` | `astrbot/core/pipeline/context_utils.py:115`（失败分支 `:114-121`） |

**迁移后符号 → 目标模块**（tasks 11.1–11.5 落地后生效。上表是 2026 首轮实测锚点，行号数字一位不改；本表只说明符号搬家去向，不重排上表）：

| 现行符号 | 迁移后所在模块 |
|---|---|
| `Gateway._guard` 内的硬编码判定顺序 | `core/pipeline.py` 的 `ReviewPipeline.run`（启用集与展示顺序来自 `core/registry.py`） |
| `Gateway.guard_call` / `handle_call` 的编排体 | 契约仍在 `tooling_guard/main.py`，编排委托 `core/pipeline.py` |
| `triage/engine.py` 的规则与快审编排 | 拆成 `reviewers/rules.py` 与 `reviewers/jev_fast.py` 两个审查器适配器 |
| `policy/allowlists.py` 的名单判定 | `reviewers/policy.py`（`order=-10`、拒绝注销与停用）与 `reviewers/base_check.py`（`order=0`、可停用）各自调用；白名单只降延迟/深度，黑名单优先 |
| `main.py` 的同步深审 / 后台分流 | `reviewers/llm_deep.py`，预算记账移到 `core/budget.py` |
| `ui/contracts.py` 的状态视图 | `core/guard.py` 的只读视图（`ui/` 与 `web/` 共用） |

**本轮新增符号的实测行号**（与上表并存，均为本轮实测；`_strip` / `_degraded_kind` / `clear_toolset` 也已并入上表）：`install._exempt_set` `tooling_guard/interface/install.py:153`、`install.exempt_tool_names` `:181`、`install._drop_entries` `:205`、`install.strip_untrusted_candidates` `:228`、`install.clear_toolset` `:282`、`wrapper.BUDGET_MARGIN_S = 5.0` `tooling_guard/interface/wrapper.py:25`、`wrapper._open_call_scope` `:169`、`wrapper._close_call_scope` `:193`、`wrapper._remaining_seconds` `:209`、`wrapper._clamp_yield_time` `:240`、`wrapper._forward`（协程）`:321`、`Gateway.remaining_seconds`（公开方法）`tooling_guard/main.py:1458`、模块级 `remaining_seconds(deadline, now)` `:1011`。上一段写的 `_remaining_seconds :169`、`_clamp_yield_time :200`、`_forward :268`、`Gateway.remaining_seconds :1322`、`exempt_tool_names :164`、`strip_untrusted_candidates :211`、`_exempt_set :136`、`_drop_entries :188`、`clear_toolset :265` 全部按本段读。

挂起策略相关符号的实测行号（同上，独立补充、不改既有数字）：`suspension_cap_seconds` `tooling_guard/main.py:1146`、
`effective_suspend_deadline` `:1173`、`suspension_wait_seconds` `:1131`、`can_suspend` `:1194`、
`Gateway._suspend_cap` `:3394`、`Gateway._suspend_suppression` `:3409`、`Gateway._suppress_suspend` `:3441`、
`Gateway._alert_suspend_suppressed` `:3477`、`MAX_SUSPEND_WAIT_S = 110.0` `tooling_guard/approval/waiter.py:40`、
`MIN_SUSPEND_REMAINING_S = 30.0` `waiter.py:43`、`wait_for_decision` `waiter.py:240`、
`_persist_canceled` `waiter.py:212`、`GROUP_MESSAGE` `tooling_guard/notify/sender.py:36`、
`session_key` `tooling_guard/interface/identity.py:44`、
`「剩余 N 秒」` 字段 `tooling_guard/notify/messages.py:203`。

审查器流水线与 Web 面相关符号的实测行号（同上，独立补充、不改既有数字）。`tooling_guard/main.py`
的行号在写作期间仍在被改动，故本节对**该文件只给符号名**，其余文件给实测行号：`tickets.transition`
`tooling_guard/store/tickets.py:487`、`tickets.consume_approved` `tooling_guard/store/tickets.py:664`（本表上方
`:631` 已漂移）、`audit.SOURCE_WEB` `tooling_guard/store/audit.py:43`、
`policy.config.boolean` `tooling_guard/policy/config.py:272`（非布尔即记 `not_bool` 并返回 `False`）、
`ui.commands.decide_ticket` `tooling_guard/ui/commands.py:539`（命令面与 Web 面共用）、
`ui.commands.read_reviewer_statuses` `tooling_guard/ui/commands.py:247`、`ui.commands._reviewer_lines`
`tooling_guard/ui/commands.py:282`、`web.api.register_web_apis` `tooling_guard/web/api.py:457`（路由基址
`f"/{plugin_name}/guard/api"` `tooling_guard/web/api.py:396`）、`web.queries.LIMIT_DEFAULT = 50`
`tooling_guard/web/queries.py:26`、`LIMIT_MAX = 200` `tooling_guard/web/queries.py:27`、
`WINDOW_DEFAULT_S = 86_400` `tooling_guard/web/queries.py:30`、`WINDOW_MAX_S = 7 * 86_400`
`tooling_guard/web/queries.py:31`、`EVENT_FIELDS` `tooling_guard/web/queries.py:39`、`TICKET_FIELDS`
`tooling_guard/web/queries.py:63`、`Scope.reads_nothing` `tooling_guard/web/queries.py:116`、
`resolve_scope` `tooling_guard/web/queries.py:149`、`serialize_reviewer` `tooling_guard/web/queries.py:417`。
只给符号名的 `main.py` 侧入口：`Gateway.reviewer_statuses`、`Gateway._base_check_enabled`、
`Gateway._note_reviewer_state`、`Gateway._record_reviewer_state`、`Gateway._schedule_reviewer_alert`、
`DEGRADED_BASE_CHECK_DISABLED`、`DEGRADED_BASE_CHECK_RESTORED`。
宿主侧取插件名的位置是 `astrbot/dashboard/api/plugins.py:250`（`plugin_path` 首段），这就是路由必须带前缀的原因。

上表 `strip_managed_candidates`（`install.py:119`）已**无调用方**（`grep` 全仓零调用）：降级剥离一律走 `strip_untrusted_candidates`（`:228`）+ `exempt_tool_names`（`:181`），该函数**保留但未使用、待清理**。四个 `install.py` 入口本轮实测为 `_surface_kind` `:27`、`strip_managed_candidates` `:119`、`install_proxies` `:357`、`remove_proxies` `:446`（`install.py` 共 466 行）；历史段落里的 `:23` / `:98` / `:132` / `:198` 与「现为 `:27` / `:102` / `:265` / `:335`」都按本段读。定位一律以符号名为准，改代码时按本节口径刷新。

R9 复核修复相关符号的实测行号（同上，独立补充、不改既有数字）：
`anonymize.validate_secret_pattern` `tooling_guard/anonymize.py:569`、`MAX_SECRET_PATTERN_LENGTH = 512` `:80`、
`MAX_SECRET_PATTERN_REPEAT = 64` `:89`、`MAX_SECRET_PATTERN_AMBIGUITY = 64` `:97`、七个稳定 code 常量
`:107` / `:110` / `:113` / `:116` / `:119` / `:122` / `:125`、`Anonymizer` `:1153`；
`policy.config._ABSOLUTE_ENTRY_RE` `tooling_guard/policy/config.py:59`（`path_not_absolute` 判定循环 `:303-319`，
issue code `:41`）；`policy.snapshot` 的致命与 advisory 分支 `tooling_guard/policy/snapshot.py:265-266`、
`:268-272`、`:284`；`TaintStore.refused_secret_patterns` `tooling_guard/trace/taint.py:365`；
`triage.classify._glob_alternatives` `tooling_guard/triage/classify.py:572`、`_glob_regex` `:584`、
`_glob_credential` `:639`、`_GLOB_TOTAL_WILDCARD_WITNESS = ".env"` `:230`；
`tickets.expire_stale` `tooling_guard/store/tickets.py:751`、`tickets.invalidate_on_startup` `:836`、
`tickets.startup_sweep` `:892`（调用顺序 `:937-938`）、`store.db.run_startup_sweep` `tooling_guard/store/db.py:677`
（`open_db` `:736`、调用点 `:775`、`BUSY_TIMEOUT_MS = 150` `:58`）；
`reviewers._common.ReviewerSlot` `tooling_guard/reviewers/_common.py:377`、`ReviewerState.begin` `:418`、
`leave` `:428`（按 slot 幂等 `:444-450`）、`record` `:452`、`BuiltinReviewer.review` `:531`；
`core.pipeline._await_cancelled` `tooling_guard/core/pipeline.py:400`、`PREEMPT_GRACE_S = 0.05` `:94`、
`TIMEOUT_MARKER` `:83`、`BUSY_MARKER` `:85`；`notify.admin.NOTIFY_TIMEOUT_S = 5.0`
`tooling_guard/notify/admin.py:12`。`tooling_guard/main.py` 侧同上只给符号名：`CallScope`、
`begin_call_scope`、`end_call_scope`、`Gateway.remaining_seconds`、`NOTIFY_TIMEOUT_REASON`、
`Gateway._notify_timeout`。

R10 复核修复相关符号的实测行号（同上；本节与上一段冲突时以本段实测为准）：
`store.db._CommitOwner` `tooling_guard/store/db.py:372`（每连接一把可重入 `threading.RLock`）、
`write_lock` `:440`、`blocked_writers` `:456`、`write_transaction` `:474`、`serialized_write` `:504`、
`StartupSweepState` `:353`、`startup_sweep_state` `:527`、`require_startup_sweep` `:561`、
`run_startup_sweep` `:677`、`open_db` `:736`、`BUSY_TIMEOUT_MS = 150` `:58`；
`tickets.find_approved` `tooling_guard/store/tickets.py:602`、`tickets.consume_approved` `:664`；
`policy.allowlists.MAX_SECRET_SCAN` `tooling_guard/policy/allowlists.py:27`（= `MAX_REDACT_SCAN`）、
`SECRET_SCAN_TRUNCATED` `:38`、`SecretScan` `:379`、`scan_secret_patterns` `:410`、
`secret_pattern_hit` `:448`；`triage.engine` 的 payload 键 `deadline_monotonic` `tooling_guard/triage/engine.py:404`；
`anonymize.PATTERN_UNBOUNDED_WILDCARD` `tooling_guard/anonymize.py:125`、`PATTERN_UNCOMPILABLE` `:128`、
`_atom` `:279`、`_barrier` `:525`、`_finalize` `:568`；`observation._probe_worker_read`
`tooling_guard/observation.py:426`。`tooling_guard/main.py` 侧只给符号名：`Gateway._delivery_cap`
（`:3271`）、`Gateway._notify_timeout`（`:3299`）、`Gateway._announced_remaining`（`:3315`）、
`FragmentFilter.truncated_marker`（`:524`，赋值 `:1194` / `:1202`）、`Gateway._send_notice`（`:3533`）——全 5 个投递调用点是
`:1807` / `:1956` / `:3492` / `:3804` / `:3942`。

R11 复核修复相关符号的实测行号（同上；本节与前面两段冲突时以本段为准，上一段里的 `_CommitOwner :372`、
`write_lock :440`、`blocked_writers :456`、`write_transaction :474`、`serialized_write :504`、
`StartupSweepState :353`、`startup_sweep_state :527`、`require_startup_sweep :561`、`run_startup_sweep :677`、
`open_db :736`、`SecretScan :379`、`scan_secret_patterns :410`、`secret_pattern_hit :448`、`_atom :279`、
`_barrier :525`、`_finalize :568`、`_announced_remaining :3315` 均已漂移，按本段读）：
`store.db.PROCESS_STARTED_AT` `tooling_guard/store/db.py:218`、`_CommitOwner` `:382`、`write_lock` `:450`、
`blocked_writers` `:466`、`write_transaction` `:484`、`serialized_write` `:514`、`startup_sweep_state` `:537`、
`require_startup_sweep` `:571`、`_abandon_connection` `:698`、`run_startup_sweep` `:719`、
`recover_startup_sweep` `:800`、`open_db` `:832`、`BUSY_TIMEOUT_MS = 150` `:58`；
`policy.allowlists.SECRET_SCAN_INCOMPLETE` `tooling_guard/policy/allowlists.py:41`、`SecretScan` `:389`、
`incomplete` `:419-422`、`incomplete_marker` `:424-429`、`scan_secret_patterns` `:432`、`secret_pattern_hit` `:470`；
`policy.layers` 的 fail-closed 分支 `tooling_guard/policy/layers.py:235-253`（可批准的敏感配置挂起在其后
`:260-270`）；`anonymize._atom` `tooling_guard/anonymize.py:277`、`_finalize` `:541`（抛点 `:585-596`）、
`validate_secret_pattern` `:599`、八个稳定 code 常量 `:107` / `:110` / `:113` / `:116` / `:119` / `:122` / `:125` /
`:128`、`Anonymizer` `:1282`——**`_barrier` 已不存在**；`ui.commands.startup_sweep_view` `tooling_guard/ui/commands.py:377`
（docstring `:383` 声明状态查询只读）、`_startup_sweep_line` `:408`、`RECOVERY_WINDOW_S` `:114`、
`_sweep_recovery` `:1353`；`web.api` 的 `startup_sweep` 字段 `tooling_guard/web/api.py:367-375`；
`tooling_guard/main.py` 侧只给符号名：`STARTUP_SWEEP_ALERT_TOOL`（`:201`）、`DEGRADED_STARTUP_SWEEP`（`:203`）、
`Gateway.schedule_startup_sweep_alert`（`:2007`，R12-03 前是私有名 `_schedule_startup_sweep_alert`，内部调用点 `:2116`；`ui/commands.py:1346` 的 `getattr` 探测的就是这个公开名）、`Gateway._alert_startup_sweep_failed`（`:2030`）、
`Gateway._announced_remaining`（`:3458`，渲染点 `:3628`）。投递面同样漂移：`Gateway._delivery_cap`（`:3414`）、
`Gateway._notify_timeout`（`:3442`）、`Gateway._send_notice`（`:3676`），六个投递调用点是 `:1844` / `:1993` /
`:2074` / `:3635` / `:3947` / `:4085`（第 6 个是启动清理告警）——上一段写的 `:3271` / `:3299` / `:3533`
与「全 5 个投递调用点」都按本段读。出厂默认在 `_conf_schema.json:28`（`secret_patterns`；旧文写的 `:24` / `:27` 都是漂移值。本轮 `_conf_schema.json` 共 41 行 / 39 键）；被重建的测试
文件在 `tests/unit/gateway/test_gateway.py`（1210 行 / 179 checks）。

R12 复核修复相关符号的实测行号（同上；本节与前面各段冲突时以本段为准）：`anonymize._finalize`
`tooling_guard/anonymize.py:542`（两个拒绝抛点在 `:593` 与 `:598`）、`validate_secret_pattern` `:601`、
`_atom` `:278`、`Anonymizer` `:1285`；本轮的判据变化只有一处——`_branch` 里零宽原子也清终端标志
（`:268-276` 的 `if kind == "zero": self._tail_open = False`），所以「无界重复之后跟一个可失败的
零宽断言」（`a+$` / `[a-z]+$` / `a+\b` / `(?i)x+$` / `^sk-[A-Za-z0-9]{16,}$`）现在被拒，稳定 code
仍是原来那八个、`_conf_schema.json:28` 的两条出厂默认不受影响（旧文 `:24` / `:27` 按本段读）。`tooling_guard/main.py` 侧只给符号名：
`Gateway._audited_summary_line`（`:4369`，截断尾标记追加在 `:4407-4409`）。上一段写的 `_finalize :541`、
`validate_secret_pattern :599`、`_atom :277`、`Anonymizer :1282` 都按本段读。
**第六批改动（信任域 / 审查器开关 / 配置降级观察 / 配置页中文化）的实测行号**——本节与前面各段冲突时以本段为准，定位同样以符号名为准：

- 三路分流与披露：`install_proxies` `tooling_guard/interface/install.py:384`、循环 `:418-430`、分支 `:425-426`（managed）/ `:427-428`（stripped）/ `:429-430`（passthrough）、剥离 WARN `:459-465`、**唯一**披露 WARN `:466-471`、`_surface_kind` `:27`、判定顺序 `:59-84`、`FUTURE_TASK_NAME` `:21`、`HANDOFF_NAME_PREFIX` `tooling_guard/compat.py:58`；`install.py` 共 495 行。
- 信任域：开关 `_conf_schema.json:40`（`trust_project_roots`，默认 `false`）；`trusted_in_project_roots` `tooling_guard/policy/allowlists.py:520`。**0.6.0 起只是标签**：策略层的 `LAYER_TRUSTED_ROOT` 放行分支已删除，`reviewers/_common.skips_model_review` 的域内例外也删了（`SKIP_TRUSTED_ROOT` 改名 `SKIP_WHITELISTED`，现在只有白名单会跳过模型），所以域内目标只产生 `AllowHints`（`in_project_root` 等），**既不放行也不跳过模型审查**；目标只取分类器认识的 `PATH_KEYS`（`_resolved_targets` `:815`）；状态词 `tooling_guard/ui/commands.py:143-144`、`_trust_line` `:1844`（调用点 `:481`）。代价：打开它不再减少模型调用次数，也不再放过任何调用。
- 两个模型审查器开关：`jev_enabled` 默认 `False` `tooling_guard/policy/config.py:155`、`llm_enabled` 默认 `True` `:159`、解析 `:442-443`、双关 advisory `deep_reviewers_disabled` `:478-486`（code 登记 `ISSUE_CODES` `:34`）；`_PROTECTED_NAMES` `tooling_guard/core/registry.py:54`、`_ALWAYS_ON_NAMES` `:58`；装配门 `Gateway._jev_enabled` `tooling_guard/main.py:1903` / `_llm_enabled` `:1915`，客户端建造点 `_build_jev_client` `:4949`（开关 `:4956`）与 `_build_deep_client` `:4984`（开关 `:4997`）；深审折叠 `_apply_deep_result` `:866-870`（折成 `deny_judge`）、`reason` 覆写 `:877-884`、`REASON_JUDGE_UNAVAILABLE` `:252`、`DEGRADED_JUDGE_UNAVAILABLE` `:243`；状态词 `ui/commands.py:146-149`、行生成 `:1863` / `:1882`。
- 配置校验失败降级为观察：`REASON_GATEWAY_OBSERVED` `tooling_guard/main.py:253-255`、`DEGRADED_GATEWAY_DISABLED` `:258`；判定入口 `:2903-2904`、`_observe_disabled` `:3949`、审计行文本 `:3984-3989`、返回 `:4024-4026`、`_alert_disabled` `:4028`（正文 `:4062-4066`、投递 `:4073-4088`，与其它降级共用 `DEGRADED_WINDOW_S` `tooling_guard/notify/ratelimit.py:22`）；`/guard status` 文案 `tooling_guard/ui/commands.py:486-491`。
- 宿主默认模型：`llm_mode = text(llm_mode) or astrbot_provider` `tooling_guard/policy/config.py:454`、注释 `:473-477`；`_generate` `tooling_guard/provider/llm.py:157-169`、`_default_provider_id` `:171` 起（失败抛 `TypeError` / `RuntimeError`）；适配器通用 fail-closed `tooling_guard/reviewers/_common.py:624-640`，降级前缀 `triage_error:` `:102`。
- 配置页：`_conf_schema.json` 全部中文 `name` / `description` / `hint`，hint 以「键 <key>。」开头；`mode` `:2`、`llm_mode` `:24`、`fast_judge_backend` `:18` 为 `options` + `labels` 单选；`jev_api_key` `:22`、`llm_api_key` `:27` 带 `secret: true`；`suspend_timeout_s` `:3`（slider 1–110 step 1）、`deep_analysis_timeout_s` `:32`（slider 1–60 step 5）、`decision_budget_s` `:34`（slider 1–120 step 5）、`fast_allow_score` `:19` / `fast_block_score` `:20`（slider 0–100 step 1）、`fast_min_confidence` `:21`（slider 0–1 step 0.05），区间与 `INT_BOUNDS` `tooling_guard/policy/config.py:84` 及 `FLOAT_BOUNDS` 一致；键与行号的本轮实测清单见下面「第九批」段。

**第八批改动（未配置即观察 / 未识别工具的两种处置）的实测行号**——同上，本节与前面各段冲突时以本段为准：

- 空 `project_roots` 只报 advisory：`tooling_guard/policy/config.py:394-404`（`advisory(...)`，code 仍是 `root_missing`）；非空条目仍在 `:405-418` 的循环里 `issue(...)` 致命，判据 `resolve(strict=True)` + `is_dir()`（`:408-410`）。
- 不可纳管工具开关：`_conf_schema.json:14`（`strip_unmanaged_tools`，默认 `false`）；`tooling_guard/policy/config.py:165` 字段、`:559-569` 解析并在 True 时出 advisory（code `strip_unmanaged_tools_enabled`，登记 `ISSUE_CODES` `:64`；非致命）、`:635` 透传给 `GatewayConfig`；`Gateway.strip_unmanaged_tools` `tooling_guard/main.py:1509-1521`；`tooling_guard/interface/install.py:206 strip_unmanaged`（读属性 `:225`、读不出记 error `:227`）、分支 `:427-430`、剥离 WARN `:459-465`、披露 WARN `:466-471`。**五类同归一开关**：`mcp` / `handoff` / `background` / `future_task` / `unknown` 默认全部原样放行，开关打开才一起剥离；`unknown` 不再是唯一能放行的一类，另外四类也不再是永远剥离。
- 配置页：`_conf_schema.json` 现 **44 行 / 42 键**（本批新增 `fast_judge_backend` `:18`、`fast_allow_score` `:19`、`fast_block_score` `:20`、`fast_min_confidence` `:21`，删掉已废弃的 `jev_api_mode`）；`mode` `:2`、`suspend_timeout_s` `:3`、`suspend_disabled_sessions` `:4`、`base_check_enabled` `:10`、`project_roots` `:11`、`exempt_tools` `:13`、`strip_unmanaged_tools` `:14`、`jev_enabled` `:15`、`jev_base_url` `:16`、`jev_model` `:17`、`jev_api_key` `:22`、`llm_enabled` `:23`、`llm_mode` `:24`、`secret_patterns` `:31`、`deep_analysis_timeout_s` `:32`、`web_admin_usernames` `:41`、`web_subject_map` `:42`、`trust_project_roots` `:43`。

**第九批改动（快审判定：单请求给出 score + noul + confidence）的实测行号**——同上，本节与前面各段冲突时以本段为准：

- 判定纯函数：`tooling_guard/jev/score.py`。`DEFAULT_FAST_ALLOW_SCORE=30` / `DEFAULT_FAST_BLOCK_SCORE=75` / `DEFAULT_FAST_MIN_CONFIDENCE=0.6`、`BACKEND_JEV`/`BACKEND_LLM`、`normalize_score`（`round(raw/(n-1)*100)` 夹 0..100）、`normalize_confidence`（拒绝 bool、越界不夹取）、`FastThresholds.from_config`（三个键的唯一读取点）、`decide`（阈值倒置 → `None` 先于 confidence 门；0.6.1 起中间档一律 `None`、0.6.2 起低于 confidence 下限也 `None`）、`forces_deep`（只认 `noul is True`，任一分档都算）、`annotate_confidence`（`confidence_missing` / `confidence_below_floor`）、`decide`（0.6.1 起中间档一律 `None`＝弃权，丢弃默认阈值 `DEFAULT_FAST_BLOCK_SCORE=75` 的旧三分支）、`forces_deep`（只认 `noul is True`，任一分档都算）。
- 结构化状态：`tooling_guard/prompts/state.py` 的 `build_state` / `state_json` 是**唯一构造点**（`MAX_STATE_CHARS=6000`、`MAX_FIELD_CHARS=1200`、`MAX_ITEMS=12`，经 `Anonymizer` + `PathRedactor` 脱敏，超长按 trajectory→text→targets 瘦身）。
- 请求体：`tooling_guard/prompts/systemone.py:82-100` 的 `build_systemone_body` 返回 `{"model","state","questions"}`，`questions` 里 `risk`（type=score，恰 5 档 criteria，`:40`）与 `deep`（type=noul）**同一次请求**发出；`tooling_guard/prompts/single_call.py:26` 是 llm 后端的等价提示词（只许回 `{"score","noul","confidence"}`）。**模型可见的提示词一律英文**（criteria、instructions、state 引导句、system 提示）：中文 criteria 会让小模型把档位读歪，实测 0.8B 端点对英文档位给出的分数与档位文字自洽。
- 客户端：`tooling_guard/jev/client.py` 的 `JevClient(config, *, transport=None, client=None)`、`.backend` / `.endpoint` / `.model`、`body(state)` / `parse(payload)` / `ask(state)`（**不重试**，错误只暴露异常类名）；`jev_base_url` 是**完整 endpoint**，不追加任何路径段。
- 解析：`tooling_guard/jev/schema.py` 的 `parse_jev_answer`（读 `answers.risk.score` / `answers.risk.confidence` / `answers.deep.noul`；`_probability` 把 0..1 概率按 `>=0.5` 折成 bool）与 `parse_llm_answer`（要求 score 为 0..100 int、noul 为 bool）。
- 折叠与接线：`tooling_guard/triage/engine.py` 的 `judge_payload` → `annotate_confidence` → `decide`；低 confidence 只标 `degraded=fast_low_confidence`（0.6.2 起**弃权**，不再挂起、不建票，交给深审）；`JudgeStage.force_deep` 由 `reviewers/jev_fast.py` 以 `DETAIL_FORCE_DEEP` 带出。
- 状态面同源：`tooling_guard/ui/contracts.py:69` 的 `FastJudgeStatus(enabled, backend, allow_score, block_score, min_confidence)`；`tooling_guard/main.py:1382` 的 `FastThresholds.from_config` 是唯一解析点、`:1662` 只读属性 `fast_judge_status`、`:1383-1389` 只构造一次；读侧 `tooling_guard/ui/commands.py:349` 的 `read_fast_judge_status`（`/guard status` 行在 `:2095`）与 `tooling_guard/web/queries.py:446` 的 `serialize_fast_judge`（payload 键在 `tooling_guard/web/api.py:490`，固定六键 available/enabled/backend/allow_score/block_score/min_confidence）。**代价**：两处显示的是同一个真相，配置写错时一起显示降级观察，不会各写一套。
- R8 读写分离：`tooling_guard/triage/classify.py` 的 `READ_ONLY_COMMANDS`（`:327`，54 个只读命令词）、`WRITE_EXEC_WORDS`（`:391`，写/删/执行动词）、`is_read_only_command`（`:809`）、`_read_only_line`（`:1135`）算出正交标签 `LABEL_READ_IN_ROOTS`（`:55`，值 `read_in_project_roots`）；`tooling_guard/triage/rules.py` 的 `_rule_r8`（`:535`）见到该标签即在 `:545` 直接 `return None`，其余判据与 `absolute_paths=<n>` 记录一字未改；预计算在 `tooling_guard/triage/engine.py` 的 `_mark_read_in_roots`（`:253`：只对 exec/read 工具生效，`read_scope_paths`（`classify.py:753`）拿到的每个路径都用 `paths.is_in_project_roots` 过一遍，异常一律回退不标记），由 `classify_features`（`:273`）调用——`rules.py` 依旧不读配置。**代价**：词表外形态、写/删/执行动词、重定向、未加引号的 `>` 与 `$(`、空 `project_roots` 全部照旧触发；去掉的只是 observe 级观测与同步深审触发，不放开任何调用。
- 深审片段保留：`tooling_guard/main.py` 的 `FragmentFilter`（`:535`）新增 `outside_project_roots_kept` 与 `roots_configured` 两个末尾默认字段；`filter_fragments`（`:1241`）先秘密扫描（命中仍 `dropped_secret += 1` 丢弃），空 `project_roots` 仍按旧语义全丢，域外绝对路径替换成 `<EXT>/<basename>`（`_placeholder_outside_roots` `:1339` / `_placeholder_name` `:1361`）后**重扫秘密**，再按 2 KB 截断（`_truncate_utf8` `:1368`）进 `kept`；`sample_fragments`（`:2484`）在 `dropped` 或 `outside_project_roots_kept` 非零时都写一行 census（`_record_fragment_census` `:4615`；只保留的轮次文案是 `deep-analysis fragments kept outside project roots:`、`degraded=False`）；`no_fragment_in_scope` 只在 `kept` 为空时出现（`:2530`，`deep_review` 在 `:2504`）。`census` 串形如 `secret_pattern=0;outside_project_roots_kept=1;outside_project_roots=0`，空 roots 追加 ` project_roots=missing`。


**第十批改动（用户可见文案压缩 + 管理员回复即审批）的实测行号**——同上，本节与前面各段冲突时以本段为准：

- 通知渲染：`tooling_guard/notify/messages.py` 的 `render_admin_message` 固定 6 行（抬头含票据、工具/动作/层级/判定/规则、目标/参数、主体/会话/剩余、回复语法 + 一个等价 `/guard approve`、覆盖边界），`_short_code` 取票据前 8 字符（占位票返回空串，则通知不给短码）；`render_late_notice` / `render_delivery_failure_notice` / `render_canceled_notice` 压到 2–4 行。通知里**不再出现** `/guard deny`、`/guard status` 与「如非预期请拒绝」。verb/tier 仍取事件字段，挂起路径没传时如实显示「未知动作/未定级」而不猜。
- 命令面文案：`tooling_guard/ui/commands.py` 的 `_HELP`（6 行）、`_COVERAGE`（两条：(a) cron/后台唤醒与子 agent 内部调用不经本钩子；(b) MCP/handoff/后台/未知形态工具被剥离即不可用、挂起最长 110s）、`_status_reply`（4 行骨架 + 可选行）、`_ticket_status_reply`（3 行）、`_whoami_reply`（2 行，被拒 3 行）、`_verdict_line`（单行三判断）、`_diagnosis_note`（单行）、`_reviewer_lines`（**单行**，`审查器 reviewers：` + 各审查器 `name 状态 最近= 降级=` 以 `｜` 连接）、`_stats_reply` 第 2 行。保留不变：`REFUSAL_TEXT` 首句逐字、`JEV_LINE_*`（`JEV 快审：已启用/已关闭`）、`DEEP_ON/OFF`（`深度复核：已启用/已关闭`）、`_startup_sweep_line` 的 `ok=`/`attempts=`/`approvals_closed=` 三个 token。
- 回执文案：`tooling_guard/interface/results.py` 的 `denial_result` 仍以「工具调用已被拦截」开头但压成两句、`suspension_text` 五分支各一句。
- 回复即审批：新模块 `tooling_guard/ui/reply_approval.py` 的 `parse_reply`（只认首词、`APPROVE_WORDS`/`DENY_WORDS` 封闭集合、可带 ≥4 字符票号前缀与拒绝原因）、`handle_reply`（私聊 + 管理员 + 有待批票据三道闸，否则返回 `None` 让消息照常进 LLM）、`_ambiguous_reply`（多条待批时列短码不猜）、`short_code`；决定一律调 `tooling_guard/ui/commands.py` 的 `decide_ticket`（同一 CAS、同一 `_late_result` 迟到路径），审计 `tool_name=guard/reply`、`source=manual`。为让回复面不碰私有符号，`ui/commands.py` 新增四个公开包装 `admin_actor` / `chat_type` / `store_connection` / `redactor`。
- 入口：仓库根 `main.py` 用 `@filter.regex(reply_approval.REPLY_APPROVAL_PATTERN)` 注册 `approve_by_reply`，命中则 `yield event.plain_result(text)` + `event.stop_event()`，不命中直接返回（宿主 `astrbot/core/pipeline/process_stage/stage.py:62-76` 决定消息随后照常进 LLM）。**`handle_reply` 是同步函数**，`await` 它会抛 `object str can't be used in 'await' expression`（e2e 实测抓到过一次）。`/toolguard` 概览压成一行。
- 代价：三条决定入口（命令面、Web、私聊回复）都落在同一个 `decide_ticket` 上，所以入口不改变终态与窗口；通知只给回复语法与一个等价命令，完整命令列表要看 `/guard help`；`_status_reply` 因规格钉住两个标签与三个 token，不可能比 4 行更短。


**第十一批改动（深审 Context 修复 + 快审超时可配）的实测行号**——同上，本节与前面各段冲突时以本段为准：

- 深审拿不到宿主 Context（真实故障）：`tooling_guard/main.py` 的 `_build_deep_client` 原为 `DeepReviewClient(self._config)`，而 `llm_mode=astrbot_provider`（出厂默认）要靠 `context.llm_generate` 解析空的 `llm_provider_id`（`tooling_guard/provider/llm.py:140-155` 的 `_review_provider`、`:166-169` 的 `_generate`、`:197-218` 的 `_default_provider_id`）。缺 Context 时每次深审都抛 `TypeError: astrbot_provider unavailable: ... does not expose the public llm_generate method`，`_guarded_review`（`:1009-1033`）把它折成 `deep_review_failed:TypeError`。现在传 `context=self._context`。
- 熔断器藏起成因：`JUDGE_FAILURE_THRESHOLD = 2`（`main.py:247`）、`JUDGE_COOLDOWN_S = 300.0`（`:249`），`_sync_deep_review` 在 `self._judge_retry_at > now` 时直接返回 `DEGRADED_JUDGE_UNAVAILABLE`（`:2672-2675`），期间每次判定只有无因标记。`_note_judge_result` 现在在失败突发第一次与断路器真正打开时各打一条 warning（带 marker 与冷却秒数），每条突发最多两行。
- 快审超时可配：`tooling_guard/jev/client.py` 的 `MAX_TIMEOUT_S = 50.0`（绝对上限，为容纳本机冷启动从 30 抬到 50）、`DEFAULT_TIMEOUT_S = 10.0`、`configured_timeout()`、`JevClient.timeout_s`（从 `jev_timeout_s` 读，钳制到 1–50）、`ask()` 按客户端上限钳制、`FastJudge` 未显式给超时时取客户端值。配置键在 `tooling_guard/policy/config.py`（`INT_BOUNDS` 里 `jev_timeout_s` 为 `(1, 50)`、`decision_budget_s` 为 `(1, 120)`、`GatewayConfig.jev_timeout_s`）与 `_conf_schema.json`；`main.py` 的 `self._jev_timeout` 一次解析，`_fast_judge_callable` 与 `_review_round` 的 `budgets={JEV_FAST_NAME: min(self._jev_timeout, budget)}` 都用它。**超时不再拒绝**：0.6.0 起快审超时按弃权计（`triage/engine.judge_stage` 折成「模型没有给出结论」），两层模型都弃权时才开票问管理员。
- 诊断证据：真实诊断包（`Review/astrbot-diagnostics-raw-20261030-215154.zip`）里第一条深审行是 `deep_review_failed:TypeError`，其余 26 行都是 `judge_unavailable`；同一次探测显示本机端点 `/v1/systemone` 冷启动 14.7 秒——旧版 5 秒上限在任何冷启动期间都必然超时。

## 1d. 模块化审查流水线（目标态：并发早停）

四层边界，依赖方向单向下行，跨层反向调用一律返工：

1. **契约层 `core/`**：只表达「一次调用是什么」（`call.py`）、「一个结论是什么」（`verdict.py`）、「一个审查器是什么」（`reviewer.py`，含自有时间预算）、「谁被启用、按什么顺序展示」（`registry.py` + `pipeline.py`），另加共享预算（`budget.py`）与只读视图（`guard.py`）。没有任何具体规则、不写审计、不发通知、不 import 具体审查器。
2. **审查器层 `reviewers/`**：每个内置审查器只实现 `Reviewer` 协议——读 `GuardCall`、返回 `Verdict`、暴露 `ReviewerStatus`（busy 三态、`order`、`enabled`、`removable`）。五个内置项：`policy`（`order=-10`、注册表既拒绝注销也拒绝停用，无条件跑硬拒绝策略阶段——路径/用户黑名单、私钥/PEM、`strict_path_whitelist`、T-strong 挂起）、`base_check`（`order=0`、默认启用、拒绝注销、可停用；停用只关「白名单命中把 `skip` 提升成 `allow`」这一档，同时写降级审计并告警）、`rules`、`jev_fast`、`llm_deep`。审查器只调 `core` 契约与只读视图，具体判定仍委托既有能力库（`policy/`、`triage/`、`jev/`、`provider/`）。
3. **编排层 `core/pipeline.py` + `tooling_guard/main.py`**：`main.py` 只做装配与生命周期，`_guard` 由「硬编码顺序」改为「向注册表取启用集后交给 `ReviewPipeline.run`」。聚合是**并发早停**：
   - 所有 `enabled` 审查器**并发启动**（各自 `asyncio.create_task`），`order` 只用于记录与结果相同时的确定性展示，不决定谁能跑；
   - 第一个 `deny` **立即早停**：cancel 其余仍在跑的任务并立刻返回，返回值标 `terminated_early=True` 并列出被抢占者；
   - `suspend` **不得早停**——`deny` 强于 `suspend`，此时取消其余审查器可能漏掉更严重的 `deny`，须继续等到其余完成或 deadline；
   - 最终折算 `deny > suspend > allow/skip`，**放行要求全员 allow 或 skip**（skip 指该审查器判定不需要复杂审核）；
   - 被早停取消的审查器记 `preempted`，既不算 allow 也不算 skip，不计入「全部通过」；取消必须 `await` 到任务
  真正结束（`_await_cancelled`，上限 `PREEMPT_GRACE_S = 0.05`），而适配器 MUST NOT 吞 `CancelledError`
  ——否则忙计数（`reviewer_busy:<name>`）残留、后续调用被误判为忙；
   - 每个审查器吃自己的时间预算，超时 fail-closed：记 `reviewer_timeout:<name>` 并按 `deny`（与既有 `triage_timeout` 同口径）。

   `PipelineOutcome` 字段：`decision`、`verdicts`（按完成顺序）、`preempted`（名字元组）、`terminated_early: bool`、`degraded`、`elapsed_s`。审计、通知、票据、轨迹这些副作用仍由 `main.py` 按既有顺序执行，审查器不参与。
4. **展示层 `web/` + 根 `views/`**：`web/api.py` 经宿主 `register_web_api` 暴露路由，鉴权与命令面同源（宿主注入的用户名非空即读全部主体、只有被 `web_subject_map` 映射时才收窄；决策按 `web_admin_usernames`，空名单=任何已登录用户；拿不到身份一律拒绝）；`views/guard/index.html` 只做列表/筛选/详情/批准拒绝，不自建端口、不直连数据库（宿主只发现 `views/<目录>/index.html`，裸 `views/index.html` 永不显示）。状态数据一律取自 `core/guard.py` 的只读视图，批准与拒绝走与 `/guard approve|deny` 相同的票据 CAS。

审查器新增不改变覆盖边界：cron、后台唤醒与子 agent 内部调用仍不经过 `OnLLMRequestEvent`，任何审查器都看不到它们（见第 7 节与 `README.md` 不保证项）。

## 2. 各层职责与禁止事项

| 层 | 只做什么 | 明确不做 |
|---|---|---|
| 根 `main.py` | `ToolingGuard(Star)`、`@filter.command("toolguard")`、`on_llm_request` 注册、`__init__`/`terminate` 转调 | 任何判定、路径、存储、网络逻辑 |
| `tooling_guard/main.py` | 组装组件、向注册表取启用审查器后交给 `core/pipeline.py`、执行副作用（意图 → 审计 → 轨迹/挂起）、暴露 `Gateway` | 直接 import AstrBot 运行时对象（由 interface 层传入）、硬编码审查顺序 |
| `core/` | 契约数据类、`Reviewer` 协议与状态、注册表、并发早停聚合、共享预算、只读视图 | 具体规则、写审计、发通知、import 任何具体审查器 |
| `reviewers/` | 五个内置审查器按 `Reviewer` 协议产出 `Verdict` 与 `ReviewerStatus` | 写审计/通知/库、互相调用、改变覆盖边界 |
| `web/` | `register_web_api` 路由、鉴权、筛选、把批准/拒绝转给票据 CAS | 自建端口、直连数据库、绕过判定、给非管理员开批准权 |
| 根 `views/` | 列表/筛选/详情/批准拒绝页面（只经 bridge SDK 调 `web/`） | 任何策略与判定逻辑 |
| `interface/` | 把 `req.func_tool`、event、`FunctionTool`、`CallToolResult` 转成内部数据；装卸代理 | 判定规则、路径规范化、SQL、HTTP |
| `policy/` | 配置与名单、路径规范化、求值顺序、快照版本 | 调模型、写审计表 |
| `triage/` | 标签分类、规则目录、decision 枚举、同步判定编排 | 直接访问 sqlite 或 HTTP（经注入接口） |
| `trace/` | 意图/轨迹/摘要/taint/R12 | 决定 deny（只把升级结论交给 triage/policy） |
| `store/` | sqlite 打开、迁移、审计与票据写入、CAS 转换；**一个连接只有一个提交所有者**（每连接一把可重入 RLock，写函数一律经 `write_transaction` / `@serialized_write`）；启动 sweep 失败时批准侧 fail closed | 判定、脱敏渲染、通知、绕过写锁直接 `commit` / `rollback` |
| `jev/` + `prompts/` | jev 请求构建与提示词构建、响应解析 | 直接读轨迹原文（只接收已脱敏摘要/片段） |
| `provider/` | 深度分析模型接入与后台任务 | 提示词正文（在 `prompts/`） |
| `notify/` + `approval/` | 通知文本与回帖、等待/迟到处理 | 判定与持久化（经 store 接口）；**不自行夹取投递超时**——上限只在 `Gateway._send_notice` 一处 |
| `ui/` | 命令面（`/guard`、`/toolguard`）的分发与文本渲染，视图数据类改为消费 `core/guard.py` | 任何执行、写配置、绕过判定 |

## 3. 依赖方向（单向，违反即返工）

~~~
interface ──▶ main(Gateway) ──▶ { trace, approval }（副作用：审计、票据、意图、挂起）
main ──▶ core.registry（main 注入五个内置审查器）
main ──▶ core.pipeline ──▶ reviewers/*（并发启动，仅 deny 早停）
reviewers ──▶ core（契约 + 只读视图）──▶ 既有能力库（policy / triage / jev / provider）
main ──▶ { store, jev, provider, notify }
                    ├──▶ store ◀──────┘
                    ├──▶ jev ──▶ prompts
                    ├──▶ provider ──▶ prompts
                    └──▶ notify ──▶ anonymize
core：不 import reviewers / web，也不 import store 的写路径（只 import dataclass 与标准库）
web ──▶ core.guard（只读视图）+ store.tickets（票据 CAS），不 import interface / triage / reviewers
compat / anonymize：可被任何层 import，自身不 import 本包其它业务模块
ui：只 import 数据类与 store 的只读视图，不 import interface
~~~

硬规则：
- `jev/`、`prompts/`、`provider/`、`store/`、`policy/` **不得** import `interface/`，也不得 import `astrbot.api` 之外的更深 AstrBot 模块。
- 除 `interface/` 与 `compat.py` 外，任何模块不得出现 `_wrapped`、`mcp_*`、`transfer_to_` 这类上游实现细节；这些线索只在 `compat.py` 识别并对外暴露稳定标记。
- 除 `store/db.py` 外任何模块不得直接 `sqlite3.connect`；除 `jev/client.py`、`provider/llm.py` 外任何模块不得发起 HTTP。
- HTTP 一律用 `httpx.AsyncClient`（异步，不阻塞事件循环），**禁 `requests`、禁同步 `httpx.Client`**；客户端按需短生命周期创建并在同一事件循环内使用，不跨请求复用连接池。
- 除 `anonymize.py` 外任何出口（审计、通知、模型、片段）不得自行拼装未脱敏文本。
- 平台交互只用平台中立访问器：`get_platform_id()`/`get_sender_id()`/`get_group_id()`/`event.is_admin()`/`event.send()`；首个必须兼容目标是 **OneBot v11**（`aiocqhttp` 适配器），禁止使用任何 OneBot 专有 API。
- 数据路径只经 `astrbot.api.star.StarTools.get_data_dir`（本机实测可调用，签名 `(plugin_name: str | None = None) -> pathlib.Path`）。
- `reviewers/` 只依赖 `core/` 的契约（`call` / `verdict` / `reviewer`）与只读视图（`core/guard.py`）：**不得** import `store/`、`notify/`、`web/`，不得自行写审计、发通知或打开数据库；停用与降级事实以 `ReviewerStatus` 上交 `core/pipeline.py`，由 `tooling_guard/main.py` 落审计与告警。
- `core/` **不得** import 任何具体审查器（`reviewers/*`）与 `web/`：它是契约与编排，具体审查器一律由 `tooling_guard/main.py` 经 `core/registry.py` 注入。
- **写 sqlite 只能经 `store/db.py` 的写事务入口**：`write_lock` / `write_transaction` / `@serialized_write`。
  `sqlite3.connect(check_same_thread=False)` 只去掉线程亲和，**不**串行化事务——两个线程共用同一连接时
  一方 `rollback` 会丢另一方未提交的行、一方 `commit` 会连带提交。因此 `store/audit.py` 的 5 个写函数与
  `store/tickets.py` 的 7 个写函数全部串行化，旁路观测 worker 线程（`observation.py` 的
  `_probe_worker_read`）取同一把锁；新增写路径必须复用入口，不得自己 `conn.execute("BEGIN")` 或裸 `commit`。
  已知边界：事件循环上的写最多等一个 worker 持有的锁，上界由 `BUSY_TIMEOUT_MS = 150` 与语句耗时决定，
  没有硬实时保证。
- **批准侧的 fail-closed 闸只有一处**：`require_startup_sweep`（`store/db.py`）。启动 sweep 失败时进程照常
  启动，但 `find_approved` / `consume_approved` 一律抛 `StorageUnavailableError`，网关抑制后拒绝，sweep
  重试成功才放行；从未尝试过 sweep 的连接不算 fail-closed（生产路径必经 `open_db`）。新增批准路径不得
  绕过这道闸，也不得把「sweep 没跑过」当成可用。
- **通知投递超时只在 `Gateway._send_notice` 夹取**：每次 `min(5 秒, 本调用剩余预算)`，拿不到预算时仍有
  5 秒上限。超时只记投递失败、**不改判决**——审计与判决都不依赖送达。给管理员看的剩余秒数是保守值
  （真实窗口 − 单次投递上限，最多低估 5 秒），通知文本不参与超时判定。
- `web/` 只依赖 `core/guard.py` 的只读视图与 `store/tickets.py` 的票据 CAS（`find_approved` / `consume_approved`）：**不得** import `interface/`、`triage/`、`reviewers/`，不得自建判定、不得绕过 `guard_call`，批准权限与 `/guard approve|deny` 同源（仅管理员）。

## 4. 端到端数据流

1. `interface/hooks.py` 收到 `OnLLMRequestEvent` → `policy/config` 校验快照 → `interface/install.py` 的 `install_proxies`（`tooling_guard/interface/install.py:384`）遍历 `req.func_tool`，用 `compat.unwrap` 解包后按 `_surface_kind`（`:27`，判定顺序 `:59-84`）分类，再按**三路分流**处理（循环 `:418-430`）：
   1. **managed** → 包成 `interface/wrapper.py` 的 `ManagedToolProxy` 回填（`:425-426`）。判据：`name in KNOWN_TOOLS`（`:77-78`），**或**插件工具能读出**任一**归属线索——`handler` 非空（`:79-80`）或 `handler_module_path` 非空（`:81-82`）——第三方插件自有工具因此一并被纳管。顺序是「先 MCP/handoff/后台/`future_task`，再要求 `FunctionTool` 且名字非空（`:75-76`），最后才算线索」。判据的 docstring 原话是 “A tool counts as managed as soon as ONE ownership clue is readable”（`:32-39`）：宿主的 `_PermissionGuardedTool` 故意把 `handler` 留成 `None`、而 `handler_module_path` 取自工具类的 `__module__`，**要求两者同时成立会把第三方可调用工具错判成 unknown 从而丢掉**。
   2. **一切不可纳管（五类）** → 由**唯一**开关 `strip_unmanaged_tools` 决定 passthrough 还是 stripped（`:427-430`）。五类是 `mcp`（判定 `:65-67`）、`handoff`（`transfer_to_*`，`tooling_guard/compat.py:58` 的 `HANDOFF_NAME_PREFIX`；判定 `:68-71`）、`background`（`:72-73`）、`future_task`（`install.py:21` 的 `FUTURE_TASK_NAME`；判定 `:74-75`）、`unknown`（`:60-64` / `:76-77` / `:84`）。开关**关（出厂默认）** ⇒ 五类全部原样放行：不装代理、不审计、不落策略，打全仓**唯一**一条披露 WARN「%d 个不可纳管工具原样放行（不进入审计与策略）：%s」（`:466-471`）；开关**开** ⇒ 五类全部移除并打**唯一**一条剥离 WARN「开关 strip_unmanaged_tools 已开启，剥离 %d 个不可纳管工具（这些工具本轮不可用，也不留审计行）：%s」（`:459-465`）。**unknown 不再等于被剥离**，反过来 MCP / handoff / 后台任务 / `future_task` 也不再等于永远剥离：`observe` 下都不记 `would_be`，审计里没有它们的行——放过即放过。
2. 模型调用受管工具 → 代理 `call` 入口记 `deadline = now + tool_call_timeout - 10` → 网关把宿主会话工作区 `<data>/workspaces/<归一化 umo>` 当 base 取出来（`Gateway._workspace_base`，`tooling_guard/main.py:427`；调用点在 `_decide` 之前，`:2523`/`:2545`）→ `trace/intent` 记 call_id → `triage/engine.call_base`（`triage/engine.py:274`）在判定期间绑定该 base，相对路径按它解析；base 为 `None` 时相对目标落到 `relative_unknown_base` 的拒绝侧 → `triage/engine` 出标签与规则命中 → `policy/layers` 出策略结论 → `triage/decisions` 落 decision。
3. 允许 → 转发内层工具（委派方式由 `triage/engine` 决定）；拒绝 → `interface/results` 造 `CallToolResult(isError=True)`。
4. 挂起 → **唯一判定是 `suspend_disabled_sessions` 整键精确**（`main.py` 的 `_suspend_suppression`
   `:3409` 拿名单与会话键逐字比较，`:3436-3438`；命中时 `_suppress_suspend` `:3441` 零票据直接
   `deny_policy` + `degraded=suspend_disabled_session`，并私信告警管理员
   `_alert_suspend_suppressed` `:3477`，按会话限频 `alert_scope=session` `:3538`）——**没有别的门**：
   群会话里任何发起人都照常等待，而「能等」不等于「能批」，批准仍要宿主 `is_admin()` 与插件
   `config.admins` 双条件（`_admin_actor`，`tooling_guard/ui/commands.py:1588`）→ 仍可挂起时用
   `effective_suspend_deadline` 把等待终点重画成 `min(deadline, now + min(suspend_timeout_s, 110))`（只会缩短）
   → `store/tickets` 建票据 → `notify/admin` 通知 → `approval/waiter` 在 call 内同步等待到该终点
   → 返回真实非空字符串；批准不自动重放。
5. 旁路 → `trace/recorder` 追加摘要、`trace/taint` 更新 shingle、`trace/escalation` 评估 R12、必要时升级挂起。
6. 所有出口先经 `anonymize.py`，再写 `store/audit.py`、通知、模型。

目标态差异只在第 2 步：标签与规则命中、快审、深审分别由 `reviewers/rules.py`、`reviewers/jev_fast.py`、`reviewers/llm_deep.py` **并发**给出，`reviewers/base_check.py` 同时给出名单结论，`core/pipeline.py` 汇总为 `PipelineOutcome`（见 §1d）；其余步骤（审计、票据、挂起、轨迹、脱敏出口）逐条不变。

## 5. 模块 ↔ tasks 组映射

| tasks 组 | 主要落点 |
|---|---|
| 1（实测门） | `compat.py`（指纹与解包线索）、`interface/install.py` 装配计数 |
| 2（骨架与控制台） | `tooling_guard/main.py`、`policy/config.py`、`_conf_schema.json`、各模块骨架 |
| 3（代理与生命周期） | `interface/install.py`、`interface/wrapper.py`、`interface/results.py`、`approval/waiter.py` |
| 4（策略与路径） | `policy/paths.py`、`policy/layers.py`、`policy/allowlists.py`、`policy/snapshot.py` |
| 5（单条判定） | `triage/classify.py`、`triage/decisions.py`、`jev/*`、`prompts/single_call.py` |
| 6（轨迹与深审） | `trace/*`、`provider/*`、`prompts/trajectory.py`、`notify/*` |
| 7（票据与审批） | `store/tickets.py`、`approval/lateness.py`、`notify/messages.py` |
| 8（审计与存储） | `store/db.py`、`store/audit.py`、`anonymize.py` |
| 9（降级与自检） | `compat.py`、`interface/hooks.py` canary、`ui/contracts.py` 状态视图 |
| 10（文档与验收） | README、`metadata.yaml` 改名、验收脚本 |
| 11（模块化审查流水线） | `core/*`、`reviewers/*`、`web/*`、根 `views/guard/index.html`、`metadata.yaml` 的 `views: [guard]` 声明 |

## 6. 命名规则

- 目录与模块 `snake_case`；每层 `__init__.py` 只导出该层对外稳定符号。
- 类名：`Gateway`、`ToolProxy`、`PolicySnapshot`、`TriageEngine`、`TicketStore`、`TaintStore`、`JevClient`、`AdminNotifier`、`ApprovalWaiter`。
- 内部数据一律 dataclass；跨层不传 AstrBot 对象（`FunctionTool`/event 只出现在 `interface/`）。
- 配置键名与 `_conf_schema.json` 完全一致；键名常量集中在 `policy/config.py`，禁止散落字面量。

## 7. 本期明确不实现（架构已预留）

- `ui/`：命令面保留（`/guard`、`/toolguard`），视图数据类迁往 `core/guard.py`；页面由 `web/` + 根 `views/guard/index.html` 承担（tasks 11.6/11.7），加 WebUI 行为仍必须先在 `specs/` 增加 requirement。
- 子 agent 内部工具调用：tasks 6.7 只做旁路观测与告警。
- `cron`/后台唤醒：无法被 `OnLLMRequestEvent` 覆盖，只做旁路审计与状态页披露。

## 8. 「不保证项」的实现锚点（README 压成一页后，细则落在这里）

README 的「不保证项」已压缩成每行一条短句，只保留结论。以下条目在两份深层文档里原本没有别处记录，
细则按本节读；其余条目在 `AGENTS.md` 的 R9 / R10 / R11 / W1 / T1 与本文 §1c 已有完整口径，不再重复。

- **迟到裁决不回填模型上下文**。design 的 D4 要求把迟到决定经 `req.system_prompt` 摘要披露，当前没有写入任何
  `req.system_prompt`：`tooling_guard/` 与根 `main.py` 里唯一命中是 `tooling_guard/provider/llm.py:129`
  （深度分析模型的入参，不是请求上下文）；
  `tooling_guard/approval/lateness.py:21` 只有 `reject_late_decision`。迟到决定只落审计并通知管理员。
- **读路径不产生 `allow_*` 审计行，现有测试盯着它**。读接口只写 `deny_requester`（`_record_refusal`，
  `tooling_guard/web/api.py:111`；限频入口 `_read_refusal` `:177`），读成功不写任何 `allow_*` 行，
  `tests/unit/web/test_web.py` 已用「已登录读取不写任何拒绝行/放行行」与「决策拒绝永不折叠」两组断言钉住。
- **没有存活等待者的批准会撤回重试窗口**。无人等待的审批不再留一段可被 `find_approved` 命中的批准窗口：
  票据被撤回到 `canceled_external`，summary 记 `retry_window=withdrawn reason=no_waiter`。
- **凭据 glob 不含备份副本**。`_GLOB_KEY_CANDIDATES`（`tooling_guard/triage/classify.py:212`）与
  `_GLOB_CONFIG_CANDIDATES`（`:219`）只列**具体键名与配置名**，所以 `id_rsa.bak` / `id_rsa.txt` 能被
  `glob=*.txt` 或 `glob=*.bak` 命中却不产生任何凭据目标、不判 `deny_secret`；按 path 直接指定 `id_rsa.bak`
  仍按凭据目标判 `deny`。「用通配符扫目录」不等价于「扫到所有副本」。
- **相对路径的根只复现宿主 legacy 工作区布局**。base 取宿主会话工作区 `<data>/workspaces/<归一化 umo>`
  （`Gateway._workspace_base` → `_decide(..., base=...)` → `triage/engine.call_base`）；自定义/项目工作区走宿主
  `resolve_workspace_root_for_umo` 的数据库分支，插件读不到，那种部署下 base 只能是 `None`，相对目标一律落到
  `relative_unknown_base` 的拒绝侧。
- **审计 drain 仍在事件循环线程里执行**。`tooling_guard/observation.py` 的 `record_async` 只把**旁路观测**写库放进
  线程（`_worker_capable` 探测失败则退回同步），告警有 `ALERT_TIMEOUT_S = 5.0` 上限、写库失败显式写
  `audit_store_unavailable`（`STORE_FAILED_REASON`）；但审计写入的 drain 没有搬到工作线程，单次被外部锁住时最坏
  冻结约 `BUSY_TIMEOUT_MS = 150` 毫秒量级（`tooling_guard/store/db.py:61`，原 5000）。事件循环上的写因此没有硬实时上界。
- **未识别包装形态只有分类器，没有动作**。`tooling_guard/compat.py:240` 的 `classify_wrapper_surface` 只做分类：
  `unwrap_chain`（`:180`，上限 `MAX_UNWRAP = 4`，`:90`）缺属性返回 `complete=True`，自引用、互指环、读失败、超深
  返回不完整；异常面只有显式七类 `_HOSTILE_ERRORS`（`:124`），没有盲 `except`，`__getattr__` / `name` property /
  `__str__` 抛异常不外泄。顺序为 MCP -> handoff -> background -> future_task -> FunctionTool 形状 -> 目录/插件
  （`SURFACE_MARKERS`，`:106`；与安装期 `_surface_kind` 对齐）；不传 `known_tools` 时只凭形状判定，`handler` 为空的
  FunctionTool 判 `unknown`（`:296-306`，比安装期更严格）。`unknown` 在 `MANAGED_SURFACES`（`:117`）之外、
  `surface_is_managed`（`:309`）返回假，即「不纳管」——安装期对它原样放行并披露，不是 fail-closed 删掉。
- **Web 控制台没有自己的 CSRF token，也不假设面板只对本机开放**。身份只来自宿主注入的 `PluginRequest.username`，
  安全性委托宿主会话 / JWT 与同源策略；approve / deny 是 POST，且**先判名单再动票据**。默认口径是「本机单人运维」
  ——一旦反代到公网，任何能登录面板的账号可读全部审计并批准任何票据，这是配置层需要自己承担的代价。
- **观测心跳断言是测试侧的时间假设**。`tests/unit/observation/test_observation.py` 的心跳断言在极端负载下可能瞬时
  抖动；产品路径上没有「心跳必须在 N 毫秒内到」这样的判定。
- **尚未关闭的易用性 nit**：`cron` 轮次既不装代理也不剥离；`/guard status` 的挂起提示仍写死「挂起中，最长 110s」，
  不按实际剩余时间重算。（已关的三条：参数摘要做 NFKC∘NFC 归一、决策失败回复不回显异常类型名、
  `tests/manual/enforce_readiness.py` 自测阈值随场景推导。）
