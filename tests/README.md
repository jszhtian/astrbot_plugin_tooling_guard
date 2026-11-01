# tests

离线断言套件：不连 AstrBot、不连 jev、不写审计库，纯 stdlib，直接造对象跑。

## 怎么跑

```
set PYTHONPATH=<仓库根>
py -3 tests/verify_layers.py
py -3 tests/verify_plan.py
py -3 tests/verify_rounds.py
py -3 tests/verify_061.py
py -3 tests/verify_062.py
py -3 tests/verify_063.py
py -3 tests/verify_064.py
py -3 tests/verify_065.py
py -3 tests/verify_066.py
py -3 tests/verify_067.py
py -3 tests/verify_068.py
py -3 tests/verify_069.py
py -3 tests/verify_070.py
```

每个脚本末行打印 `ALL CHECKS PASSED`，退出码 0 即通过。

| 脚本 | 覆盖 |
|---|---|
| `verify_layers.py` | 三层判决表（静态/快审/深审的七行组合）、`policy_verdict` 三态、`judge_stage` 弃权语义、`_needs_deep`、超时按弃权 |
| `verify_plan.py` | `consensus` → `_Plan`，含 observe 改写与 `_ask_human_plan` |
| `verify_rounds.py` | 两轮编排：`only=` 子集、`merge_outcomes`、空集不静默放行 |
| `verify_061.py` | 快审分档、迟到决定去重、`serialize_call_context`、`delivery_attempts` |
| `verify_062.py` | 管理员私信的平台解析（裸 id 展开、面板平台不算送达）、低置信度弃权、`pick_ticket_event` |
| `verify_063.py` | 深审客户端懒建与复用、`_call_summary` 记录 verb/tier |
| `verify_064.py` | 轨迹窗口（`TrajectoryRecorder`/`TrajectoryView`）、ISO 时间、`trajectory_history` 进模型输入 |
| `verify_065.py` | 记录带 `targets`，R7 才可能在生产里命中 |
| `verify_066.py` | R7 命中强制深审（`FORCED_DEEP_RULES`），jev 放行也照写 force 标记 |
| `verify_067.py` | 归因层（stage/layer/source）、`rule_ids_role=evidence`、路径目标形态收敛 |
| `verify_068.py` | 回执里的归因句（`_spoken_reason`），放行不加 |
| `verify_069.py` | 未纳管侧通知开关只停私信，观测与审计不变 |
| `verify_070.py` | 0.7.0/0.7.1 快审来源与配置页顺序：`verdict_from_decision_answers` 折算与弃权、懒加载 `astrbot.api.provider`、`DecisionJudge`/`ProviderJudge` 调用与超时、`jev_enabled` 优先、来源分派、endpoint 必填条件、配置页顺序（协议与来源在端点之前、端点/模型/密钥相邻）、schema 与版本号 |

`make_zip.py <版本号>` 打发布包（排除 `tests/`、`__pycache__`、`.git`）。
