# multicast_guard — 离线双组播树布置与审核工具

面向互不完全信任站点的**纯离线、纯合成**规划/审核工具。所有站点、消息、链路、
许可与故障域均来自虚构 JSON 输入；程序不接触真实网络、不使用任何密钥或密码学，
只模拟两种封装标签：

| 标签 | 含义 |
| --- | --- |
| `"C"` | 密文封装（ciphertext） |
| `"P"` | 明文封装（plaintext） |

运行环境：Windows 原生 Python 3.12，仅标准库、纯 CPU。

---

## 1. 复验命令速览

在仓库根目录执行：

```bat
:: 规划：枚举候选树并选出最优双树
python -m multicast_guard plan cases\case07_full_scale.json

:: 审核：独立重算、基线核验、小图暴力枚举交叉核对、时序网格
python -m multicast_guard check cases\case03_cheap_reuse.json

:: 单元测试（26 个断言用例）
python -m unittest tests.test_multicast_guard -v
```

输出均为可复现的 UTF-8 JSON（键顺序固定、缩进 2 格、`ensure_ascii=False`）。
同一输入多次运行字节级一致。格式错误时以退出码 `2` 返回，且每条错误带 JSON
指针式字段路径，例如 `edges[3].delay_min`。

> 案例文件只作为**数据**被 `json.load` 读取，工具从不导入案例目录中的任何
> 代码，且仅依赖标准库，因此在仓库根目录直接运行即不存在模块劫持面。若仍希望
> 在完全隔离解释器（忽略环境变量与用户 site-packages）下复验，可显式注入
> 仓库根路径：
>
> ```bat
> python -I -c "import sys; sys.path.insert(0,'.'); from multicast_guard.__main__ import main; main(['plan','cases/case07_full_scale.json'])"
> ```

### 冻结的虚构案例

| 文件 | 验收场景 |
| --- | --- |
| `cases/case01_shared_domain.json` | 两棵树各自可达全部接收者，却共享同一关键故障域 |
| `cases/case02_split_survival.json` | 单域失效时两树均受损，但每个接收者仍各有一条完好分支 |
| `cases/case03_cheap_reuse.json` | 便宜边复用破坏容灾，基线因容灾语义被拒 |
| `cases/case04_forbidden_plain.json` | 受禁明文中转：无明文许可的中继收到 P 即违规 |
| `cases/case05_revoked_generation.json` | 旧世代到达时许可已撤回：到达前显式丢弃、回执去重 |
| `cases/case06_exact_deadline.json` | 恰在截止时刻到达（截止点包含） |
| `cases/case07_full_scale.json` | 满规模：18 节点 / 32 边 / 7 接收者 / 6 故障域 |
| `cases/case08_infeasible.json` | 不存在可行双树：给出可重演失败见证并核验基线 |

案例由 `tools/generate_cases.py` 与 `tools/generate_full_case.py` 确定性生成，
生成结果已冻结签入 `cases/`，可直接复验而无需重新生成。

---

## 2. 输入文档（CASE.json）

### 2.1 顶层结构

```json
{
  "schema_version": "multicast-guard/v1",
  "case_id": "case07_full_scale",
  "version": "v2",
  "nodes": [ ... ],
  "edges": [ ... ],
  "topics": [ ... ],
  "message": { ... },
  "permits": [ ... ],
  "receivers": ["R1", "..."],
  "fault_domains": [ ... ],
  "previous": { ... },          // 可选：上一版本双树与目录
  "baseline": { ... },          // 可选：要求 check 核验的指定基线
  "check_request": { ... }      // 可选：指定发布时刻与失效域的重演请求
}
```

容量上限（合成格式）：节点 ≤ 18、边 ≤ 32、接收者 ≤ 7、故障域 ≤ 6。

### 2.2 节点 `nodes[]`

```json
{ "id": "A1", "role": "relay" }
```

`role` ∈ `publisher | relay | receiver`；全文档必须恰好有一个 `publisher`。

### 2.3 边 `edges[]`

```json
{
  "id": "a01",
  "src": "P0",
  "dst": "A1",
  "allowed_labels": ["P", "C"],
  "max_classification": 3,
  "delay_min": 1,
  "delay_max": 3,
  "fault_domain": "d1",
  "cost": 10
}
```

- 边为有向边；禁止自环；`id` 全局唯一。
- `allowed_labels` 非空，元素只能是 `"P"`/`"C"`。
- `max_classification`：边可承载的最高密级（非负整数），低于主题密级的边
  不能进入该主题的树。
- `delay_min`/`delay_max`：整数链路延迟闭区间，`min ≤ max`。
- `fault_domain`：该边所属故障域，且必须同时出现在该域的边名册中。
- `cost`：非负整数费用。

### 2.4 主题 `topics[]` 与消息 `message`

```json
{ "id": "T1", "classification": 3, "plain_allowed": ["P0", "A1", "R1"] }
```

`plain_allowed` 是该主题的**明文许可集合**：任何节点（无论是否指定接收者）
只要能看到明文——入站边标签为 `P`，或它是发起明文的发布站——就必须在此集合中。
「没有显式解封」不构成豁免：入站已是明文的中转同样被视为可见。

```json
{
  "id": "m1",
  "topic": "T1",
  "publisher": "P0",
  "digest": "sha256:synthetic-...",
  "generation": 2,
  "publish_window": { "earliest": 0, "latest": 4 },
  "deadline": 20
}
```

- `publish_window`：允许的整数发布时刻闭区间；规划对区间内**每个**发布时刻
  逐项核验。
- `deadline`：截止时刻；到达时刻 `== deadline` 视为按期（截止点包含）。
- 同刻事件顺序固定为**先处理策略、再处理到达**。

### 2.5 转换许可 `permits[]`

```json
{
  "id": "p1a",
  "node": "P0",
  "from_label": "P",
  "to_label": "C",
  "topic": "T1",
  "generation": 2,
  "version": "v2"
}
```

- 节点可原样转发同标签密文/明文，无需许可；只有**改变封装形态**才消耗许可。
- 许可绑定到节点、主题、世代与输入版本；同一份输入内 `version`/`generation`
  必须与消息/案例一致，**禁止跨版本拼接**（不一致直接校验失败）。
- 每条复制出来的分支各自的转换需要独立许可；同一棵树内一张许可只能消耗一次，
  两棵树的许可集合必须互不相交。
- `from_label` 与 `to_label` 必须不同（同标签转发不需要许可）。

### 2.6 故障域 `fault_domains[]`

```json
{ "id": "d1", "edges": ["a01", "a03"], "nodes": [] }
```

- 域可同时包含边与**中转节点**（仅 `relay` 角色可入域；发布站/接收者不可）。
- 故障情形只有两种：无故障，或任一域在整次传送期间失效。
- 一条接收者路径只要经过失效域的任一边或任一中转节点即判定中断。

### 2.7 上一版本 `previous`（可选）

```json
{
  "version": "v1",
  "tree_a": { "tree_id": "oldA", "root": "P0",
              "edges": [{"edge_id": "e01", "label": "P"}],
              "transforms": [] },
  "tree_b": { ... },
  "receivers": ["R1", "R2"],
  "plain_allowed": ["P0", "A", "R1", "R2"],
  "permits": [ ... ],
  "publish_window": { "earliest": -3, "latest": 2 },
  "in_flight": [ { "digest": "sha256:synthetic-oldgen", "generation": 1 } ]
}
```

旧消息始终沿旧树、旧封装传播，按旧目录/旧许可核验。当前版本中已失去明文许可
的节点，其旧路径必须在**到达该节点之前**于前驱边显式丢弃；新接收者名单不得
用于提前确认旧消息（旧回执只发给旧目录中的接收者）。

### 2.8 基线 `baseline`（可选）与 `check_request`

`baseline` 给出两棵要求 `check` 核验的树，结构同 `previous.tree_*`，但只允许
引用当前版本许可。`check_request` 指定一次可重演场景：

```json
{ "publish_time": 2, "failed_domain": "d2" }
```

`failed_domain` 为 `null` 表示无故障场景。

---

## 3. 规划语义（plan）

### 3.1 树与封装规则

1. 每棵树以发布站为根，有向边构成一棵覆盖**全部**接收者的有根树（每非根节点
   恰有一条入边、无环、全部节点由根可达）。
2. 节点原样转发同标签流量；形态变化（P→C 或 C→P）只能在许可指定的节点执行，
   且消耗一张独立许可。分支出口允许不同封装。
3. 明文可见性：入站标签为 `P` 的节点、以及发起明文的发布站，必须在主题的
   `plain_allowed` 中。
4. 叶节点规则：未列入 `receivers` 的站点不得成为叶节点。
5. 每份复制消息继承同一输入摘要、主题与世代。

### 3.2 双树容灾（逐接收者、逐场景）

- 两棵树都必须能到达全部接收者。
- 对「无故障」与每个故障域失效场景，**逐接收者**判定：该接收者在树 A 或树 B
  上至少有一条实际存活路径即通过。绝不比较两棵树的整体域集合。
- 不同接收者在同一场景下可分别依赖不同的树。

### 3.3 时序核验

- 路径到达区间 = 发布时刻 + 各边延迟区间逐项求和（整数闭区间）。
- 规划保证在「最晚发布 + 每边取 `delay_max`」的最坏组合下，每个接收者仍在
  `deadline` 前（含等于）到达。
- `check` 的 `timing_grid` 对发布窗口内每个整数时刻、每个接收者给出两树的
  到达窗口与按期标志。

### 3.4 成本与决胜（字典序，依次比较）

1. 两棵树启用的**不同边费用之和**（被两树复用的边只计一次）；
2. 全部转换次数之和；
3. 最坏送达耗时（两树最坏路径延迟的较大者）；
4. 仍并列时，按两树的规范边序列与规范转换序列决胜；无主备先后要求时，
   把较小的树排在前面。

### 3.5 候选枚举策略（可复现、诚实标注边界）

- **小图（边数 ≤ 12）**：对带标签入边做完整 DFS 穷举，带反向可达性、截止期、
  明文域与规范化顺序四类精确剪枝；`enumeration_capped=false` 表示结果完备。
- **大图（边数 > 12，如满规模案例）**：采用确定性的有界 beam 搜索——先对每个
  接收者计算按故障域掩码多样化的 K 条最便宜路径，再以域掩码分层做路径并集，
  最后对每个边集骨架确定性分配封装与许可。输出中 `enumeration_capped=true`
  明确告知这是有界搜索而非完备性证明。
- `check` 内的**独立小图暴力枚举**（边子集幂集 × 标签 × 许可绑定，独立实现）
  与主枚举器交叉核对可行树集合、可行性结论与最优成本；满规模案例因超阈值
  报告 `applied=false` 并说明原因。

### 3.6 回执去重

同版本、同摘要的消息无论经几棵树送达，每个接收者只生成一条回执，去重键为
`(digest, receiver)`。

---

## 4. 审核语义（check）

`check` 不信任任何既有结论，独立完成：

1. **独立重算**：重新枚举并判定可行性；不可行时输出可重演见证
   （`no_candidate_tree` 或 `no_feasible_pair`，含首个阻断配对、受影响接收者
   的完整路径与故障场景）。
2. **基线核验**：从边/转换清单重建每棵树，按固定顺序报告**最先越权的中转点**
   （字段 `first_violation`，含 `scope/node/edge_id/reason`）；结构合法但容灾
   不达标时报告**最先失去的接收者**及其两树路径，并附 `replay_witness`。
3. **小图枚举交叉核对**：独立暴力枚举核对可行树集合、可行性与最优成本。
4. **指定场景重演**：按 `check_request` 给出每个接收者的存活树、到达窗口与
   按期标志，以及 `first_lost_receiver`。
5. **时序网格**：见 3.3。
6. **旧版本迁移审计**：窗口交叠、迟到分支、撤回许可下的显式丢弃与旧回执。

---

## 5. 输出文档要点

### plan

```
feasible, stats{candidate_trees, pairs_evaluated, enumeration_capped, ...},
trees[ {tree_id, root, edges, canonical_edge_sequence, transforms,
        used_permit_ids, edge_cost, transform_count, worst_max_arrival,
        paths{ receiver: {node_path, edge_path, label_path, delay_interval,
                          arrival_window_*, worst_case_arrival, on_time_at_deadline,
                          domain_mask} }} ],
cost{ distinct_edge_fee, total_transforms, worst_delivery_time, tuple },
permit_sets_disjoint,
fault_survival{ scenarios, per_scenario{ receiver: {tree_a_alive, tree_b_alive,
                                                    delivered_by} } },
receipts{ receipts[], dedup_key },
migration_audit{ ... }
```

### check

```
independent_rederivation{ feasible, candidate_trees, pairs_evaluated,
                          enumeration_capped, witness },
small_graph_crosscheck{ applied, subsets_scanned, tree_sets_agree,
                        feasibility_agrees, optimum_cost_agrees, ... },
baseline_verification{ accepted, first_violation, replay_witness, ... } | {present:false},
requested_scenario{ publish_time, failed_domain, event_order, deadline_inclusive,
                    per_receiver[], first_lost_receiver },
timing_grid{ computed, delay_semantics, rows[] }
```

### 错误响应（退出码 2）

```json
{
  "status": "error",
  "error_type": "validation",
  "errors": [
    { "path": "edges[3].delay_min", "message": "delay_min must not exceed delay_max" }
  ]
}
```

---

## 6. 目录结构

```
multicast_guard/
  __init__.py        常量与容量上限
  __main__.py        CLI 入口（plan / check）
  errors.py          带字段路径的结构化校验错误
  model.py           数据模型与严格输入校验
  topology.py        树语义、指标、精确枚举与有界 beam 枚举
  planner.py         双树配对、逐接收者容灾、成本决胜、失败见证
  verifier.py        独立复核、基线核验、小图暴力枚举交叉核对、时序网格
  audit.py           旧版本迁移审计（丢弃、迟到分支、回执去重）
  serialize.py       确定性 JSON 序列化
cases/               冻结的虚构案例（可直接复验）
tests/               unittest 断言测试
tools/               案例生成器（确定性，输出已冻结签入）
```

## 7. 设计边界与诚实声明

- 全部数据为合成数据；标签仅两个，不模拟真实加解密、密钥协商或网络 I/O。
- 小图结论经独立暴力枚举交叉验证；满规模案例使用有界 beam 搜索并显式置
  `enumeration_capped=true`，不声称全局完备，但保证输出确定可复现、所有报告的
  树都通过完整的结构、授权、明文域与时序核验。
