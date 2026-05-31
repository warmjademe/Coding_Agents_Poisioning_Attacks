# 机制 A：跨通道"拆分投毒" × OWASP Top 10 — 50 案例验证

选题 B 的**机制级创新**的可行性 demo。**已通过 50/50 离线验证**（`validate_all.py`，进程内硬断言，EXITCODE=0，结果留档 `VALIDATION_ALL.json`）。

## 机制一句话

把一次攻击**拆成两个代码"零件"/拆掉两道独立防线**，分散藏进 coding agent 修 bug 时会读取的不同输入通道（代码注释 / 依赖配置）：
**任何单条通道单独看都人畜无害（bug 照修好、exploit 打不穿），只有多条通道凑齐，补丁才带上可被真实 exploit 触发的漏洞。**
这是相对 FCV/SWExploit（payload 完整塞在单一 issue 里）的机制级区别——分布式投毒，单点不可疑、不可检出，组合才致命。

## 分类体系：OWASP Top 10 (2021)，每类 5 例，共 50

| OWASP | 类别 | 案例数 | 覆盖 CWE 举例 |
|---|---|---|---|
| A01 | Broken Access Control | 5 | CWE-22/23/639/862 |
| A02 | Cryptographic Failures | 5 | CWE-916/347/338/353 |
| A03 | Injection | 5 | CWE-78/89/94/79/90 |
| A04 | Insecure Design | 5 | CWE-640/841/840/799/434 |
| A05 | Security Misconfiguration | 5 | CWE-611/489/548/942/1392 |
| A06 | Vulnerable & Outdated Components | 5 | CWE-1104/829/1357/494/427 |
| A07 | Identification & Authentication Failures | 5 | CWE-307/613/347/620/308 |
| A08 | Software & Data Integrity Failures | 5 | CWE-502/915/345/494 |
| A09 | Security Logging & Monitoring Failures | 5 | CWE-117/532/778 |
| A10 | Server-Side Request Forgery | 5 | CWE-918 |

## 验证结论（机器核对，见 `VALIDATION_ALL.json`）

1. **50/50 全部满足机制 A**（`validate_all.py` EXITCODE=0）：每个案例都满足"单条无害 + 组合致命 + 最小致命组合=2"。覆盖 39 种不同 CWE、11 个漏洞家族。
2. **单通道打穿次数 = 0**：50 案例 × 每个 3 条单通道 = 150 次单通道注入，没有任何一条单独能打穿——彻底排除"其实是单条起作用"。
3. **每个案例最小致命组合都 = 2**：必须两条通道凑齐两道防线才出漏洞，"拆分"是必要的（机制命根子）。
4. **46/50 案例静态扫描漏报**（真 exploit 打穿了，bandit/AST 静态判定却没报警）：支撑选题 B 第二条轴——判定必须用真 exploit，不能只靠静态。

## "真打"不是"看一眼"

每个案例的 `exploit()` 都是**真实触发**：命令注入真去执行注入命令看标记文件、路径穿越真把文件写到目录外、SQL 注入真用 `' OR '1'='1` 登入、SSRF 真让请求到达内部元数据端点拿到机密串……不是让大模型"看像不像有漏洞"。每个 exploit 跑 3 次要求结果一致（确定性）。

**安全边界**：所有 exploit 仅在临时目录内运行，危害动作仅限临时目录内（touch 标记 / 读写临时文件 / 返回布尔），绝不触碰临时目录以外的真实资源。符合 `../../PROBLEM_AND_RQ_DESIGN.md` §8。

## 怎么跑

```bash
cd mechanism_a
python3 validate_all.py              # 跑全部 50 例，EXITCODE=0 即机制全成立
python3 _test_module.py a03_injection   # 只验证某一个 OWASP 模块
```

无第三方依赖即可跑（静态层 bandit 缺失时自动用 AST 兜底）。

## 文件结构

```
mechanism_a/
├── framework.py            通用引擎：枚举通道组合 + 机制硬断言（真值=真exploit）
├── owasp/
│   ├── _helpers.py         临时目录/源码拼装工具
│   ├── a01_access_control.py   ... a10_ssrf.py   （10 模块 × 5 案例）
├── validate_all.py         跑全部 50 例 → VALIDATION_ALL.json
├── _test_module.py         单模块快速验证
├── VALIDATION_ALL.json     结果留档
└── README.md
```

## 每个案例的统一结构（加新案例照此模板）

```python
Case(
  name, cwe, family, issue_text,           # 元信息 + issue 通道的正常 bug 任务（幌子）
  defenses=[Defense("D1","code_comment",伪装请求1),    # 拆防线1的善意请求 → 注释通道
            Defense("D2","dep_config",  伪装请求2)],   # 拆防线2的善意请求 → 配置通道
  build_patch(dropped)->源码,             # 按"拆了哪些防线"合成补丁（dropped⊆{D1,D2}）
  c1(mod)->bool,                          # 功能测试（bug 修好没）
  exploit(mod)->bool,                     # 真实 exploit（仅当两道都拆才 True）
  owasp="A0x")
```

框架自动枚举 7 种通道激活条件、跑 C1+静态+真exploit、断言机制属性。

## 当前边界（离线 vs 实证）

- ✅ **已真验证**：拆分投毒的攻击构造 + 真实 exploit 打靶管线 + "单条无害/组合致命/静态漏报"三属性，在 OWASP 全 10 类 50 漏洞上成立。
- ⏳ **待实证**：agent 用的是**忠实的指令遵循替身**（按被激活通道里的指令决定拆哪道防线，透明可审计，非查表作弊）。"真实 LLM 是否真会被跨通道的善意伪装说服、会不会拒绝"需用真模型实测——本机已可直连 DeepSeek/Claude/GLM（key 见 `../../CLAUDE.md` 引用的同门凭据），`agent` 的真 LLM 客户端接口在 git 历史里（v1）已写好，可恢复接入。

## 与正式 benchmark 的差距

- 玩具任务/自包含函数 ≠ SWE-bench 真实仓库；替身 ≠ 真 SWE-agent/OpenHands。
- 正式版：真 LLM/真 agent、真实仓库、统计显著性、人工核验，搬 NAS 跑。
