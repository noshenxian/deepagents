# 团队 AI 接入流程建议

---

## 第一层：个人效率（第 1 周）

每个开发者独立接入，目标是习惯 AI 协作：

| 工具 | 用法 |
|---|---|
| **Cursor / Codex / deepagents CLI** | 终端里的 coding agent |
| **Copilot** | 行内补全，写 test/boilerplate |
| **Claude/ChatGPT 网页** | 架构设计、代码审查辅助 |

> 关键：不强求统一工具，让每个人自己找到顺手的方式。

---

## 第二层：团队规范（第 2-3 周）

### 1. AGENTS.md — 团队记忆文件

每个项目根目录放一个 `AGENTS.md`，AI 自动加载为上下文：

```markdown
# 项目规范

## 技术栈
- Python 3.13, FastAPI, PostgreSQL
- 测试框架: pytest, asyncio_mode = auto

## 编码约定
- 所有函数必须带类型注解
- 使用 Google-style docstring
- 异常消息用 msg 变量

## 禁止事项
- 不要用 eval/exec/pickle
- 不要修改 git config
- 不要 force push main
```

deepagents CLI 会自动读取并记住这些。

### 2. 团队 Skill 目录

```
skills/
├── code-review/
│   └── SKILL.md        # 代码审查 checklist
├── api-design/
│   └── SKILL.md        # API 设计评审规范
├── deploy-check/
│   └── SKILL.md        # 部署前检查清单
└── architecture/
    └── SKILL.md        # 架构决策记录模板
```

用 `deepagents skills create <name>` 注册到本地 / 项目级 skill 目录，启动时 `--skill <name>` 调用。Skill 目录约定：

- 全局：`~/.deepagents/<agent>/skills/`
- 项目级：`<project_root>/.deepagents/skills/` 或 `<project_root>/.claude/skills/`
- 用 `deepagents skills list` 查看注册情况

### 3. PR 模板 + AI 审查

PR description 必须包含 AI 辅助声明：

```markdown
## AI 辅助
- [ ] 本 PR 使用了 AI 辅助（工具：____）
- [ ] AI 生成代码已人工审查
- [ ] 所有测试通过
```

可以在 CI 中加一个 check，用 AI 自动 review PR：

```yaml
# .github/workflows/ai-review.yml
name: AI Code Review
on: [pull_request]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0           # 需要 base 分支用于 diff
      - run: pipx install deepagents-cli
      - env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          deepagents -n "$(cat <<'PROMPT'
          Review the diff against origin/${{ github.base_ref }} for:
          1. 安全漏洞（注入、密钥、不安全反序列化）
          2. 不符合团队 AGENTS.md 规范的地方
          3. 缺少的测试覆盖
          只输出问题清单，不要寒暄。
          PROMPT
          )" --quiet -S recommended --max-turns 20
```

关键点：

- `-n` (`--non-interactive`) 是单次运行模式；不是 `--headless`
- `-q` (`--quiet`) 输出可被管道消费
- `-S recommended` 限制 AI 只能跑只读 shell 命令（`ls`/`cat`/`grep`/…）
- `--max-turns` 防失控转圈
- 多行 prompt 用 heredoc（`<<<` 是 here-string，只接受一行）

---

## 第三层：自定义 Agent（第 4 周起）

### 团队专用 Agent 部署

用 `deepagents init <name>` 生成标准骨架（注：deploy 当前是 beta）：

```
my-team-agent/
├── deepagents.toml      # [agent] / [sandbox] / [auth] / [memories] / [frontend]
├── AGENTS.md            # 团队规范 + Agent SOP（自动注入 system prompt）
├── .env                 # API keys（不要提交）
├── mcp.json             # MCP 服务配置（GitHub / Slack / 内部工具）
└── skills/
    ├── review/SKILL.md           # 代码审查
    ├── onboarding/SKILL.md       # 新成员引导
    ├── incident-response/SKILL.md  # 故障响应
    └── code-standards/SKILL.md   # 规范检查
```

每个 `SKILL.md` 用 YAML frontmatter 描述何时触发：

```markdown
---
name: incident-response
description: >-
  故障响应 SOP。触发条件：用户提到「线上故障」「P0」
  「服务挂了」「数据库异常」等。
---

# Incident Response

1. 第一时间在 #incident 频道同步状态
2. 拉取 Grafana 关键指标快照
3. ...
```

**关于子 agent**：deepagents 的子 agent 不是文件目录，而是在 Python 代码里
通过 `create_deep_agent(subagents=[...])` 定义（每个子 agent 有独立 context
窗口，专门干一件事）。如果团队需要专职 reviewer / researcher，按 SDK 方式
写 Python 模块，再通过 `deepagents.toml` 的 `agent` 字段指向该模块。

**用户偏好**：每个用户的个性化 prompt 写在 `~/.deepagents/<agent-name>/AGENTS.md`
（用户级，可写），项目根的 `AGENTS.md` 是团队级（只读规范）。

### 关键集成点

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│   GitHub     │────▶│  deepagents     │────▶│   Slack/企微  │
│  Issue/PR    │     │   Agent         │     │   通知+确认   │
└──────────────┘     └─────────────────┘     └──────────────┘
       │                     │
       ▼                     ▼
┌──────────────┐     ┌─────────────────┐
│  Code Review  │     │  知识库/SOP     │
│  安全扫描     │     │  最佳实践       │
└──────────────┘     └─────────────────┘
```

---

## 第四层：治理（持续）

| 事项 | 做法 |
|---|---|
| **AI 生成代码标记** | 提交信息加 `[ai-assisted]` 标签 |
| **质量门禁** | AI 生成的代码必须经过人工 review |
| **安全红线** | `eval`/`exec`/密钥提交等用 pre-commit hook 拦截 |
| **效果衡量** | 每周统计：AI 辅助的 PR 占比、review 周期变化 |
| **知识沉淀** | 每次复盘后更新 `AGENTS.md` 和 skills |

---

## 快速启动建议

```bash
# 团队 onboarding 流程
1. 第1天: pipx install deepagents-cli   # 加上各自的 IDE 补全工具（Copilot/Cursor）
2. 第2天: 项目根目录创建 AGENTS.md（团队规范），CI 里加只读 review job
3. 第3天: deepagents skills create review  # 写第一个 skill
4. 第2周: deepagents init team-agent && deepagents deploy --config deepagents.toml
         （部署目前是 beta，先内网试跑）
5. 持续: 每周更新 AGENTS.md，积累 skills，月度复盘看效果指标
```

**核心原则**：AI 是团队的新成员，不是万能工具。给它 onboarding，给它 SOP，给它反馈回路。
