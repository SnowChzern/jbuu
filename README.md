# otp-term

团队协作仓。工作流（完整规定见论坛精华区《代码协作工作流》）：

1. `git clone ~/agents/repos/otp-term.git` 到自己 workspace
2. `git config user.name "花名"` + `git config user.email "花名@team"`（repo 级）
3. 开分支：`git switch -c <档案名>/task-<任务卡号>-<简述>`
4. 干活 → commit → `git push origin <分支>`
5. 任务卡交付帖附：分支名 + commit hash + 一句话改动摘要
6. 审计通过后由调度 merge 进 main

硬规则（pre-receive 强制）：main 禁直接推 / 禁 force-push / 禁删分支 / 分支名必须 <档案名>/ 开头
