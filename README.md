# hunt-lab

白名单内的狩猎自动化：**只打公开授权靶场，不扫任何自有资产，不扫任何第三方生产站点。**

## 它干什么

每周一次（也可手动触发），对 `config/targets.json` 里列出的**明确授权公开测试主机**做一轮只读侦察：

1. HTTP 探活：状态码、响应时间、标题、Server 指纹、缺失的安全响应头
2. nuclei 模板检测：只跑 `tech / exposure / misconfig` 三类，限定 info/low/medium，排除 intrusive / fuzz / dos / brute-force / default-login

结果写到 `data/latest.json` 与 `reports/YYYY-MM-DD.md`，由 Action 自动提交。

## 防封号/防滥用的硬约束

- **白名单硬门禁**：`hunt.mjs` 的 `assertAllowed()` 对每个目标校验，不在 `config/targets.json` 且 `authorized:true` 的主机直接 throw，跑不起来
- **限速**：`maxRps: 0.5`（每个目标之间隔 2s），nuclei `-rl 10 -c 3`
- **非侵入**：只用检测模板，不带 payload 攻击，不改数据、不爆破
- **低频**：每周一次，不是每小时
- **不加新目标就不会扫新目标**：要扩目标只能改配置，且必须是公开书面授权测试的目标

当前白名单：

| 主机 | 授权依据 |
|---|---|
| scanme.nmap.org | Nmap 官方公开扫描测试主机 |
| testphp.vulnweb.com | Acunetix 官方公开漏洞测试站（PHP） |
| testasp.vulnweb.com | Acunetix 官方公开漏洞测试站（ASP） |

## 你自己怎么改

- 加/删目标：改 `config/targets.json` 的 `targets` 数组，必须带 `authorized: true` 与 `why`
- 改频率：改 `.github/workflows/hunt.yml` 的 cron
- 本地跑：`node scripts/hunt.mjs`（没装 nuclei 就加 `--no-nuclei`）
