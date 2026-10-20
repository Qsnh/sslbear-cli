---
name: sslbear-cli
description: 当用户要给域名申请 SSL / HTTPS 证书（Let's Encrypt 免费证书、泛域名证书），把证书部署、更新到云服务，续期 / 续签快到期或已过期的证书，查看哪些证书快到期，给域名开启 HTTPS，或设置证书自动续期时使用。覆盖阿里云、腾讯云、火山引擎、华为云、百度智能云、七牛云的 CDN、全站加速、EdgeOne、ESA、对象存储（OSS、COS、TOS、OBS）、直播、点播、图片服务；DNS 验证支持这几家云的云解析，以及 Cloudflare、AWS Route 53、Google Cloud DNS、Azure DNS、DigitalOcean、GoDaddy。证书熊 sslbear-cli。
---

# sslbear-cli：申请、部署、续期 SSL 证书

证书熊 CLI 有三条主要命令：`domains` 列出各云上的域名和证书到期时间；`issue` 向 Let's Encrypt 申请证书，自动添加、删除 DNS 验证记录；`deploy` 把一张证书部署到它覆盖的所有域名，可以跨云、跨服务。

## 调用

- 命令前缀是 `npx -y sslbear-cli@latest`，需要 Node.js ≥ 18.17。下文简写为 `sslbear-cli`。
- 每条命令都加 `--json`。成功时 stdout 输出一行 `{"ok":true,"data":…}`；失败时 stderr 输出一行 `{"ok":false,"status":…,"message":…}`。
  - exit 2：参数或凭证有误，没调用任何接口。按 `message` 改正后重跑。
  - exit 1：云接口或签发失败。
- 凭证自动从当前目录的 `.env` 加载，当前目录没有时加载 `~/.sslbear-cli/.env`。放在别处时，每条命令都加 `--env-file <路径>`。
- 带 `*` 的域名参数要加引号，如 `-d 'example.com,*.example.com'`。zsh 下不加引号会报 no matches found。
- `issue` 一般要 1~2 分钟，最长约 9 分钟。命令超时设到 10 分钟（600000 毫秒）或更长；工具的超时上限不够时，放到后台运行并等它结束。中途不要打断。
- 参数细节看 `sslbear-cli <命令> --help`。

## 开始前

先运行 `sslbear-cli env --json`：

- 要用的云，在 `data.providers[]` 里的 `state` 要是 `ok`。
- 域名所在的 DNS 服务商，在 `data.dns[]` 里的 `state` 也要是 `ok`。
- 有任何一家是 `incomplete`（只配了一半）时，命令会整条报错。

不满足时，先按 [references/setup.md](references/setup.md) 帮用户配好凭证。

## 按任务读

| 用户要做的事 | 读 |
| --- | --- |
| 首次使用、配置凭证、遇到权限报错 | [references/setup.md](references/setup.md) |
| 给域名申请新证书 | [references/issue.md](references/issue.md) |
| 部署证书、给域名开 HTTPS、换上用户自备的证书 | [references/deploy.md](references/deploy.md) |
| 检查哪些证书快到期、续期、设置自动续期 | [references/renew.md](references/renew.md) |

## 必须遵守

- 没有用户同意，不要加 `--force`。
  - `deploy --force` 会提前替换还没到期的证书。
  - `issue --force` 会重新签发，占用 Let's Encrypt 配额（同一组域名每周最多 5 张）。
- `deploy` 先加 `--dry-run` 看计划，由 agent 自己核对。计划和用户的要求一致就去掉 `--dry-run` 执行；超出用户要求的部分先收窄范围或问用户。
- 没开 HTTPS 的域名，只有用户要求给它开 HTTPS 时，才用 `deploy -d` 点名。点名就会开启 HTTPS。
- 用户只提到部分云或服务时，用 `-p` / `-s` 限定范围。
- `deploy` 结果里的 `message`、`needsConfirm: true`，以及 `issue` 结果里的 `cleaned: false`，都要转告用户。
- 能做的先做完，需要用户决定的事最后合并成一次提问。
- 凭证不要写进命令行参数，也不要明文出现在日志或回复里。
- 各命令会改什么：
  - `env`、`domains`、`certs` 是只读的。
  - `issue` 只临时添加、删除 `_acme-challenge` TXT 记录。
  - `deploy` 只改 HTTPS 证书，用 `-d` 点名没开 HTTPS 的域名时会打开 HTTPS 开关。它不动强制跳转、HTTP/2、TLS 版本等其他配置（个别服务首次开启 HTTPS 时会写入默认配置，见已知限制），也不删除云上的旧证书。

## 更多

- 各云需要的权限：<https://github.com/Qsnh/sslbear-cli/blob/main/docs/permissions.md>
- 各云的已知限制：<https://github.com/Qsnh/sslbear-cli/blob/main/docs/limitations.md>。结果与预期不符，或者出现 `unsupported`、`failed` 时，查对应云厂商那一节。
- 更新本 skill：运行 `npx -y sslbear-cli@latest skill install`。如果是用 `npx skills add` 装的，运行 `npx skills update`。
