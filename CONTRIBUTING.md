# 参与开发

## 开发环境

开发工具（vitest、tsup）要求 Node.js 22.18+ 或 24.11+。打包产物的目标是 Node 18，运行时只要求 ≥ 18.17，CI 会在 18.17 上运行产物。

```bash
npm install
npm run dev -- domains --json   # 直接运行源码
npm test                        # vitest
npm run typecheck
npm run build                   # 产物在 dist/index.js
```

真实账号调试时把凭证写进项目根目录的 `.env`（已在 `.gitignore` 里）。

## 约定

- **零运行时依赖**：不引入云厂商 SDK，请求签名用 `node:crypto` 自己实现；commander 在打包时内联进产物。确实需要新依赖时，先开 issue 讨论。
- **输出契约**：`--json` 时成功在 stdout 输出一行 `{"ok":true,"data":…}`，失败在 stderr 输出一行 `{"ok":false,"status":"…","message":"…"}`；退出码 1 是接口失败，2 是参数错误（没调用任何云接口）。详见 README 的[输出约定](README.md#输出约定)。新增字段可以，改名、删字段属于不兼容变更。
- **以官方 API 定义为准**：字段名、时间格式（有的云返回不带时区的时间）、分页方式按官方 API 元数据或文档实现，不要照搬控制台的显示。
- **文档分层**：README 是给 AI agent 看的，只放维护流程、输出约定、命令速查和凭证。各云需要的权限写进 [docs/permissions.md](docs/permissions.md)，已知限制写进 [docs/limitations.md](docs/limitations.md)，都按云厂商分节。
- **测试不发真实请求**：用 `test/helpers.ts` 的 `fakeFetch` 按请求路由返回固定响应，没命中的请求返回 404，能直接看出漏了哪个接口。测试和代码里不要放真实凭证，也不要放云厂商文档里的示例密钥原文（会被 GitHub Push Protection 拦截）。

## 新增云服务 / DNS 服务商

- **云服务的域名查询**：在 `src/providers/<云>/` 下新建文件，实现 `DomainService`（`key`、`label`、`list`），加进该云 `index.ts` 的 `services`。逐个 bucket / 站点查询的服务，单项失败时调用 `warn` 并继续。
- **证书部署**：给服务加 `deployer`，接口和各方法的约束见 `src/providers/registry.ts` 的 `Deployer`。上传证书不是幂等操作，只发一次；重试前先重新查重。
- **新云厂商**：在 `src/types.ts`（`Provider`、`PROVIDERS`、`PROVIDER_LABEL`）、`src/lib/env.ts`（`ENV_FAMILIES`）、`src/query.ts`（`PROVIDER_DEFS`）注册，用 `defineProvider` 定义。
- **新 DNS 服务商**：在 `src/dns/` 下实现 `DnsProviderDef`（`listZones`、`addTxt`、`removeTxt`，约束见 `src/dns/types.ts` 的注释），注册到 `src/types.ts` 的 `DnsVendor` / `DNS_VENDORS` 和 `src/dns/index.ts` 的 `DNS_DEFS`。`removeTxt` 只能删自己添加的那个值。
- 同步更新 README 的服务表或凭证表、`docs/permissions.md`、`docs/limitations.md`。

## 提交

- 提交信息用 `类型(范围): 中文说明`，类型有 `feat`、`fix`、`docs`、`test`、`refactor`、`chore`，范围是命令或云厂商，如 `fix(tencent): …`、`feat(issue): …`。
- 提交 PR 前确认 `npm run typecheck && npm test && npm run build` 通过。改了云接口调用的，说明是否用真实账号验证过。

## 发布（维护者）

1. 改 `package.json` 和 `package-lock.json` 里的版本号，提交 `chore: 发布 x.y.z（主要变化）`。
2. 推送 `vX.Y.Z` tag。[Release 工作流](.github/workflows/release.yml)会校验 tag 与版本号一致，跑类型检查、测试和打包，暂存发布到 npm（Trusted Publishing），并创建 GitHub Release。
3. 在 npmjs.com 包页面的 Staged Packages 里批准，或执行 `npm stage approve <stage-id>`（需要 2FA、npm ≥ 11.15）。批准后版本才能安装。

## 许可证

提交的代码按 [GPL-3.0-only](LICENSE) 授权。
