# 部署证书（deploy）

`deploy` 把一张证书部署到它覆盖的所有域名：

- 用证书的 SAN 精确匹配各云上的域名。`*.example.com` 只覆盖一级子域。
- 有的服务要用证书 ID 绑定，这时会先把证书上传到该云的证书服务；那里已有同一张证书时直接复用。

## 证书要求

- `issue` 签发的证书：直接用它输出的 `data.files.cert` 和 `data.files.key`。
- 用户自备的证书（证书熊、acme.sh、certbot 签的，或者买的），要满足三点：
  - 证书是 fullchain PEM，即叶子证书加中间证书链。
  - 私钥是 RSA 或 ECC，且没有加密。
  - 证书带 CN。多数云服务拒收没有 CN 的证书，Let's Encrypt 的 shortlived / tlsserver 配置文件签的证书就没有 CN。

## 步骤

1. **预览。** 运行 `sslbear-cli deploy --cert <fullchain.pem> --key <privkey.pem> --dry-run --json`。只输出计划，不上传证书，也不改任何配置。
   - 用户要给没开 HTTPS 的域名开启时，预览就带上 `-d <这些域名>`。
2. **核对计划。** agent 自己核对：`would_update` / `would_deploy` 的域名正是用户要动的，就继续执行。范围超出用户要求时，加 `-p`（云）、`-s`（服务）或 `-d`（域名）收窄，或者先问用户。
3. **执行。** 同一条命令去掉 `--dry-run`。
4. **处理结果。** 按下面的结果表逐条处理。需要用户决定的，合并成一次提问。
5. **核对。** 云上生效要十几秒到几分钟。稍后运行 `sslbear-cli domains -d <关键字> --json`，确认 `cert.notAfter` 已是新证书的到期时间。
   - `domains` 的 `-d` 是关键字过滤（也匹配证书的 CN 和 SAN），用 `example.com` 能一次查出它下面的所有域名。
   - 还是旧证书时，过几分钟再查。不要因此重跑 `deploy` 或加 `--force`。

不加 `--force` 时的规则：

- 域名已开 HTTPS，并且当前证书 30 天内到期（含已过期），就直接换成新证书。
- 其他情况会跳过，或者标记为需要用户确认。
- 已经是这张证书的域名会跳过，所以重复执行是安全的。

`-d` 是精确的域名列表，逗号分隔。加了 `-d` 就只处理点名的域名；点名的域名没开 HTTPS 时，会顺带开启。

`deploy` 只开启 HTTPS、绑定证书，不设置 HTTP 跳转 HTTPS（强制跳转）。用户要强制跳转时，请用户到对应云的控制台设置。

## 结果

`data.results[]` 里每一项对应一个域名：

| `action` / `reason` / `code` | agent 怎么做 |
| --- | --- |
| `deployed` / `updated` | 已开启 HTTPS 并部署 / 已替换旧证书。稍后核对 |
| `would_deploy` / `would_update` | `--dry-run` 给出的计划。去掉 `--dry-run` 执行 |
| `skipped`，且 `needsConfirm: true` | 需要用户决定，`reason` 有四种：`not_due` 当前证书还剩 30 天以上；`newer_current` 当前证书比新证书到期还晚；`same_expiry` 到期时间相同，但签发时间或算法不同；`unknown_expiry` 查不到当前证书的到期时间。把域名和 `message` 列给用户，问要不要提前替换。用户同意后，加 `-d <这些域名> --force` 重跑 |
| `skipped` `already_current` | 已经是这张证书，不用处理 |
| `skipped` `https_off` | 域名没开 HTTPS。用户要开时，用 `-d` 点名重跑 |
| `skipped` `platform_managed` | 云厂商的平台默认域名，证书由平台负责，不用处理 |
| `skipped` `unsupported` | 这个服务不支持用 CLI 部署。按 `message` 请用户去控制台操作 |
| `skipped` `shared_cert_blocked` | 证书挂在多条记录共用的配置上（阿里云 ESA 站点），同组有记录挡住了更新。按 `message` 里的放行方法处理后重跑 |
| `failed` `HttpsStateUnknown` | 查不到 HTTPS 现状，没做修改。稍后重跑；仍然失败的，多半缺读权限 |
| `failed` `HttpsAlreadyEnabled` / `HttpsDisabled` | 查询之后 HTTPS 状态变了，没做修改。重跑即可 |
| `failed` `DomainBusy` | 域名上一次的配置变更还在部署（通常几分钟），没做修改。过几分钟重跑 |
| `failed` `CertWithoutCommonName` | 这个服务不接受没有 CN 的证书。换一张带 CN 的，`issue` 签发的就带 CN |
| `failed` `DomainNotFound` / `NotCovered` | `-d` 点名的域名找不到，或者不在证书的 SAN 里。核对拼写 |
| `failed` 其他 `code` | 云接口返回的错误。`retryable: true` 时先原样重跑一次；否则把 `code`、`message`、`requestId` 报给用户。权限问题见 [setup.md](setup.md) |

有 `failed` 时 exit 1。这时 stderr 输出 `{"ok":false,"status":"DeployFailed",…}`，完整的 `results`、`uploads`、`issues` 都在这个对象的**顶层**，不在 `data` 下面。

`issues[]` 里：

- `kind: "error"` 表示某个服务查询失败，多半是缺权限。
- `kind: "inactive"` 表示服务没开通，可以忽略。
