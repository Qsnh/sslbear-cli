# 设计：用 ACME 申请证书并自动设置 DNS（`sslbear-cli issue`）

2026-10-18

## 为什么做

`deploy` 要求使用者自己备好证书。用户希望 sslbear-cli 自己能向 Let's Encrypt 申请证书：DNS-01 验证所需的 TXT 记录由 CLI 调 DNS 服务商的接口自动添加、验证完自动删除。这样 agent 用两条命令（`issue` → `deploy`）就能完成「申请 + 部署」。

## 目标

- 一条命令签发证书：`issue -d example.com,*.example.com`，产出 fullchain + 私钥两个文件，直接喂给 `deploy --cert --key`。
- 自动找出每个域名由哪家 DNS 服务商解析，自动添加 / 删除 `_acme-challenge` TXT 记录。
- 主要调用方是 AI：参数一次传完、不交互；`--json` 结果能让 agent 判断成功、失败原因、能否重试；重复执行安全（不浪费 Let's Encrypt 配额）。
- 零运行时依赖：ACME、JWS、CSR、各服务商签名全部用 `node:crypto` 手写。

## 不做

- Let's Encrypt 以外的 CA（ZeroSSL、Google 等需要 EAB 的），以后再说。
- HTTP-01 / TLS-ALPN-01 验证；IP 证书。
- `_acme-challenge` 已 CNAME 到别的域名（DNS 别名模式）：不支持，遇到时服务商接口会因 CNAME 冲突报错，报错里说明原因。
- 吊销证书、定时自动续期（续期由 agent 按 `domains -e 30` 的结果触发）。
- Namecheap（接口每次整体覆盖全部解析记录，出错会清空用户的解析，且要 IP 白名单）、西部数码、DNS.LA 等：以后按需加。

## 绝不能发生（反目标）

- 删除或修改不是本次添加的 DNS 记录（同名下别的 TXT 值、别的记录类型都不能动）。
- 本次添加的 TXT 记录在命令结束后残留而不告诉用户（删除失败必须在结果里列出来，让用户手动删）。
- 私钥出现在任何输出、日志、错误信息里；私钥文件权限不是 600。
- `--staging` 签出的测试证书覆盖正式证书文件。

## 用户已定（2026-10-18）

1. DNS 服务商 11 家：阿里云云解析、腾讯云 DNSPod、火山引擎云解析、华为云云解析、百度智能云 DNS（复用各自云的凭证）；Cloudflare、AWS Route 53、Google Cloud DNS、Azure DNS、DigitalOcean、GoDaddy（新增凭证变量）。七牛没有 DNS 服务。
2. 证书默认保存在 `~/.sslbear-cli/certs/<目录名>/`，`--out` 可改。不放当前目录，避免私钥被提交进 git。
3. 默认 RSA 2048，`--key-type ecc` 为 ECDSA P-256。
4. 保存位置已有覆盖同一组域名、同算法、剩余 30 天以上的证书时直接复用（`reused: true`），`--force` 才重签。续签时带 ARI `replaces`。
5. 只支持 Let's Encrypt，`--staging` 用测试环境。

## 命令

```
sslbear-cli issue -d <域名,...> [选项]
  -d, --domain <list>      要签发的域名，逗号分隔、可重复；支持泛域名 *.example.com（只覆盖一级子域，不含 example.com 本身）。必填，最多 100 个
      --key-type <type>    rsa（默认，RSA 2048）或 ecc（ECDSA P-256）
      --out <dir>          证书保存目录（写 fullchain.pem、privkey.pem）；默认 ~/.sslbear-cli/certs/<目录名>/
      --dns <list>         只在这些 DNS 服务商里查找域名，逗号分隔（aliyun, tencent, volcengine, huawei, baidu, cloudflare, aws, google, azure, digitalocean, godaddy）；默认所有已配置凭证的
      --email <email>      ACME 账号联系邮箱（可选；Let's Encrypt 已不发到期提醒邮件）
      --staging            使用 Let's Encrypt 测试环境（证书不受浏览器信任，用于演练）
      --force              已有可复用的证书也重新签发
      --dry-run            只检查凭证、找出每个域名由哪家 DNS 解析，不申请证书、不改 DNS
      --dns-timeout <秒>   等待 TXT 记录在权威 DNS 上生效的最长时间，默认 300
      --timeout <ms> --json --env-file <path>   同其他命令
```

- 主域名：层级最少的域名（泛域名按去掉 `*.` 后算），同级时非泛域名优先、再按字母序；与 `-d` 的顺序无关，作证书 CN，也决定目录名。
- 目录名：主域名（`*` 换成 `_`）+ `_rsa` / `_ecc`，测试环境再加 `_staging`。如 `*.example.com` 的 ECC 证书在 `~/.sslbear-cli/certs/_.example.com_ecc/`。
- 状态目录根：`~/.sslbear-cli`，环境变量 `SSLBEAR_CLI_HOME` 可改（CI / 测试用）。
- 第一次运行自动注册 ACME 账号（等于同意 Let's Encrypt 订阅协议，README 写明），账号私钥（ECDSA P-256）存在 `<根>/acme/<CA 主机名>/account.pem`（600），以后复用。

## 执行流程

1. **校验参数**（失败 exit 2，不调用任何接口）：域名合法（小写化、去结尾点、IDN 转 punycode；泛域名只允许最左侧一个 `*.`；不接受 IP）；去重；不超过 100 个；`--dns` 取值合法且已配置凭证（显式指定却没配置 / 配置不完整 → exit 2）；默认模式下一家都没配置 → exit 2，提示各家需要的变量。默认模式下凭证配置不完整的服务商跳过，记进 `issues`（不像其他命令那样整条报错：DNS 类变量常被其他工具共用，如 AZURE_*、AWS_*）。
2. **复用检查**（不联网）：保存目录里 `fullchain.pem` + `privkey.pem` 能通过 `loadLocalCert` 校验，域名集合与本次完全相同（不计顺序），算法相同，正式 / 测试环境相同（看签发者 CN 是否含 `STAGING`），且距到期超过 30 天 → 直接返回 `reused: true`（`--dry-run` 也一样）。`--force` 跳过这一步。
3. **查找 zone**：并行列出所选服务商的全部公网 zone。每个域名（泛域名去掉 `*.`）取最长后缀匹配的 zone；
   - 多家服务商都托管了这个最长 zone：查该 zone 实际的 NS 记录，与各家接口返回的 NS（没有就用该家的 NS 主机名规则）比对，只有一家匹配就用它；否则 `ZoneAmbiguous`，提示用 `--dns` 指定。
   - 找不到：`ZoneNotFound`，`message` 列出查过的服务商，`issues` 带上列 zone 失败的服务商（多半是缺权限）。
4. `--dry-run` 到此为止，输出每个域名用哪家、哪个 zone、要加的记录名。
5. **下单**：加载 / 创建账号，`newAccount`；`newOrder`：CA 目录里有 `classic` 配置文件就显式指定（保证证书带 CN，国内多数云服务拒收无 CN 证书）；保存目录里有旧证书（同正式 / 测试环境）且 CA 支持 ARI 时带 `replaces`，带 `replaces` 下单失败就去掉它重试一次。
6. **设置 DNS**：对每个 pending 授权取 dns-01 质询，记录 `_acme-challenge.<授权域名>` = `dnsTxtValue(token)`；已是 valid 的授权（CA 复用了近期的验证）跳过。所有 TXT 记录**串行**添加（同名记录集的读改写不能并发）。任何一条添加失败 → `DnsRecordFailed`，删除已加的，退出。
7. **等待生效**：查 zone 的权威 NS（系统解析器查 NS 记录，再解析 NS 的 IP），每 5 秒直接向每个权威服务器查询 TXT，全部权威服务器都看到全部值后，再等 10 秒（Let's Encrypt 多地验证，anycast 节点同步有延迟）。超过 `--dns-timeout` → `DnsPropagationTimeout`（可重试）；message 里说明域名实际的 NS 与服务商是否一致。所有权威服务器都连不上（网络环境限制）→ 退化为固定等待 30 秒后继续。
8. **验证**：逐个通知质询，轮询授权直到 valid；invalid → `AcmeChallengeFailed`，带 CA 给的原因。
9. **清理**：无论成功失败，第 6 步加过的记录都在退出前逐条删除（只删本次加的那个值）。删除失败不影响签发结果，但在 `dns[].cleaned: false` 和 `message` 里写明，让用户手动删。
10. **签发**：生成证书私钥（RSA 2048 / P-256），CSR 的 CN 为主域名（超过 64 个字符则不设 CN），SAN 为全部域名；`finalize` 并轮询订单直到 valid；下载证书链，用 `loadLocalCert` 校验（链、私钥匹配、有效期），再写文件：目录 700，先写临时文件再改名，`privkey.pem` 600、`fullchain.pem` 644。
11. **输出**。

人在终端运行（不加 `--json`）时，每一步在 stderr 打一行进度（「已在 阿里云云解析 添加 _acme-challenge.example.com」「等待 DNS 生效…」）；`--json` 时 stderr 不输出进度，只在失败时输出一行错误 JSON。

## 输出契约

成功（exit 0），stdout 一行：

```json
{"ok":true,"data":{
  "reused":false,"staging":false,
  "files":{"cert":"/Users/x/.sslbear-cli/certs/example.com_rsa/fullchain.pem","key":"/Users/x/.sslbear-cli/certs/example.com_rsa/privkey.pem"},
  "cert":{"commonName":"example.com","sans":["example.com","*.example.com"],"notBefore":"…","notAfter":"…","algorithm":"RSA","fingerprint":"…","issuer":"R12"},
  "dns":[{"domain":"*.example.com","provider":"aliyun","zone":"example.com","record":"_acme-challenge.example.com","cleaned":true}],
  "issues":[]
}}
```

- `files.cert` / `files.key` 是绝对路径，直接用作 `deploy --cert` / `--key`。
- `cert` 字段与 `deploy` 输出的 `cert` 相同。
- `dns[]` 每个需要验证的域名一项；授权已有效、没加记录的域名不列。`cleaned: false` 带 `message`（删除失败的原因），要转告用户手动删除。复用时 `dns` 为空数组。
- `--dry-run`：`{"dryRun":true,"reused":…,"staging":…,"files":{…},"dns":[{"domain","provider","zone","record"}],"issues":[]}`，复用时带 `cert`。
- `issues[]`：列 zone 失败、凭证不完整被跳过的服务商，`{provider, kind:"error", code, message, requestId?}`。

失败：stderr 一行 `{"ok":false,"status":"…","message":"…","retryable":…, …}`，带上已知的 `dns`、`issues`。

| status | exit | 含义 | 附加字段 |
| --- | --- | --- | --- |
| `UsageError` | 2 | 参数、凭证配置错误，未调用任何接口 | |
| `ZoneNotFound` | 1 | 域名不在任何所选服务商的 zone 里 | `domains`、`issues` |
| `ZoneAmbiguous` | 1 | 多家服务商都托管了这个 zone，无法按 NS 判定 | `domain`、`providers` |
| `DnsRecordFailed` | 1 | 添加 TXT 记录失败（多半缺写权限），已加的已清理 | `provider`、`code`、`requestId`、`retryable` |
| `DnsPropagationTimeout` | 1 | 超时仍未在权威 DNS 上看到 TXT 记录 | `retryable: true` |
| `AcmeChallengeFailed` | 1 | CA 验证失败 | `domain`、`acmeType`、`detail` |
| `AcmeRateLimited` | 1 | 触发 Let's Encrypt 频率限制 | `retryAfter`（秒，有的话） |
| `AcmeError` | 1 | 其他 ACME 错误（含网络错误） | `acmeType`、`retryable` |

## 代码结构

```
src/dns/types.ts        DnsProviderDef 接口、DnsZone、TxtRecord、relativeName
src/dns/env.ts          凭证：familyEnv（复用云厂商名族）、varsEnv（DNS 专用服务商的变量清单）
src/dns/index.ts        DNS_DEFS 注册表
src/dns/<vendor>.ts     11 个适配器（aws-sign.ts、google-auth.ts 等辅助文件同目录）
src/issue/types.ts      ACME 接口约定、AcmeError、Let's Encrypt 目录地址
src/issue/acme.ts       ACME 客户端（JWS ES256、nonce、轮询、problem document）
src/issue/asn1.ts       最小 DER 编码 / 解析
src/issue/csr.ts        生成证书私钥、PKCS#10 CSR、ARI 证书标识
src/issue/domains.ts    域名校验与规范化、目录名
src/issue/zones.ts      zone 查找（最长后缀、NS 判定）
src/issue/propagation.ts 权威 DNS 生效检查（DnsLookup 可注入）
src/issue/store.ts      状态目录、账号私钥、证书文件读写、复用检查
src/issue/run.ts        编排
src/issue/render.ts     表格 / 进度输出
```

- `CloudApiError.provider` 放宽为 `Vendor`（云厂商 ∪ DNS 服务商）。
- `env` 命令输出增加 `dns[]`：11 家 DNS 服务商各自的 `{provider, state, keys}`。
- `.env` 整组屏蔽规则扩展到 DNS 专用服务商的变量。
- `Deps` 增加 `home`（用户主目录，测试注入临时目录）与 `dnsLookup`（测试注入假的权威 DNS 查询）。

## 安全

- 证书私钥、账号私钥只写进 600 的文件，不打印；错误信息不带请求体。
- 各服务商只用 TXT 记录的增删查接口；README / docs/permissions.md 写明各家最小权限（如阿里云 `AliyunDNSFullAccess` 或自定义 `alidns:AddDomainRecord/DeleteDomainRecord/DescribeDomains/DescribeSubDomainRecords`；Cloudflare token 需 Zone.DNS:Edit + Zone.Zone:Read）。

## 验收

- 单元测试：域名校验、zone 最长匹配与 NS 判定、复用检查、ACME 客户端（假 CA）、CSR（用 openssl 解析校验）、ARI 标识（RFC 9773 示例）、11 个适配器的请求构造与翻页 / 重复记录 / 同名多值（fakeFetch）、编排流程与清理（假 DNS + 假 CA）、输出契约与退出码。
- 真实环境：阿里云云解析 + Let's Encrypt staging，再正式签一张 `sslbear-test.luoxuan.xyz` + `*.sslbear-test.luoxuan.xyz`，确认 TXT 记录已清理，再用 `deploy --dry-run` 验证产物能直接用。其他 10 家没有测试账号，只做 mock 测试，docs/limitations.md 注明「未经真实账号验证」。
