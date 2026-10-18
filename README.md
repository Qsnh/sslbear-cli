# sslbear-cli

证书熊（[sslbear.com](https://sslbear.com)）CLI，主要给 AI agent 用。用户要查看、续期、更换或部署云服务域名的 SSL 证书时用它：一条命令查出各云上全部域名的证书和到期时间，再用一条命令把新证书部署到它覆盖的所有域名上（跨云、跨服务）。

- 运行：`npx sslbear-cli <命令>`，需 Node.js ≥ 18.17
- 覆盖：阿里云、腾讯云、火山引擎、华为云、百度智能云、七牛云的 CDN / 全站加速 / 边缘加速、对象存储、直播、点播、图片服务（见[服务表](#服务表)）
- 不签发证书：证书要另备（证书熊、acme.sh、certbot 等签发的 fullchain + 私钥）

## 维护流程

agent 调用一律加 `--json`，这样遇到需要确认的情况也不会停下来交互提问。用户只提到部分云或服务时，每条命令都加 `-p` / `-s` 限定范围。

1. **检查凭证**：`npx sslbear-cli env --json`。`data.providers[].state` 为 `ok` 的云会被查询，`missing` 的云会被跳过。只要有一家是 `incomplete`（只配了一半），后面的命令就会整条报错（exit 2），除非用 `-p` 把它排除；这时请用户补全或删掉这家的凭证（见[凭证](#凭证)）。
2. **找出快到期的域名**：`npx sslbear-cli domains -e 30 --json`。这条命令列出 30 天内到期的证书，已过期的也算在内；`data.items` 按 `daysLeft` 升序，`cert.sans` 是新证书需要覆盖的域名。
3. **准备新证书**：fullchain（叶子证书 + 中间证书链）和未加密的 RSA / ECC 私钥。多数服务拒收没有 CN 的证书：Let's Encrypt 的 classic 配置文件签发的证书有 CN，shortlived / tlsserver 配置文件签发的没有（见[已知限制·通用](docs/limitations.md#通用)）。一张证书只需部署一次，它覆盖的所有域名会被自动找出来。
4. **预览**：`npx sslbear-cli deploy --cert fullchain.pem --key privkey.pem --dry-run --json`。只输出计划，不上传证书，也不修改任何配置。
5. **执行**：同一条命令去掉 `--dry-run`。
6. **处理结果**：按[处理 deploy 结果](#处理-deploy-结果)一节逐条处理。需要用户拍板的事项合并成一次提问。
7. **核对**：云接口受理就返回，边缘生效要十几秒到几分钟。稍后执行 `domains -d <关键字> --json`，确认 `cert.notAfter` 已更新。

自动替换的规则：域名已开 HTTPS，并且当前证书 30 天内到期（含已过期），就直接换成新证书。其他情况会跳过，或者标记为需要确认。

必须遵守：

- `domains`、`certs`、`env` 是只读命令。`deploy` 会修改线上配置，但只改 HTTPS 证书，不动 HTTP/2、强制跳转、TLS 版本、HSTS 等其他配置，也不删除证书服务里的旧证书。例外情况：首次开启 HTTPS 时，个别服务会写入默认配置；阿里云 ESA 会原地替换站点上的证书（详见[已知限制](docs/limitations.md)）。
- 没经过用户同意，不要加 `--force`。
- 没开 HTTPS 的域名默认不会被处理。用 `deploy -d` 点名会顺带为它开启 HTTPS，所以只在用户要求给这个域名开 HTTPS 时才点名。
- 重复执行是安全的：已经是这张证书的域名会被跳过。
- 凭证不要明文写进命令行参数、日志或回复里。

## 输出约定

- 成功时，stdout 输出一行 `{"ok":true,"data":…}`。失败时，stderr 输出一行 `{"ok":false,"status":"…","message":"…"}`。
- 退出码：
  - `0`：成功。
    - `domains` / `certs` 只有部分服务失败时也返回 0，失败的服务记在 `issues` 里。
    - `deploy` 只要没有 `failed` 的结果就返回 0。
  - `1`：有两种情况。
    - 所有查询都失败，比如凭证无效、网络不通。
    - `deploy` 有域名失败（`--dry-run` 也一样）。这时 `status` 是 `"DeployFailed"`，stderr 里的这个对象**在顶层**带完整的 `results`、`uploads`、`issues`，不在 `data` 下面。
  - `2`：没有调用任何云接口，也没做任何修改。按 `message` 修正后重跑。可能的原因：
    - 参数错误
    - 证书文件不合格：链不全、私钥与证书不匹配、证书不在有效期内、私钥加密了
    - 凭证没配或配得不完整
- 时间一律是 ISO 8601（UTC）。`daysLeft` 是剩余天数，负数表示已过期。

### domains / certs

```json
{"ok":true,"data":{"items":[{"provider":"aliyun","service":"oss","domain":"img.example.com","status":"Enabled","https":true,"cert":{"id":"12345-cn-hangzhou","notAfter":"2026-11-02T10:14:51.000Z","status":"Enabled"},"daysLeft":15,"extra":{"bucket":"static-prod","region":"cn-shanghai"}}],"issues":[{"provider":"aliyun","service":"dcdn","kind":"inactive","code":"DcdnServiceNotFound","message":"…"}]}}
```

- `cert` 可能包含这些字段：`id`、`name`、`commonName`、`sans`、`issuer`、`notBefore`、`notAfter`、`status`、`algorithm`。只输出该云服务实际返回的字段。
- 双证书域名（RSA + ECC，或国际 + 国密）另有 `certs[]` 列出全部证书，这时 `cert` 是其中先到期的那张。
- `extra.managed: "platform"` 表示云厂商的平台默认域名。这类域名的证书由平台负责，没有 `cert` 字段，也不用管。
- `issues[].kind` 有两种：
  - `inactive`：服务没开通或没有资源，可以忽略。
  - `error`：调用失败，带 `code`，有时带 `requestId`；多数是缺权限，见[所需权限](docs/permissions.md)。对于逐个 bucket / 站点 / 应用查询的服务，`target` 标出失败的那一项，其余项照常返回。
- `certs` 命令返回各云证书服务里的证书。`items[]` 的字段与 `cert` 相同，另外有 `provider`、`daysLeft`、`source`。

### 处理 deploy 结果

```json
{"ok":true,"data":{"dryRun":false,"cert":{"commonName":"example.com","sans":["example.com","*.example.com"],"notAfter":"2027-01-15T00:00:00.000Z","algorithm":"RSA","fingerprint":"…"},"uploads":[{"provider":"aliyun","certId":"12345","reused":false}],"results":[{"provider":"aliyun","service":"cdn","domain":"static.example.com","action":"updated","before":{"notAfter":"2026-11-02T10:00:00.000Z","daysLeft":15},"after":{"id":"12345","notAfter":"2027-01-15T00:00:00.000Z"}},{"provider":"tencent","service":"cdn","domain":"www.example.com","action":"skipped","reason":"not_due","needsConfirm":true,"message":"…"}],"issues":[]}}
```

`results[]` 里每一项对应一个被证书覆盖的域名。用了 `-d` 时只列出点名的域名。任何结果只要带 `message`，都要转告用户。

| `action` / `reason` / `code` | 含义 | agent 怎么做 |
| --- | --- | --- |
| `deployed` / `updated` | 已为域名开启 HTTPS 并部署证书 / 已替换旧证书 | 完成，稍后核对 |
| `would_deploy` / `would_update` | `--dry-run` 给出的计划 | 去掉 `--dry-run` 执行 |
| `skipped` 且 `needsConfirm: true` | 需要用户决定。reason 有四种：`not_due` 当前证书还剩 30 天以上；`newer_current` 当前证书比新证书到期还晚；`same_expiry` 到期时间相同，但签发时间或算法不同；`unknown_expiry` 查不到当前证书的到期时间 | 把域名和 `message` 列给用户。用户同意后加 `-d <这些域名> --force` 重跑。证书没有 CN 时，部分服务加 `--force` 后仍会报 `CertWithoutCommonName` |
| `skipped` `already_current` | 域名上已经是这张证书 | 不用处理。如果查不到当前证书的算法，同时签发的 RSA 和 ECC 证书分不出来，用户坚持要换时，用 `-d` 点名并加 `--force` |
| `skipped` `https_off` | 域名没开 HTTPS | 用户要开时，用 `-d` 点名重跑 |
| `skipped` `platform_managed` | 平台默认域名 | 不用处理 |
| `skipped` `unsupported` | 该服务或记录不支持用 CLI 部署 | 按 `message` 告诉用户去控制台操作 |
| `skipped` `shared_cert_blocked` | 证书挂在多条记录共享的配置上（阿里云 ESA 站点），同组有记录挡住了更新 | 按 `message` 里的放行方法处理后重跑 |
| `failed` `HttpsStateUnknown` | 查不到该域名的 HTTPS 配置，没法判断现状，没做修改 | 稍后重跑原命令。仍失败时，多半是缺读权限，见[所需权限](docs/permissions.md) |
| `failed` `HttpsAlreadyEnabled` / `HttpsDisabled` | 写入前发现 HTTPS 状态与查询时不同，没做修改 | 重跑原命令 |
| `failed` `CertWithoutCommonName` | 该服务不接受没有 CN 的证书，没做修改 | 换一张带 CN 的证书 |
| `failed` `DomainNotFound` / `NotCovered` | `-d` 点名的域名找不到，或者不在证书覆盖范围内 | 检查拼写，对照证书的 SAN |
| `failed` 其他 `code` | 云接口返回的错误。`retryable: true` 表示可以原样重试 | 可重试的先重跑一次。其余把 `code`、`message`、`requestId` 报给用户；权限问题见[所需权限](docs/permissions.md)，其他情况查[已知限制](docs/limitations.md)里对应的云厂商 |

## 命令速查

```
domains  [-p 云] [-s 服务] [-d 关键字] [-e 天数] [--timeout ms]   域名及其证书（只读）
certs    [-p 云] [-d 关键字] [-e 天数] [--timeout ms]             证书服务里的证书（只读）
deploy   --cert <fullchain.pem> --key <privkey.pem> [-p 云] [-s 服务] [-d 域名,...] [--force] [--dry-run] [--timeout ms]
env                                                               凭证配置检查（ID 脱敏，Secret 只显示是否已设置）
所有命令都支持：--json  --env-file <path>；--timeout 是单个请求的超时，默认 15000
```

- `-p` 和 `-s` 都可以用逗号分隔多个值。不传 `-p` 时，查询所有已配置凭证的云。
- `domains` / `certs` 的 `-d` 是关键字过滤，也会匹配证书的 CN 和 SAN；`deploy` 的 `-d` 是精确的域名列表，逗号分隔，可以重复传。
- `deploy` 按证书 SAN 精确匹配域名。`*.example.com` 只覆盖一级子域，不包括 `example.com` 本身。
- 需要证书 ID 才能绑定的服务，会先把证书上传到该云的证书服务。每次运行每家云最多上传一次；证书服务里已有同一张证书时直接复用。新上传的证书名形如 `sslbear-example.com-20270101`。
- 人在终端里运行 `deploy` 且不加 `--json` 时，CLI 会逐个询问需要确认的域名，回答 `y` 相当于加了 `--force`。
- 完整规则见 `npx sslbear-cli <命令> --help`。

### 服务表

| `-p` | `-s`（`domains` / `deploy`） | `certs` 查询的证书服务 |
| --- | --- | --- |
| `aliyun` | `cdn`、`dcdn`（全站加速）、`esa`（边缘安全加速）、`oss`、`live`（直播）、`vod`（点播） | 数字证书管理服务 |
| `tencent` | `cdn`、`teo`（EdgeOne）、`cos`、`live`、`vod` | SSL 证书 |
| `volcengine` | `cdn`、`dcdn`、`tos`、`vod`、`live`、`imagex`（veImageX） | 证书中心（只含已签发的证书） |
| `huawei` | `cdn`、`live`、`obs` | 云证书管理 CCM（含上传的证书，以及过期不满 3 年的证书） |
| `baidu` | `cdn` | 证书管理 |
| `qiniu` | `cdn`（含全站加速） | SSL 证书（CDN 和 SSL 证书服务共用） |

## 凭证

凭证从环境变量读取。当前目录有 `.env` 文件时会自动加载，也可以用 `--env-file` 指定。只需配置要用的云。

| 云 | 必填 | 可选（临时凭证） |
| --- | --- | --- |
| aliyun | `ALIBABA_CLOUD_ACCESS_KEY_ID`、`ALIBABA_CLOUD_ACCESS_KEY_SECRET`（别名 `ALIYUN_ACCESS_KEY_ID` / `ALIYUN_ACCESS_KEY_SECRET`） | `ALIBABA_CLOUD_SECURITY_TOKEN` |
| tencent | `TENCENTCLOUD_SECRET_ID`、`TENCENTCLOUD_SECRET_KEY` | `TENCENTCLOUD_SESSION_TOKEN` |
| volcengine | `VOLCENGINE_ACCESS_KEY`、`VOLCENGINE_SECRET_KEY` | `VOLCENGINE_SESSION_TOKEN` |
| huawei | `HUAWEICLOUD_SDK_AK`、`HUAWEICLOUD_SDK_SK`（别名 `HW_ACCESS_KEY` / `HW_SECRET_KEY`） | `HUAWEICLOUD_SDK_SECURITY_TOKEN`（别名 `HW_SECURITY_TOKEN`） |
| baidu | `BAIDUCLOUD_ACCESS_KEY`、`BAIDUCLOUD_SECRET_KEY` | `BAIDUCLOUD_SESSION_TOKEN` |
| qiniu | `QINIU_ACCESS_KEY`、`QINIU_SECRET_KEY` | — |

- shell 里已设置的变量优先。只要 shell 里设置了某家云的任意一个凭证变量，`.env` 里这家云的凭证就会整组忽略，两处的值不会拼在一起用。
- 建议使用子账号（阿里云 RAM、腾讯云 CAM，其他云的 IAM）。只做查询时授予只读权限即可；要用 `deploy` 再加写权限，见[所需权限](docs/permissions.md)。

## 按需查阅

- [docs/permissions.md](docs/permissions.md)：各云需要的只读权限和写权限。`issues` 或 `failed` 里出现权限错误时看。
- [docs/limitations.md](docs/limitations.md)：各云服务的已知限制，按云厂商分节。结果和预期不一致，或者遇到 `unsupported`、`failed` 时，看对应云厂商那一节。

## 开发

```bash
npm install && npm test && npm run typecheck && npm run build   # 产物在 dist/index.js
```
