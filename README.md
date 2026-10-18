# sslbear-cli

证书熊（[sslbear.com](https://sslbear.com)）命令行工具：一条命令查出阿里云、腾讯云、火山引擎、华为云、百度智能云、七牛云各云服务上配置的域名，以及每个域名当前绑定的 SSL 证书和到期时间；也可以把手上的证书一键部署到这些域名上，或替换快到期的旧证书。

- 零安装：`npx sslbear-cli ...` 即可运行（Node.js ≥ 18.17），发布包不带任何运行时依赖
- `domains` / `certs` / `env` 只读，只调用查询类接口；`deploy` 会修改云上的 HTTPS 证书配置（可先 `--dry-run` 预览）
- 面向 AI agent 设计：参数一次传完，`--json` 输出结构化结果，需要用户拍板的操作会明确标出
- 凭证从环境变量读取，也支持当前目录的 `.env` 文件

## 快速开始

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI...
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=...
export TENCENTCLOUD_SECRET_ID=AKID...
export TENCENTCLOUD_SECRET_KEY=...
# 火山引擎、华为云、百度智能云、七牛云的变量名见下文「配置」，只配置用到的云厂商即可

npx sslbear-cli env                      # 检查凭证配置
npx sslbear-cli domains                  # 所有云服务域名及证书，按剩余天数升序
npx sslbear-cli domains -e 30            # 只看 30 天内到期（含已过期）的
npx sslbear-cli certs                    # 证书服务里的证书列表
npx sslbear-cli deploy --cert fullchain.pem --key privkey.pem --dry-run   # 预览证书会部署 / 更新到哪些域名
```

输出示例：

```
云厂商  服务          域名               HTTPS  证书               到期时间    剩余天数
腾讯云  CDN           static.example.cn  开启   static-cert        2026-10-12  已过期 3 天
阿里云  对象存储 OSS  img.example.com    开启   12345-cn-hangzhou  2026-11-02  18
阿里云  CDN           api.example.com    开启   api-2026           2027-01-12  89
腾讯云  EdgeOne       www.example.io     关闭   -                  -           -

共 4 个域名，1 个证书已过期，1 个 30 天内到期，1 个未开启 HTTPS
提示：aliyun/dcdn 未开通或无资源（DcdnServiceNotFound）
```

表格里的到期时间按本机时区显示。

## 配置

| 环境变量 | 说明 |
| --- | --- |
| `ALIBABA_CLOUD_ACCESS_KEY_ID` | 阿里云 AccessKey ID（别名 `ALIYUN_ACCESS_KEY_ID`） |
| `ALIBABA_CLOUD_ACCESS_KEY_SECRET` | 阿里云 AccessKey Secret（别名 `ALIYUN_ACCESS_KEY_SECRET`） |
| `ALIBABA_CLOUD_SECURITY_TOKEN` | 可选，使用 STS 临时凭证时设置 |
| `TENCENTCLOUD_SECRET_ID` | 腾讯云 SecretId |
| `TENCENTCLOUD_SECRET_KEY` | 腾讯云 SecretKey |
| `TENCENTCLOUD_SESSION_TOKEN` | 可选，使用临时凭证时设置 |
| `VOLCENGINE_ACCESS_KEY` | 火山引擎 Access Key ID |
| `VOLCENGINE_SECRET_KEY` | 火山引擎 Secret Access Key |
| `VOLCENGINE_SESSION_TOKEN` | 可选，使用 STS 临时凭证时设置 |
| `HUAWEICLOUD_SDK_AK` | 华为云 AK（别名 `HW_ACCESS_KEY`） |
| `HUAWEICLOUD_SDK_SK` | 华为云 SK（别名 `HW_SECRET_KEY`） |
| `HUAWEICLOUD_SDK_SECURITY_TOKEN` | 可选，使用临时凭证时设置（别名 `HW_SECURITY_TOKEN`） |
| `BAIDUCLOUD_ACCESS_KEY` | 百度智能云 Access Key |
| `BAIDUCLOUD_SECRET_KEY` | 百度智能云 Secret Key |
| `BAIDUCLOUD_SESSION_TOKEN` | 可选，使用 STS 临时凭证时设置 |
| `QINIU_ACCESS_KEY` | 七牛云 AccessKey |
| `QINIU_SECRET_KEY` | 七牛云 SecretKey |

- 只配置了一家云厂商也可以，命令默认只查已配置凭证的云厂商。
- 当前目录有 `.env` 时会自动加载；`--env-file <path>` 可指定其他文件。shell 里已设置的变量优先：只要 shell 里设置了某家云厂商的任一凭证变量，`.env` 里这家的凭证就整组忽略，不会把两处的 ID、Secret 拼成一组。
- 建议用子账号 / 子用户（阿里云 RAM、腾讯云 CAM、火山引擎 IAM、华为云 IAM、百度智能云 IAM、七牛云 IAM）。只查询时只授予只读权限；要用 `deploy` 再加上对应的写权限（见下文「所需权限」）。

## 命令

### `domains`：云服务域名及其证书

```
sslbear-cli domains [选项]
  -p, --provider <list>         只查指定云厂商：aliyun, tencent, volcengine, huawei, baidu, qiniu
  -s, --service <list>          只查指定服务，见下表
  -d, --domain <keyword>        按域名关键字过滤（同时匹配证书的通用名和 SAN）
  -e, --expiring-within <days>  只看 N 天内到期（含已过期）的证书
      --timeout <ms>            单个请求超时，默认 15000
      --json                    输出单行 JSON
      --env-file <path>         从指定文件加载环境变量
```

| 云厂商 | `--service` | 云服务 |
| --- | --- | --- |
| aliyun | `cdn` | CDN |
| aliyun | `dcdn` | 全站加速 DCDN |
| aliyun | `esa` | 边缘安全加速 ESA（站点下开启代理加速的记录、SaaS 域名） |
| aliyun | `oss` | 对象存储 OSS（自定义域名） |
| aliyun | `live` | 视频直播 |
| aliyun | `vod` | 视频点播 |
| tencent | `cdn` | CDN |
| tencent | `teo` | EdgeOne |
| tencent | `cos` | 对象存储 COS（自定义源站域名） |
| tencent | `live` | 云直播 |
| tencent | `vod` | 云点播 |
| volcengine | `cdn` | CDN |
| volcengine | `dcdn` | 全站加速 DCDN |
| volcengine | `tos` | 对象存储 TOS（自定义域名） |
| volcengine | `vod` | 视频点播（华北、亚太东南-柔佛） |
| volcengine | `live` | 视频直播 |
| volcengine | `imagex` | veImageX（华北、亚太东南-柔佛） |
| huawei | `cdn` | CDN |
| huawei | `live` | 视频直播 |
| huawei | `obs` | 对象存储 OBS（自定义域名） |
| baidu | `cdn` | CDN |
| qiniu | `cdn` | CDN（含全站加速域名） |

### `certs`：证书服务里的证书

列出各云厂商证书服务中的证书，同样支持 `-p`、`-d`、`-e`、`--json`：

| 云厂商 | 证书服务 |
| --- | --- |
| aliyun | 数字证书管理服务（SSL 证书） |
| tencent | SSL 证书 |
| volcengine | 证书中心（已签发的 SSL 证书） |
| huawei | 云证书管理服务 CCM（SSL 证书，含上传的证书和过期 3 年内的证书） |
| baidu | 证书管理 |
| qiniu | SSL 证书（CDN 与 SSL 证书服务共用） |

### `deploy`：部署 / 更新证书

把本地证书部署到云服务上被它覆盖的域名，或替换这些域名上快到期的旧证书。只改 HTTPS 证书相关配置，不动 HTTP/2、强制跳转、TLS 版本、HSTS 等其他配置，不删除旧证书。

```
sslbear-cli deploy --cert <fullchain.pem> --key <privkey.pem> [选项]
      --cert <path>            证书文件（PEM，叶子证书 + 中间证书链）
      --key <path>             私钥文件（PEM，RSA 或 ECC，不支持加密私钥）
  -p, --provider <list>        只处理指定云厂商
  -s, --service <list>         只处理指定服务（取值同 domains）
  -d, --domain <list>          只处理这些域名（精确匹配，逗号分隔，可重复）；点名的域名没开 HTTPS 时会部署并开启
      --force                  需确认的域名也替换（AI 调用前须先向用户确认）
      --dry-run                只输出计划，不做任何修改（也不上传证书）
      --timeout <ms>           单个请求超时，默认 15000
      --json                   输出单行 JSON
      --env-file <path>        从指定文件加载环境变量
```

执行前先校验证书：私钥与证书匹配、带中间证书链、在有效期内，任一不满足直接报参数错误，不调用任何云接口。然后查询所选云厂商的全部域名，只处理被证书覆盖的域名（与证书 SAN 精确匹配，`*.example.com` 只覆盖一级子域，不含 `example.com` 本身），逐个按下面的规则决定：

| 情况 | 结果 |
| --- | --- |
| 已开 HTTPS，当前证书 30 天内到期（含已过期） | 更新为新证书 |
| 已开 HTTPS，当前证书还有 30 天以上才到期 | 跳过，`reason: "not_due"`，**需确认** |
| 已开 HTTPS，查不到当前证书的到期时间 / 当前证书比新证书到期还晚 / 到期相同但签发时间或算法不同（重签、RSA 换 ECC） | 跳过（`unknown_expiry` / `newer_current` / `same_expiry`），**需确认** |
| 已开 HTTPS，已是这张证书（到期、签发时间相同，算法相同或查不到） | 跳过（`already_current`），所以重复执行是安全的；查不到当前证书算法时，加 `--force` 可强制替换 |
| 没开 HTTPS，没用 `-d` 点名 | 跳过（`https_off`） |
| 没开 HTTPS，用 `-d` 点名 | 部署并开启 HTTPS |
| 平台默认域名 / 服务不支持 | 跳过（`platform_managed` / `unsupported`，message 写明原因） |

**需确认的域名（二次确认）**：

- AI 调用时（`--json` 或非终端）：这些域名带 `needsConfirm: true` 跳过。AI 应把它们列给用户确认，用户同意后加 `--force` 重新执行（可配合 `-d` 只针对这些域名）。
- 人在终端里直接运行时：列出这些域名并当场询问「是否提前更换？[y/N]」，回答 y 等同于 `--force`。

**证书上传**：需要证书 ID 才能绑定的服务，会先把证书上传到该云的证书服务（每次运行每家云最多上传一次）。证书服务里已有同一张证书时直接复用，按指纹等能确定是同一张的信息判断，判断不了就重新上传。上传的证书名形如 `sslbear-example.com-20270101`。

**生效时间**：云接口受理即算成功，不等待边缘节点生效（各云需要几秒到几分钟），可稍后用 `domains` 核对。

**JSON 输出**：

```json
{"ok":true,"data":{"dryRun":false,"cert":{"commonName":"example.com","sans":["example.com","*.example.com"],"notAfter":"2027-01-15T00:00:00.000Z","algorithm":"RSA","fingerprint":"…"},"uploads":[{"provider":"aliyun","certId":"12345","reused":false}],"results":[{"provider":"aliyun","service":"cdn","domain":"static.example.com","action":"updated","before":{"name":"old","notAfter":"2026-11-02T10:00:00.000Z","daysLeft":16},"after":{"id":"12345","notAfter":"2027-01-15T00:00:00.000Z"}},{"provider":"tencent","service":"cdn","domain":"www.example.com","action":"skipped","reason":"not_due","needsConfirm":true,"message":"当前证书还剩 75 天，未到更新时间；确需提前更换请向用户确认后加 --force 重新执行（可配合 -d 只针对这些域名）"}],"issues":[]}}
```

- `action`：`deployed`（原先没开 HTTPS）、`updated`（替换旧证书）、`skipped`、`failed`；`--dry-run` 时为 `would_deploy` / `would_update` / `skipped` / `failed`。
- `failed` 带 `code`、`message`、`requestId`（有的话）和 `retryable`（能否原样重试）。常见 code：`HttpsStateUnknown`（查询该域名的 HTTPS 配置失败，无法判断现状，未做修改，可稍后重试）、`DomainNotFound`（`-d` 点名的域名找不到）、`NotCovered`（`-d` 点名的域名不被证书覆盖）、`HttpsAlreadyEnabled`（写入前发现 HTTPS 已被开启，与查询时不同，重新执行即可），其余为云接口的错误码。
- `shared_cert_blocked`：证书挂在多个域名共享的配置上（目前是阿里云 ESA 站点），同组有记录不能一起更换时整组跳过，message 列出挡住的记录与放行方法。
- 退出码：`0` 没有失败（全部成功或跳过，包括什么都没改）；`1` 有域名部署失败或所有查询都失败，stderr 输出 `{"ok":false,"status":"DeployFailed","message":…}`，同一个对象里带完整的 `results`、`uploads`、`issues`；`2` 参数、证书文件或凭证配置错误（未做任何修改）。

### `env`：检查配置

显示每家云厂商的凭证是否配置齐全（AccessKey ID 脱敏显示，Secret 只显示「已设置」）以及可查询的服务。

## JSON 输出与退出码

加 `--json` 后输出单行 JSON，便于脚本和 agent 解析：

```json
{"ok":true,"data":{"items":[{"provider":"aliyun","service":"oss","domain":"img.example.com","status":"Enabled","https":true,"cert":{"id":"12345-cn-hangzhou","notAfter":"2026-11-02T10:14:51.000Z","status":"Enabled"},"extra":{"bucket":"static-prod","region":"cn-shanghai","certType":"CAS"},"daysLeft":18}],"issues":[{"provider":"aliyun","service":"dcdn","kind":"inactive","code":"DcdnServiceNotFound","message":"The DCDN service is not activated."}]}}
```

- 时间字段统一为 ISO 8601（UTC），`daysLeft` 为剩余天数，负数表示已过期。
- 各云服务返回的字段不完全一致，`cert` 里只输出该服务实际提供的字段（如 OSS 只有证书 ID 和有效期，没有证书名）。
- `extra.managed: "platform"` 表示云厂商分配的平台默认域名（如腾讯云 `*.myqcloud.com`、`*.vod-qcloud.com`），用云厂商自己的证书提供 HTTPS，用户无需续期：不带 `cert`、不计入到期统计，表格的证书列显示「平台托管」。
- `issues` 记录各服务的查询问题：`kind: "inactive"` 表示该服务未开通或无资源，`kind: "error"` 表示调用失败（含错误码和 RequestId）；逐个 bucket / 站点 / 应用展开查询的服务，单个子项失败时用 `target` 标明是哪一个，其余子项照常返回。
- 退出码：`0` 成功（部分服务失败时仍返回 0，详情见 `issues`）；`1` 所有查询都失败（如凭证无效、网络不通）；`2` 参数或凭证配置错误。失败时 stderr 输出 `{"ok":false,"status":...,"message":"..."}`。

## 所需权限

`domains`、`certs` 只需各产品的只读权限，可在各云的访问控制里给子账号授予对应产品的只读系统策略：

- 阿里云：CDN、DCDN、边缘安全加速 ESA（`AliyunESAReadOnlyAccess`）、OSS、视频直播、视频点播、数字证书管理服务的 ReadOnly 策略。
- 腾讯云：CDN、EdgeOne、对象存储 COS（`QcloudCOSReadOnlyAccess`）、云直播、云点播、SSL 证书的只读策略。
- 火山引擎：`CDNReadOnlyAccess`、`DCDNReadOnlyAccess`、`TOSReadOnlyAccess`、`VodReadOnlyAccess`、`LIVEReadOnlyAccess`、`ImageXReadOnlyAccess`、`SSLReadOnly`（证书中心）。
- 华为云：`CDN DomainReadOnlyAccess`、`Live ReadOnlyAccess`（项目级，需授权到直播所在地域的项目或所有资源）、`SCM ReadOnlyAccess`；OBS 的 `OBS ReadOnlyAccess` 不含「获取桶的自定义域名」，需另加包含 `obs:bucket:ListAllMyBuckets`、`obs:bucket:GetBucketCustomDomainConfiguration` 的自定义策略，也可以直接授予全局只读 `Tenant Guest`。查询项目 ID 用的 IAM 接口不需要额外权限。
- 百度智能云：`CdnReadAccessPolicy`（CDN 只读）、`CASReadPolicy`（证书管理只读，需产品级权限）。
- 七牛云：没有现成的只读系统策略，可用主账号 AK，或给 IAM 子账号自定义策略授权 `cdn/GetDomainList`、`cdn/GetDomainInfo`。

部分服务的域名接口只返回证书 ID，会用该云的证书列表按 ID 补全到期时间、证书名等信息（腾讯云直播、点播、EdgeOne、COS，火山引擎 DCDN、TOS、点播、veImageX，华为云直播、OBS，百度智能云 CDN，七牛云 CDN），因此建议同时授予证书服务的只读权限；补全失败只记一条 issue，域名照常输出。阿里云 CDN、DCDN、直播的证书信息来自各自的 HTTPS 证书列表接口，查不到（如缺权限）时同样只记一条 issue、域名照常输出（CDN、DCDN 的 HTTPS 以域名列表里的开关为准；直播没有开关，此时显示为关闭）。

缺少某个服务的权限时，只有该服务会出现在 `issues` 里，其余服务照常输出。

`deploy` 在只读权限之外还需要以下写权限（只部署部分服务时只需对应的那几项）：

- 阿里云：数字证书管理服务 `yundun-cert:UploadUserCertificate`、`ListUserCertificateOrder`、`GetUserCertificateDetail`（或 `AliyunYundunCertFullAccess`）；CDN `cdn:SetCdnDomainSSLCertificate`；DCDN `dcdn:SetDcdnDomainSSLCertificate`；直播 `live:SetLiveDomainCertificate`；点播 `vod:SetVodDomainSSLCertificate`；OSS `oss:PutCname`，另需 OSS 读取证书服务里证书的权限（`yundun-cert:DescribeSSLCertificatePrivateKey`、`DescribeSSLCertificatePublicKeyDetail`、`CreateSSLCertificate`）；ESA `esa:SetCertificate`、`esa:UpdateCustomHostname`。也可以直接授予各产品的 FullAccess 系统策略。
- 腾讯云：`ssl:UploadCertificate`、`cdn:ModifyDomainConfig`、`cdn:UpdateDomainConfig`、`teo:ModifyHostsCertificate`、`cos:PutBucketDomainCertificate`、`live:ModifyLiveDomainCertBindings`、`vod:SetVodDomainCertificate`。
- 火山引擎：证书中心 `ImportCertificate`；CDN `BatchDeployCert`；DCDN `CreateCertBind`、`DescribeDomainDetail`、`UpdateDomainConfig`；TOS `GetBucketCustomDomain`、`PutBucketCustomDomain`；点播 `DescribeVodDomainConfig`、`UpdateVodDomainConfig`；直播 `ListCertV2`、`DescribeCertDetailSecretV2`、`CreateCert`、`BindCert`；veImageX `GetDomainConfig`、`UpdateImageBatchDomainCert`、`UpdateHttps`。也可以授予对应产品的 FullAccess 策略。
- 华为云：CDN `CDN DomainConfiguration`；视频直播 `Live FullAccess`（授权到直播所在地域的项目）；云证书管理 `SCM FullAccess`，或包含 `scm:cert:import`、`scm:cert:get`、`scm:cert:list` 的自定义策略（只部署 CDN 时不需要）；OBS 包含 `obs:bucket:PutBucketCustomDomainConfiguration` 的自定义策略。
- 百度智能云：证书管理的创建证书权限、CDN 域名配置的写权限。
- 七牛云：主账号 AK，或有 CDN 域名配置写权限与 SSL 证书上传权限的 IAM 子账号。

## 已知限制

以下行为已在 2026-10 用各云真实账号验证（TLS 握手实测下发的证书与 CLI 报告一致）。

- 阿里云视频点播只查询上海地域（`vod.cn-shanghai.aliyuncs.com`），点播证书只有 SAN、没有通用名。直播推流域名不能配 HTTPS，会显示为关闭；直播把 HTTPS 关掉时证书会被一并删除，不存在「绑了证书但关闭」的状态。
- 阿里云 ESA 只查询中国站接入点（`esa.cn-hangzhou.aliyuncs.com`），国际站（`ap-southeast-1` 接入点）暂未适配。ESA 的证书配置在站点上，记录绑定的证书按证书通用名和 SAN 匹配得出；多张证书都匹配时按 ESA 的选择优先级取有效期内、配置时间较晚的那张，RSA 与 ECC 证书同时有效时取先到期的那张。HTTPS 列要求站点的 SSL/TLS 配置（全局配置与 SSL/TLS 规则）对该域名开启了 HTTPS，并且有已签发的匹配证书（只有申请中 / 申请失败的证书记为关闭）。JSON 里 `extra.httpsSwitch` 为开关状态 `on` / `off` / `partial`，`extra.httpsRule` 为决定结果的规则名；partial 表示有规则的条件无法按域名判断（如引用了自定义列表，或用了无法解析的写法），此时按开启处理并照常展示证书，宁可多报到期；SSL/TLS 配置查询失败时没有 `httpsSwitch`，HTTPS 只按证书判断。泛域名记录按记录名本身（如 `*.example.com`）匹配规则；SaaS 域名以其自身的 SSL 开关为准。只解析不加速的记录不列出，边缘函数、边缘容器和四层加速的记录暂不支持。在 ESA 上传的证书也会出现在 `certs`（数字证书管理服务）里，名称为 ESA 的证书 ID。
- 阿里云 CAS 证书列表的有效期取接口返回的毫秒时间戳；个别证书缺该字段时退回只有日期的 EndDate，按到期当天 23:59:59（北京时间）计算。
- 腾讯云平台默认域名按 `myqcloud.com`、`vod-qcloud.com`、`tlivecloud.com`、`tencentcos.cn` 后缀识别（接口里没有区分字段），标记为 `extra.managed: "platform"`：点播、直播的平台域名始终由平台提供 HTTPS，CDN 以 HTTPS 开关为准。CDN 的证书名取 SSL 证书的备注名。直播推流域名不能绑证书，会显示为关闭。
- 腾讯云 COS 只列存储桶的自定义源站域名，HTTPS 以该域名的证书配置为「已启用」为准（COS 没有单独的 HTTPS 开关，自定义域名本身被停用但仍绑着证书时照常显示开启——此时边缘仍下发该证书）；经过 CDN 加速的 COS 域名出现在腾讯云 CDN 的结果里。每个域名要单独查一次证书配置，域名多时请求较多（并发 5）。
- 火山引擎视频直播的读接口没有 HTTPS 开关，绑定证书并开启 HTTPS 时域名才带证书链 ID，CLI 以此判断；绑定证书时关闭了 HTTPS 的域名显示为关闭（边缘节点实际仍会用该证书完成 TLS 握手，读接口看不到）。推流域名的证书用于 RTMPS / HTTPS 推流，同样列出。
- 火山引擎 TOS 没有 HTTPS 开关，绑定证书即可 HTTPS 访问；证书状态为 `CertNotExist`（证书已删除）或 `RoleNotExist`（TOS 无法访问证书中心）时实际下发的是 TOS 默认证书，记为关闭，原证书 ID 与状态放在 `extra.certId` / `extra.certStatus`。DCDN 绑了证书但关闭 HTTPS 的域名按开关记为关闭（实测边缘仍下发该证书）。CDN、点播的双证书（RSA + ECC）是平台白名单功能。
- 火山引擎视频点播、veImageX 只查华北与亚太东南（柔佛）两个地域，HTTPS 配置要逐域名查询，域名多时较慢。`certs` 只列证书中心里已签发的 SSL 证书，不含视频直播证书管理里上传的证书、CDN 自托管证书和私有 CA 证书。
- 华为云只适配中国站（CDN 走 `cdn.myhuaweicloud.com`，证书列表走 `scm.cn-north-4.myhuaweicloud.com`）。CDN 一次拉取所有企业项目下的域名；CDN 双证书只支持「国际 + 国密」，关闭 HTTPS 时证书会被一并删除。视频直播按 IAM 项目逐地域查询 cn-north-4、cn-north-1、cn-east-3、ap-southeast-3、ap-southeast-2，只查各地域的主项目，没用到直播的地域静默跳过；直播没有 HTTPS 开关，播放域名配置了证书即视为开启 HTTPS（未配证书时下发的是平台默认证书），有效期取自域名当前证书的 PEM（证书列表接口的时间比真实值早 8 小时，只在取不到 PEM 时补正后使用）。OBS 只列对象桶（不含并行文件系统），自定义域名绑定了服务端证书（含国密）才算 HTTPS。证书列表的到期时间不带时区，实测为北京时间。
- 百度智能云只覆盖境内 CDN（海外 CDN 未覆盖），每个 CDN 域名只能绑一张证书。HTTPS 以「已开启 HTTPS 的域名列表」为准：绑了证书但关闭 HTTPS 的域名记为关闭（实测边缘握手仍下发该证书，但 HTTPS 请求返回 403 httpsDisabled）；证书的通用名与 SAN 从证书管理按证书 ID 补全（该列表的 certCommonName 字段实为证书名）。未开通 CDN 的账号只读接口照常返回空列表，因此显示 0 个域名、不提示未开通；「已开启 HTTPS 的域名列表」接口失败时退回逐个域名查询 HTTPS 配置（并发 5），域名多时较慢。`certs` 只列证书管理里的证书，不单独查询 SSL 证书服务里购买的证书；使用平台通用证书（`cert-common`）的域名没有到期时间。
- 七牛云只支持 CDN（含全站加速）域名，对象存储 Kodo 的自定义域名不在其中，七牛给新建 bucket 自动分配的测试域名（`*.clouddn.com`）不列出；泛域名按七牛的写法以点开头（如 `.example.com`）；已下线、冻结的域名也会列出，用 `status` 区分。一个域名只能绑一张证书，降级为 HTTP 时证书会被解绑。开启了 HTTPS 的域名要逐个查详情，七牛接口限 10 QPS，域名多时约每秒 8 个。

### `deploy` 的已知限制

- 阿里云：
  - 证书上传到数字证书管理服务（中国站，地域 cn-hangzhou），私钥会先转成 PKCS#1（RSA）/ SEC1（ECC）格式再上传，这是阿里云的要求。
  - 直播推流域名不能配 HTTPS。直播的 HTTPS 证书列表查询失败时，无法判断直播域名是否开着 HTTPS，记为 `HttpsStateUnknown`。
  - ESA 普通记录的证书是往站点上**追加**的，旧证书不删除，站点证书数受套餐配额限制，配额满了要到控制台清理过期证书。站点上加入一种算法的证书不会替换另一算法的证书：域名上原有 ECC 证书时部署 RSA 证书，ECC 证书在到期前仍可能下发给支持 ECC 的客户端。站点下被新证书覆盖的记录要全部满足更新条件才会上传，否则整站跳过（`shared_cert_blocked`）。没开 HTTPS 的普通记录不能通过 CLI 部署（要改站点的 SSL/TLS 规则，影响面超出单个域名）。ESA 的 SSL/TLS 配置查询失败时，该站点有证书的记录记为 `HttpsStateUnknown`。
  - OSS 泛域名 CNAME 没有专门适配。
- 腾讯云：
  - EdgeOne 只经过模拟测试，尚未用真实账号验证。挂了多张证书但查不到算法的 EdgeOne 域名不处理；原来用免费证书的 EdgeOne 域名，更新后改为托管证书。
  - CDN 部署不会替你打开 HTTPS 计费开关（HttpsBilling）；它关着时证书照常部署，结果里会提示 HTTPS 请求会被拦截。
  - 直播推流域名、点播里由 EdgeOne 分发的域名、锁定中的点播域名不支持。COS 已停用的自定义域名只换证书，不会启用域名。
- 火山引擎：
  - 视频直播拉流域名不能自动更新证书：`BindCert` 不传 HTTP/2、TLS 版本就会恢复默认值，而直播没有接口能读出当前设置，只能在控制台更换；推流域名不受影响。拉流域名点名部署时 HTTP/2 关闭、最低 TLS 1.2。直播证书上传到直播自己的证书管理，`certs` 看不到。
  - veImageX 只经过模拟测试，尚未用真实账号验证；部署（开启 HTTPS）时 TLS 版本取 1.1–1.3、不开 OCSP。
  - DCDN 部署后会读回确认 HTTPS 已开启，必要时再单独打开开关。TOS 证书状态为 `RoleNotExist` 时不处理，需先在 TOS 控制台完成访问证书中心的授权。
  - CDN、点播的双证书（RSA + ECC）是平台白名单功能，只替换同算法那张；双证书域名查不到算法时不处理。
- 华为云：
  - CDN 直接传证书内容，不经过云证书管理（用云证书管理的证书绑定 CDN 需要先在控制台授权），所以 CDN 部署的证书在 `certs` 里看不到；直播、OBS 会先上传到云证书管理再绑定。
  - CDN、直播的国密证书只有由云证书管理托管时才能保留；自己上传的国密证书读不到私钥，这类域名跳过，需在控制台更换。直播推流域名不能配证书。OBS 只设置国际证书，国密证书和客户端 CA 证书不动；OBS 列表不给国际证书的算法。
- 百度智能云：只支持境内 CDN，只替换国际证书（RSA / ECC 二选一），国密 HTTPS 证书不处理。证书管理的查重依赖接口返回的证书指纹，拿不到时会多上传一份。
- 七牛云：泛子域名的 HTTPS 继承泛域名，不能单独部署（请对泛域名部署）。上一次配置还在处理中的域名七牛会拒绝修改，需稍后重新执行。部署（开启 HTTPS）时 HTTP/2 默认打开、不强制跳转。

## 开发

```bash
npm install
npm test           # 单元测试（签名算法用官方示例向量校验，云接口用 mock）
npm run typecheck
npm run build      # 打包到 dist/index.js
node dist/index.js domains --help
```
