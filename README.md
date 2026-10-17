# sslbear-cli

证书熊（[sslbear.com](https://sslbear.com)）命令行工具：一条命令查出阿里云、腾讯云、火山引擎、华为云、百度智能云、七牛云各云服务上配置的域名，以及每个域名当前绑定的 SSL 证书和到期时间。

- 零安装：`npx sslbear-cli ...` 即可运行（Node.js ≥ 18.17），发布包不带任何运行时依赖
- 只读：只调用查询类接口，不会修改任何云上配置
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
- 建议用子账号 / 子用户（阿里云 RAM、腾讯云 CAM、火山引擎 IAM、华为云 IAM、百度智能云 IAM、七牛云 IAM），只授予只读权限（见下文「所需权限」）。

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

### `env`：检查配置

显示每家云厂商的凭证是否配置齐全（AccessKey ID 脱敏显示，Secret 只显示「已设置」）以及可查询的服务。

## JSON 输出与退出码

加 `--json` 后输出单行 JSON，便于脚本和 agent 解析：

```json
{"ok":true,"data":{"items":[{"provider":"aliyun","service":"oss","domain":"img.example.com","status":"Enabled","https":true,"cert":{"id":"12345-cn-hangzhou","notAfter":"2026-11-02T10:14:51.000Z","status":"Enabled"},"extra":{"bucket":"static-prod","region":"cn-shanghai","certType":"CAS"},"daysLeft":18}],"issues":[{"provider":"aliyun","service":"dcdn","kind":"inactive","code":"DcdnServiceNotFound","message":"The DCDN service is not activated."}]}}
```

- 时间字段统一为 ISO 8601（UTC），`daysLeft` 为剩余天数，负数表示已过期。
- 各云服务返回的字段不完全一致，`cert` 里只输出该服务实际提供的字段（如 OSS 只有证书 ID 和有效期，没有证书名）。
- `issues` 记录各服务的查询问题：`kind: "inactive"` 表示该服务未开通或无资源，`kind: "error"` 表示调用失败（含错误码和 RequestId）；逐个 bucket / 站点 / 应用展开查询的服务，单个子项失败时用 `target` 标明是哪一个，其余子项照常返回。
- 退出码：`0` 成功（部分服务失败时仍返回 0，详情见 `issues`）；`1` 所有查询都失败（如凭证无效、网络不通）；`2` 参数或凭证配置错误。失败时 stderr 输出 `{"ok":false,"status":...,"message":"..."}`。

## 所需权限

只需各产品的只读权限，可在各云的访问控制里给子账号授予对应产品的只读系统策略：

- 阿里云：CDN、DCDN、边缘安全加速 ESA（`AliyunESAReadOnlyAccess`）、OSS、视频直播、视频点播、数字证书管理服务的 ReadOnly 策略。
- 腾讯云：CDN、EdgeOne、对象存储 COS（`QcloudCOSReadOnlyAccess`）、云直播、云点播、SSL 证书的只读策略。
- 火山引擎：`CDNReadOnlyAccess`、`DCDNReadOnlyAccess`、`TOSReadOnlyAccess`、`VodReadOnlyAccess`、`LIVEReadOnlyAccess`、`ImageXReadOnlyAccess`、`SSLReadOnly`（证书中心）。
- 华为云：`CDN DomainReadOnlyAccess`、`Live ReadOnlyAccess`（项目级，需授权到直播所在地域的项目或所有资源）、`SCM ReadOnlyAccess`；OBS 的 `OBS ReadOnlyAccess` 不含「获取桶的自定义域名」，需另加包含 `obs:bucket:ListAllMyBuckets`、`obs:bucket:GetBucketCustomDomainConfiguration` 的自定义策略，也可以直接授予全局只读 `Tenant Guest`。查询项目 ID 用的 IAM 接口不需要额外权限。
- 百度智能云：`CdnReadAccessPolicy`（CDN 只读）、`CASReadPolicy`（证书管理只读，需产品级权限）。
- 七牛云：没有现成的只读系统策略，可用主账号 AK，或给 IAM 子账号自定义策略授权 `cdn/GetDomainList`、`cdn/GetDomainInfo`。

部分服务的域名接口只返回证书 ID，会用该云的证书列表按 ID 补全到期时间（腾讯云直播、点播、EdgeOne、COS，火山引擎 DCDN、TOS、点播、veImageX，华为云直播、OBS，百度智能云 CDN，七牛云 CDN），因此建议同时授予证书服务的只读权限；补全失败只记一条 issue，域名照常输出。

缺少某个服务的权限时，只有该服务会出现在 `issues` 里，其余服务照常输出。

## 已知限制

- 阿里云视频点播只查询上海地域（`vod.cn-shanghai.aliyuncs.com`）。
- 阿里云 ESA 只查询中国站接入点（`esa.cn-hangzhou.aliyuncs.com`），国际站（`ap-southeast-1` 接入点）暂未适配。ESA 的证书配置在站点上，记录绑定的证书按证书通用名和 SAN 匹配得出；多张证书都匹配时按 ESA 的选择优先级取有效期内、配置时间较晚的那张，RSA 与 ECC 证书同时有效时取先到期的那张。HTTPS 列要求站点的 SSL/TLS 配置（全局配置与 SSL/TLS 规则）对该域名开启了 HTTPS，并且有已签发的匹配证书（只有申请中 / 申请失败的证书记为关闭）。JSON 里 `extra.httpsSwitch` 为开关状态 `on` / `off` / `partial`，`extra.httpsRule` 为决定结果的规则名；partial 表示有规则的条件无法按域名判断（如引用了自定义列表，或用了无法解析的写法），此时按开启处理并照常展示证书，宁可多报到期；SSL/TLS 配置查询失败时没有 `httpsSwitch`，HTTPS 只按证书判断。泛域名记录按记录名本身（如 `*.example.com`）匹配规则；SaaS 域名以其自身的 SSL 开关为准。只解析不加速的记录不列出，边缘函数、边缘容器和四层加速的记录暂不支持。
- 腾讯云 COS 只列存储桶的自定义源站域名，HTTPS 以该域名的证书配置为「已启用」为准；经过 CDN 加速的 COS 域名出现在腾讯云 CDN 的结果里。每个域名要单独查一次证书配置，域名多时请求较多（并发 5）。
- 火山引擎视频直播、TOS 的读接口不返回 HTTPS 开关，以「绑定了证书」视为开启 HTTPS。视频点播、veImageX 只查华北与亚太东南（柔佛）两个地域，HTTPS 配置要逐域名查询，域名多时较慢。`certs` 只列证书中心里已签发的 SSL 证书，不含 CDN 自托管证书和私有 CA 证书。
- 华为云只适配中国站（CDN 走 `cdn.myhuaweicloud.com`，证书列表走 `scm.cn-north-4.myhuaweicloud.com`）。CDN 一次拉取所有企业项目下的域名。视频直播按 IAM 项目逐地域查询 cn-north-4、cn-north-1、cn-east-3、ap-southeast-3、ap-southeast-2，只查各地域的主项目，没用到直播的地域静默跳过；直播没有 HTTPS 开关，播放域名配置了证书即视为开启 HTTPS。OBS 只列对象桶（不含并行文件系统），自定义域名绑定了服务端证书（含国密）才算 HTTPS。证书列表的到期时间不带时区，按北京时间处理。
- 百度智能云只覆盖境内 CDN（海外 CDN 未覆盖）；`certs` 只列证书管理里的证书，不单独查询 SSL 证书服务里购买的证书；使用平台通用证书（`cert-common`）的域名没有到期时间。
- 七牛云只支持 CDN（含全站加速）域名，对象存储 Kodo 的自定义域名不在其中；泛域名按七牛的写法以点开头（如 `.example.com`）；已下线、冻结的域名也会列出，用 `status` 区分。开启了 HTTPS 的域名要逐个查详情，七牛接口限 10 QPS，域名多时约每秒 8 个。
- 阿里云 CAS 证书列表接口只返回到期日期、不含具体时刻，按到期当天 23:59:59（北京时间）计算剩余天数。

## 开发

```bash
npm install
npm test           # 单元测试（签名算法用官方示例向量校验，云接口用 mock）
npm run typecheck
npm run build      # 打包到 dist/index.js
node dist/index.js domains --help
```
