# sslbear-cli

证书熊（[sslbear.com](https://sslbear.com)）命令行工具：一条命令查出阿里云、腾讯云各云服务上配置的域名，以及每个域名当前绑定的 SSL 证书和到期时间。

- 零安装：`npx sslbear-cli ...` 即可运行（Node.js ≥ 18.17），发布包不带任何运行时依赖
- 只读：只调用查询类接口，不会修改任何云上配置
- 凭证从环境变量读取，也支持当前目录的 `.env` 文件

## 快速开始

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI...
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=...
export TENCENTCLOUD_SECRET_ID=AKID...
export TENCENTCLOUD_SECRET_KEY=...

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

- 只配置了一家云厂商也可以，命令默认只查已配置凭证的云厂商。
- 当前目录有 `.env` 时会自动加载；`--env-file <path>` 可指定其他文件。shell 里已设置的变量优先：只要 shell 里设置了某家云厂商的任一凭证变量，`.env` 里这家的凭证就整组忽略，不会把两处的 ID、Secret 拼成一组。
- 建议用 RAM 子账号 / CAM 子用户，只授予只读权限（见下文「所需权限」）。

## 命令

### `domains`：云服务域名及其证书

```
sslbear-cli domains [选项]
  -p, --provider <list>         只查指定云厂商：aliyun, tencent
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
| tencent | `live` | 云直播 |
| tencent | `vod` | 云点播 |

### `certs`：证书服务里的证书

列出阿里云数字证书管理服务（SSL 证书）和腾讯云 SSL 证书中的证书，同样支持 `-p`、`-d`、`-e`、`--json`。

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

只需各产品的只读权限，可在 RAM / CAM 控制台给子账号授予对应产品的 ReadOnly 系统策略（CDN、DCDN、边缘安全加速 ESA（`AliyunESAReadOnlyAccess`）、OSS、视频直播、视频点播、数字证书管理服务；腾讯云 CDN、EdgeOne、云直播、云点播、SSL 证书）。腾讯云直播、点播里只返回证书 ID 的域名，会用 SSL 证书列表补全到期时间，因此建议同时授予 SSL 证书只读权限。

缺少某个服务的权限时，只有该服务会出现在 `issues` 里，其余服务照常输出。

## 已知限制

- 阿里云视频点播只查询上海地域（`vod.cn-shanghai.aliyuncs.com`）。
- 阿里云 ESA 只查询中国站接入点（`esa.cn-hangzhou.aliyuncs.com`），国际站（`ap-southeast-1` 接入点）暂未适配。ESA 的证书配置在站点上，记录绑定的证书按证书通用名和 SAN 匹配得出；多张证书都匹配时按 ESA 的选择优先级取有效期内、配置时间较晚的那张，RSA 与 ECC 证书同时有效时取先到期的那张。HTTPS 列要求站点的 SSL/TLS 配置（全局配置与 SSL/TLS 规则）对该域名开启了 HTTPS，并且有已签发的匹配证书（只有申请中 / 申请失败的证书记为关闭）。JSON 里 `extra.httpsSwitch` 为开关状态 `on` / `off` / `partial`，`extra.httpsRule` 为决定结果的规则名；partial 表示有规则的条件无法按域名判断（如引用了自定义列表，或用了无法解析的写法），此时按开启处理并照常展示证书，宁可多报到期；SSL/TLS 配置查询失败时没有 `httpsSwitch`，HTTPS 只按证书判断。泛域名记录按记录名本身（如 `*.example.com`）匹配规则；SaaS 域名以其自身的 SSL 开关为准。只解析不加速的记录不列出，边缘函数、边缘容器和四层加速的记录暂不支持。
- 暂不支持腾讯云 COS 自定义域名。经过 CDN 加速的 COS 域名会出现在腾讯云 CDN 的结果里。
- 阿里云 CAS 证书列表接口只返回到期日期、不含具体时刻，按到期当天 23:59:59（北京时间）计算剩余天数。

## 开发

```bash
npm install
npm test           # 单元测试（签名算法用官方示例向量校验，云接口用 mock）
npm run typecheck
npm run build      # 打包到 dist/index.js
node dist/index.js domains --help
```
