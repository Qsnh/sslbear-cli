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
云厂商  服务     域名               HTTPS  证书            到期时间    剩余天数
腾讯云  CDN      static.example.cn  开启   static-cert     2026-10-12  已过期 3 天
阿里云  OSS      img.example.com    开启   cas-123456      2026-11-02  17
阿里云  CDN      api.example.com    开启   api-2026        2027-01-12  89
腾讯云  EdgeOne  www.example.io     关闭   -               -           -

共 4 个域名，1 个证书已过期，1 个 30 天内到期，1 个未开启 HTTPS
```

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
- 当前目录有 `.env` 时会自动加载；`--env-file <path>` 可指定其他文件。shell 里已设置的变量优先，`.env` 不会覆盖。
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
{"ok":true,"data":{"items":[{"provider":"aliyun","service":"cdn","domain":"api.example.com","status":"online","https":true,"cert":{"name":"api-2026","commonName":"api.example.com","notBefore":"2026-10-14T00:00:00.000Z","notAfter":"2027-01-12T00:00:00.000Z"},"daysLeft":89}],"issues":[]}}
```

- 时间字段统一为 ISO 8601（UTC），`daysLeft` 为剩余天数，负数表示已过期。
- `issues` 记录各服务的查询问题：`kind: "inactive"` 表示该服务未开通或无资源，`kind: "error"` 表示调用失败（含错误码和 RequestId）。
- 退出码：`0` 成功（部分服务失败时仍返回 0，详情见 `issues`）；`1` 所有查询都失败或网络错误；`2` 参数或凭证配置错误。失败时 stderr 输出 `{"ok":false,"status":...,"message":"..."}`。

## 所需权限

只读权限即可：

- 阿里云：`AliyunCDNReadOnlyAccess`、`AliyunDCDNReadOnlyAccess`、`AliyunOSSReadOnlyAccess`、`AliyunLiveReadOnlyAccess`、`AliyunVODReadOnlyAccess`、`AliyunYundunCertReadOnlyAccess`
- 腾讯云：`QcloudCDNReadOnlyAccess`、`QcloudTEOReadOnlyAccess`、`QcloudLIVEReadOnlyAccess`、`QcloudVODReadOnlyAccess`、`QcloudSSLReadOnlyAccess`

缺少某个服务的权限时，只有该服务会出现在 `issues` 里，其余服务照常输出。

## 开发

```bash
npm install
npm test           # 单元测试（签名算法用官方示例校验，接口用 mock）
npm run typecheck
npm run build      # 打包到 dist/index.js
node dist/index.js domains --help
```
