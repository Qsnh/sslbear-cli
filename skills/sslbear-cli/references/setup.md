# 安装与凭证配置

## 运行环境

- 需要 Node.js ≥ 18.17，用 `node -v` 查看。
- 不用预先安装：`npx -y sslbear-cli@latest` 会自动下载。
- 用户想固定版本时，可以 `npm i -g sslbear-cli`，之后直接用 `sslbear-cli`。

## 凭证放在哪

CLI 从环境变量读取凭证，并自动加载找到的第一个 `.env`，查找顺序如下：

1. 当前目录的 `.env`
2. `~/.sslbear-cli/.env`（环境变量 `SSLBEAR_CLI_HOME` 可以改 `~/.sslbear-cli` 这个目录）

也可以用 `--env-file <路径>` 指定其他文件。

优先级：shell 里已设置的变量优先。只要 shell 里设置了某家云的任意一个变量，`.env` 里这家的凭证就整组忽略，两处的值不会拼在一起用。

用户还没有 `.env` 时，建议放在 `~/.sslbear-cli/.env`。这样在任何目录下运行都能读到，自动续期也用这一份：

```sh
mkdir -p ~/.sslbear-cli && touch ~/.sslbear-cli/.env && chmod 600 ~/.sslbear-cli/.env
```

- 最好请用户自己把凭证写进这个文件，每行一个 `变量名=值`。
- 用户把密钥直接发在对话里时，替用户写进文件。回复里不要复述密钥，并建议用户事后轮换。
- 写好后运行 `sslbear-cli env --json`，确认要用的那家 `state` 是 `ok`。输出里 ID 已脱敏，Secret 只显示是否已设置；`data.envFile` 是实际加载的文件。

## 变量名

只配置要用的云。

| 云（`-p`） | 必填 | 可选（临时凭证） |
| --- | --- | --- |
| aliyun | `ALIBABA_CLOUD_ACCESS_KEY_ID`、`ALIBABA_CLOUD_ACCESS_KEY_SECRET` | `ALIBABA_CLOUD_SECURITY_TOKEN` |
| tencent | `TENCENTCLOUD_SECRET_ID`、`TENCENTCLOUD_SECRET_KEY` | `TENCENTCLOUD_SESSION_TOKEN` |
| volcengine | `VOLCENGINE_ACCESS_KEY`、`VOLCENGINE_SECRET_KEY` | `VOLCENGINE_SESSION_TOKEN` |
| huawei | `HUAWEICLOUD_SDK_AK`、`HUAWEICLOUD_SDK_SK` | `HUAWEICLOUD_SDK_SECURITY_TOKEN` |
| baidu | `BAIDUCLOUD_ACCESS_KEY`、`BAIDUCLOUD_SECRET_KEY` | `BAIDUCLOUD_SESSION_TOKEN` |
| qiniu | `QINIU_ACCESS_KEY`、`QINIU_SECRET_KEY` | — |

`issue` 要在域名所在的 DNS 服务商添加验证记录：

- 前 5 家云的云解析（DNSPod 对应 tencent）直接复用上表的凭证。七牛云没有 DNS 服务。
- 另外 6 家 DNS 服务商用自己的凭证：

| DNS 服务商（`--dns`） | 必填 | 可选 | 怎么获取 |
| --- | --- | --- | --- |
| cloudflare | `CLOUDFLARE_API_TOKEN` | — | dash.cloudflare.com → My Profile → API Tokens 建 Custom token，权限 `Zone → Zone → Read` + `Zone → DNS → Edit`。不支持 Global API Key |
| aws（Route 53） | `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY` | `AWS_SESSION_TOKEN` | IAM 用户，授权 `route53:ListHostedZones`、`route53:ListResourceRecordSets`、`route53:ChangeResourceRecordSets`；账号里有多个同名公网 zone 时再加 `route53:GetHostedZone` |
| google（Cloud DNS） | `GOOGLE_APPLICATION_CREDENTIALS`（服务账号 JSON 密钥文件的路径） | `GOOGLE_CLOUD_PROJECT` | 服务账号在项目上授予 DNS Administrator（`roles/dns.admin`），项目要启用 Cloud DNS API |
| azure（Azure DNS） | `AZURE_TENANT_ID`、`AZURE_CLIENT_ID`、`AZURE_CLIENT_SECRET`、`AZURE_SUBSCRIPTION_ID` | — | Microsoft Entra ID 应用注册，在「证书和机密」里新建客户端密码，再在订阅上给这个应用分配「DNS 区域参与者」 |
| digitalocean | `DIGITALOCEAN_TOKEN` | — | 控制台 Account → API → Tokens 生成 Personal Access Token：Full Access，或 Custom Scopes 勾选 `domain:read` + `domain:update` |
| godaddy | `GODADDY_API_KEY`、`GODADDY_API_SECRET` | — | 在 classic-developer.godaddy.com/keys 创建 Production 环境的 Key 和 Secret。developer.godaddy.com 现在发的 Personal Access Token 不支持 |

## 子账号与权限

建议用子账号的密钥：阿里云 RAM、腾讯云 CAM，其他云的 IAM。按用途授权：

- 只查询（`domains`、`certs`）：只读权限。
- 要用 `deploy`：再加上传证书、修改各服务 HTTPS 配置的写权限。
- 要用 `issue`：加域名所在 DNS 服务商的解析记录读写权限。

各云的具体策略见 <https://github.com/Qsnh/sslbear-cli/blob/main/docs/permissions.md>。`issues[]` 或 `failed` 结果里出现权限类错误码（如 Forbidden、NoPermission、AccessDenied、Unauthorized）时，也看这份文档，再把缺的权限告诉用户。阿里云、腾讯云、火山引擎、华为云的 `message` 末尾会写出缺少的权限（RAM / CAM / IAM）和可授予的系统策略，直接转告用户。
