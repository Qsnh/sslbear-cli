# 所需权限

建一个子账号（阿里云 RAM、腾讯云 CAM、其他云的 IAM），按要用的命令授权：

| 要用的命令 | 授予什么 |
| --- | --- |
| 查询：`domains` / `certs` | 用到的产品的只读权限，加上证书服务的只读权限 |
| 部署：`deploy` | 在只读的基础上，加上传证书、修改域名 HTTPS 配置的写权限 |
| 签发：`issue` | 只要域名所在 DNS 服务商的解析权限：列出域名，增删解析记录 |

每家云先给**省事做法**（直接授予系统策略），再给**最小权限**（想收紧时自己建策略）。

注意：

- **证书服务的只读权限一定要给。** 不少服务的域名接口只返回证书 ID，到期时间要去证书服务查，缺这个权限时到期时间会是空的。
- 缺权限不会让整条命令失败：只有缺权限的服务出现在 `issues`（或 `failed`）里，其他服务照常输出。
- 只部署部分服务时，只给这几个服务的写权限就行。`issue --dry-run` 只需要列出域名的权限。

跳转：[阿里云](#阿里云) · [腾讯云](#腾讯云) · [火山引擎](#火山引擎) · [华为云](#华为云) · [百度智能云](#百度智能云) · [七牛云](#七牛云) · [其他 DNS 服务商](#其他-dns-服务商)

## 阿里云

省事做法：

| 命令 | 系统策略 |
| --- | --- |
| 查询 | 用到哪个产品给哪个：`AliyunCDNReadOnlyAccess`、`AliyunDCDNReadOnlyAccess`、`AliyunESAReadOnlyAccess`、`AliyunOSSReadOnlyAccess`、`AliyunLiveReadOnlyAccess`、`AliyunVODReadOnlyAccess`；再加证书的 `AliyunYundunCertReadOnlyAccess` |
| 部署 | 把上面的 `ReadOnlyAccess` 换成 `FullAccess`，比如 `AliyunCDNFullAccess`、`AliyunYundunCertFullAccess` |
| 签发 | `AliyunDNSFullAccess` |

最小权限（在只读之上追加）：

- 部署
  - 证书：`yundun-cert:UploadUserCertificate`、`yundun-cert:ListUserCertificateOrder`、`yundun-cert:GetUserCertificateDetail`
  - CDN：`cdn:SetCdnDomainSSLCertificate`；DCDN：`dcdn:SetDcdnDomainSSLCertificate`；直播：`live:SetLiveDomainCertificate`；点播：`vod:SetVodDomainSSLCertificate`；ESA：`esa:SetCertificate`、`esa:UpdateCustomHostname`
  - OSS：`oss:PutCname`，还要让 OSS 能读证书：`yundun-cert:DescribeSSLCertificatePrivateKey`、`yundun-cert:DescribeSSLCertificatePublicKeyDetail`、`yundun-cert:CreateSSLCertificate`
- 签发：`alidns:DescribeDomains`（资源只能填 `*`）；`alidns:DescribeSubDomainRecords`、`alidns:AddDomainRecord`、`alidns:DeleteDomainRecord`（可以限定到域名：`acs:alidns::<账号ID>:domain/<域名>`）

## 腾讯云

省事做法：

| 命令 | 预设策略 |
| --- | --- |
| 查询 | 用到的产品的只读策略：CDN、EdgeOne、COS（`QcloudCOSReadOnlyAccess`）、云直播、云点播；再加 SSL 证书的只读策略。在 CAM 控制台按产品名搜「只读」 |
| 部署 | 换成对应产品的全读写策略（FullAccess） |
| 签发 | `QcloudDNSPodFullAccess` |

最小权限（在只读之上追加）：

- 部署：`ssl:UploadCertificate`；CDN：`cdn:ModifyDomainConfig`、`cdn:UpdateDomainConfig`；EdgeOne：`teo:ModifyHostsCertificate`；COS：`cos:PutBucketDomainCertificate`；直播：`live:ModifyLiveDomainCertBindings`；点播：`vod:SetVodDomainCertificate`
- 签发：`dnspod:DescribeDomainList`（资源只能选全部）；`dnspod:DescribeRecordList`、`dnspod:CreateRecord`、`dnspod:DeleteRecord`（可以按域名授权：`qcs::dnspod::uin/<主账号ID>:domain/<DomainId>`）

## 火山引擎

省事做法：

| 命令 | 系统策略 |
| --- | --- |
| 查询 | `CDNReadOnlyAccess`、`DCDNReadOnlyAccess`、`TOSReadOnlyAccess`、`VodReadOnlyAccess`、`LIVEReadOnlyAccess`、`ImageXReadOnlyAccess`；再加证书中心的 `SSLReadOnly` |
| 部署 | 换成对应产品（含证书中心）的 FullAccess |
| 签发 | `DNSFullAccess` |

最小权限（在只读之上追加）：

- 部署
  - 证书中心：`ImportCertificate`
  - CDN：`BatchDeployCert`；DCDN：`CreateCertBind`、`DescribeDomainDetail`、`UpdateDomainConfig`；TOS：`GetBucketCustomDomain`、`PutBucketCustomDomain`
  - 点播：`DescribeVodDomainConfig`、`UpdateVodDomainConfig`；直播：`ListCertV2`、`DescribeCertDetailSecretV2`、`CreateCert`、`BindCert`；veImageX：`GetDomainConfig`、`UpdateHttps`
- 签发：`dns:ListZones`、`dns:ListRecords`、`dns:CreateRecord`、`dns:DeleteRecord`

## 华为云

省事做法：

| 命令 | 系统策略 |
| --- | --- |
| 查询 | `CDN DomainReadOnlyAccess`、`SCM ReadOnlyAccess`、`Live ReadOnlyAccess`；OBS 见下方注意 |
| 部署 | `CDN DomainConfiguration`、`SCM FullAccess`、`Live FullAccess`；OBS 见下方注意。只部署 CDN 时不需要 `SCM FullAccess` |
| 签发 | `DNS FullAccess` |

注意：

- **项目级策略要授权到对的地域。** `Live ReadOnlyAccess`、`Live FullAccess` 授权到直播所在地域的项目；`DNS FullAccess` 授权到华北-北京四（cn-north-4）。不想区分就选「所有资源」。
- **OBS 没有现成的系统策略可用**（`OBS ReadOnlyAccess` 不含读取自定义域名）。自己建策略：查询要 `obs:bucket:ListAllMyBuckets`、`obs:bucket:GetBucketCustomDomainConfiguration`（或者直接给全局只读 `Tenant Guest`），部署再加 `obs:bucket:PutBucketCustomDomainConfiguration`。

最小权限：

- 云证书管理（部署）：`scm:cert:import`、`scm:cert:get`、`scm:cert:list`
- 签发：`dns:zone:list`、`dns:recordset:list`、`dns:recordset:create`、`dns:recordset:update`、`dns:recordset:delete`（同样授权到 cn-north-4 或所有资源）

## 百度智能云

| 命令 | 授予什么 |
| --- | --- |
| 查询 | `CdnReadAccessPolicy`（CDN）、`CASReadPolicy`（证书管理，要选产品级权限） |
| 部署 | 再加证书管理的创建证书、查看证书详情权限，CDN 域名配置的写权限 |
| 签发 | `DNSOperatePolicy` |

注意：签发前要先在控制台开通智能云解析，否则报缺少服务角色 `BceServiceRole_console_dns`。另外百度智能云解析目前实测签不出证书，见[已知限制](limitations.md#百度智能云)。

## 七牛云

| 命令 | 授予什么 |
| --- | --- |
| 查询 | 用主账号 AK；或给 IAM 子账号建自定义策略，授权 `cdn/GetDomainList`、`cdn/GetDomainInfo`（七牛没有现成的只读策略） |
| 部署 | 用主账号 AK；或给 IAM 子账号加 CDN 域名配置的写权限和 SSL 证书上传权限 |
| 签发 | 七牛没有 DNS 服务 |

## 其他 DNS 服务商

这几家只用于 `issue`。

| 服务商 | 怎么授权 | 注意 |
| --- | --- | --- |
| Cloudflare | dash.cloudflare.com → My Profile → API Tokens，创建 Custom Token：权限 `Zone → Zone → Read` + `Zone → DNS → Edit`，Zone Resources 选要签发的 zone 或 All zones | 「Edit zone DNS」模板缺 `Zone → Zone → Read`，要手动加上。不支持 Global API Key |
| AWS Route 53 | IAM 用户授权 `route53:ListHostedZones`、`route53:ListResourceRecordSets`、`route53:ChangeResourceRecordSets` | 账号里有多个同名公网 zone 时，还要 `route53:GetHostedZone`，否则报 `ZoneAmbiguous` |
| Google Cloud DNS | 服务账号授予 DNS 管理员（`roles/dns.admin`） | 项目要启用 Cloud DNS API（`dns.googleapis.com`），否则报 `accessNotConfigured` |
| Azure DNS | 应用注册 + 客户端密码，给这个服务主体分配「DNS 区域参与者」（DNS Zone Contributor） | 分配在**订阅**上：列 zone 用的是订阅级接口 |
| DigitalOcean | Personal Access Token：Full Access，或 Custom Scopes 勾选 `domain:read` + `domain:update` | Read Only 令牌不能用 |
| GoDaddy | developer.godaddy.com 创建 **Production** 环境的 API Key | OTE 测试环境的 Key 不能用。Key 没有细分权限，等同账号的域名管理权限。账号不满足 GoDaddy 的 API 开放条件时，所有请求返回 403 |

想收紧权限时：

- AWS Route 53：`ListHostedZones` 的 Resource 只能是 `*`；另外两个可以限定为 `arn:aws:route53:::hostedzone/<zone ID>`。写权限还能用条件键收窄到验证记录：`route53:ChangeResourceRecordSetsRecordTypes` = `TXT`、`route53:ChangeResourceRecordSetsActions` = `UPSERT` / `DELETE`、`route53:ChangeResourceRecordSetsNormalizedRecordNames` 匹配 `_acme-challenge.*`。
- Google Cloud DNS：自定义角色包含 `dns.managedZones.list`、`dns.resourceRecordSets.list`、`dns.changes.create`、`dns.changes.get`、`dns.resourceRecordSets.create`、`dns.resourceRecordSets.update`、`dns.resourceRecordSets.delete`，授予在项目上。
- Azure DNS：自定义角色最少要 `Microsoft.Network/dnsZones/read`、`Microsoft.Network/dnsZones/TXT/read`、`Microsoft.Network/dnsZones/TXT/write`、`Microsoft.Network/dnsZones/TXT/delete`。
