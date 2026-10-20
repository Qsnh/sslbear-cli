# 所需权限

建一个子账号（阿里云 RAM、腾讯云 CAM、其他云的 IAM），按要用的命令授权：

| 要用的命令 | 授予什么 |
| --- | --- |
| 查询：`domains` / `certs` | 用到的服务的只读权限，加上证书服务的只读权限 |
| 部署：`deploy` | 在只读的基础上，加上传证书、修改域名 HTTPS 配置的写权限 |
| 签发：`issue` | 只要域名所在 DNS 服务商的解析权限：列出域名，增删解析记录 |

每家云先给一张按服务列出的系统策略表（省事做法），再给最小权限（想收紧时自己建策略）。策略名、权限名都按各家 2026-10 的官方文档核对过。

注意：

- **证书服务的只读权限要给。** `certs` 和部署都要用；腾讯云、火山引擎、华为云、百度智能云、七牛云的部分服务还靠它查到期时间，缺了到期时间是空的。
- 缺权限不会让整条命令失败：只有缺权限的服务出现在 `issues`（或 `failed`）里，其他服务照常输出。
- 部署前会先查询一遍，所以部署也要有查询权限。只部署部分服务时，只给这几个服务的写权限就行。
- `issue --dry-run` 只需要列出域名的权限。

跳转：[阿里云](#阿里云) · [腾讯云](#腾讯云) · [火山引擎](#火山引擎) · [华为云](#华为云) · [百度智能云](#百度智能云) · [七牛云](#七牛云) · [其他 DNS 服务商](#其他-dns-服务商)

## 阿里云

| 服务 | 查询 | 部署 |
| --- | --- | --- |
| CDN | `AliyunCDNReadOnlyAccess` | `AliyunCDNFullAccess` |
| 全站加速 DCDN | `AliyunDCDNReadOnlyAccess` | `AliyunDCDNFullAccess` |
| 边缘安全加速 ESA | `AliyunESAReadOnlyAccess` | `AliyunESAFullAccess` |
| 对象存储 OSS | `AliyunOSSReadOnlyAccess` | `AliyunOSSFullAccess` |
| 视频直播 | `AliyunLiveReadOnlyAccess` | `AliyunLiveFullAccess` |
| 视频点播 | `AliyunVODReadOnlyAccess` | `AliyunVODFullAccess` |
| 数字证书管理服务 | `AliyunYundunCertReadOnlyAccess` | `AliyunYundunCertFullAccess` |

签发（云解析 DNS）：`AliyunDNSFullAccess`；只跑 `--dry-run` 时 `AliyunDNSReadOnlyAccess` 就够。

最小权限（2026-10 实测：子账号只挂一条含下列 Action 的自定义策略，资源填 `*`，查询、部署、签发都能跑通）：

- 查询
  - 数字证书管理服务：`yundun-cert:ListUserCertificateOrder`、`yundun-cert:GetUserCertificateDetail`
  - CDN：`cdn:DescribeUserDomains`、`cdn:DescribeCdnHttpsDomainList`；全站加速：`dcdn:DescribeDcdnUserDomains`、`dcdn:DescribeDcdnHttpsDomainList`
  - ESA：`esa:ListSites`、`esa:ListRecords`、`esa:ListCertificates`、`esa:ListHttpsBasicConfigurations`、`esa:ListCustomHostnames`
  - OSS：`oss:ListBuckets`、`oss:ListCname`
  - 视频直播：`live:DescribeLiveUserDomains`、`live:DescribeLiveHttpsDomainList`；视频点播：`vod:DescribeVodUserDomains`、`vod:DescribeVodDomainCertificateInfo`
- 部署（在查询的基础上再加）
  - 所有服务都要：`yundun-cert:UploadUserCertificate`（部署前先把证书上传到数字证书管理服务）
  - CDN：`cdn:SetCdnDomainSSLCertificate`；全站加速：`dcdn:SetDcdnDomainSSLCertificate`
  - ESA：`esa:SetCertificate`；有 SaaS 域名时再加 `esa:UpdateCustomHostname`
  - OSS：`oss:PutCname`，外加 `yundun-cert:DescribeSSLCertificatePrivateKey`、`yundun-cert:DescribeSSLCertificatePublicKeyDetail`（OSS 用你的身份去证书服务读证书）。OSS 文档里的第三项 `yundun-cert:CreateSSLCertificate` 实测不需要
  - 视频直播：`live:SetLiveDomainCertificate`；视频点播：`vod:SetVodDomainSSLCertificate`
- 签发（只需要这几项）：`alidns:DescribeDomains`（资源只能填 `*`）；`alidns:DescribeSubDomainRecords`、`alidns:AddDomainRecord`、`alidns:DeleteDomainRecord`（可以限定到域名：`acs:alidns::<账号ID>:domain/<域名>`）

<details>
<summary>完整的自定义策略（查询 + 部署 + 签发，可直接粘贴到 RAM「创建权限策略 → 脚本编辑」）</summary>

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "yundun-cert:ListUserCertificateOrder",
        "yundun-cert:GetUserCertificateDetail",
        "yundun-cert:UploadUserCertificate",
        "yundun-cert:DescribeSSLCertificatePrivateKey",
        "yundun-cert:DescribeSSLCertificatePublicKeyDetail",
        "cdn:DescribeUserDomains",
        "cdn:DescribeCdnHttpsDomainList",
        "cdn:SetCdnDomainSSLCertificate",
        "dcdn:DescribeDcdnUserDomains",
        "dcdn:DescribeDcdnHttpsDomainList",
        "dcdn:SetDcdnDomainSSLCertificate",
        "esa:ListSites",
        "esa:ListRecords",
        "esa:ListCertificates",
        "esa:ListHttpsBasicConfigurations",
        "esa:ListCustomHostnames",
        "esa:SetCertificate",
        "esa:UpdateCustomHostname",
        "oss:ListBuckets",
        "oss:ListCname",
        "oss:PutCname",
        "live:DescribeLiveUserDomains",
        "live:DescribeLiveHttpsDomainList",
        "live:SetLiveDomainCertificate",
        "vod:DescribeVodUserDomains",
        "vod:DescribeVodDomainCertificateInfo",
        "vod:SetVodDomainSSLCertificate",
        "alidns:DescribeDomains",
        "alidns:DescribeSubDomainRecords",
        "alidns:AddDomainRecord",
        "alidns:DeleteDomainRecord"
      ],
      "Resource": "*"
    }
  ]
}
```

不用的服务、不用的命令，把对应的行删掉即可。

</details>

## 腾讯云

| 服务 | 查询 | 部署 |
| --- | --- | --- |
| CDN | `QcloudCDNReadOnlyAccess` | `QcloudCDNFullAccess` |
| EdgeOne | `QcloudTEOReadOnlyaccess`（官方文档的写法，大小写以控制台为准） | `QcloudTEOFullAccess` |
| 对象存储 COS | `QcloudCOSReadOnlyAccess` | `QcloudCOSFullAccess` |
| 云直播 | `QcloudLIVEReadOnlyAccess` | `QcloudLIVEFullAccess` |
| 云点播 | `QcloudVODReadonlyAccess` | `QcloudVODFullAccess` |
| SSL 证书 | `QcloudSSLReadOnlyAccess` | `QcloudSSLFullAccess` |

签发（DNSPod）：`QcloudDNSPodFullAccess`；只跑 `--dry-run` 时 `QcloudDNSPodReadOnlyAccess` 就够。

最小权限（2026-10 实测：子账号只挂一条含下列 Action 的自定义策略，资源填 `*`，查询、部署、签发都能跑通）：

- 查询
  - SSL 证书：`ssl:DescribeCertificates`
  - CDN：`cdn:DescribeDomainsConfig`；EdgeOne：`teo:DescribeZones`、`teo:DescribeAccelerationDomains`
  - COS：`cos:GetService`、`cos:GetBucketDomain`、`cos:GetBucketDomainCertificate`
  - 云直播：`live:DescribeLiveDomains`、`live:DescribeLiveDomainCertBindings`；云点播：`vod:DescribeVodDomains`、`vod:DescribeSubAppIds`
- 部署（在查询的基础上再加）
  - 所有服务都要：`ssl:UploadCertificate`（部署前先把证书上传到 SSL 证书服务）
  - CDN：`cdn:ModifyDomainConfig`、`cdn:UpdateDomainConfig`；EdgeOne：`teo:ModifyHostsCertificate`；COS：`cos:PutBucketDomainCertificate`
  - 云直播：`live:ModifyLiveDomainCertBindings`；云点播：`vod:SetVodDomainCertificate`
- 签发（只需要这几项）：`dnspod:DescribeDomainList`、`dnspod:DescribeRecordList`、`dnspod:CreateRecord`、`dnspod:DeleteRecord`。`--dry-run` 只要 `dnspod:DescribeDomainList`。都可以按域名授权，资源写 `qcs::dnspod::uin/<主账号ID>:domain/<DomainId>`（DomainId 是 DNSPod 里的域名 ID，不是域名）。只授权部分域名时 `DescribeDomainList` 会返回什么官方没写，稳妥起见它授权全部资源。

<details>
<summary>完整的自定义策略（查询 + 部署 + 签发，可直接粘贴到 CAM「新建自定义策略 → 按策略语法创建」）</summary>

```json
{
  "version": "2.0",
  "statement": [
    {
      "effect": "allow",
      "action": [
        "ssl:DescribeCertificates",
        "ssl:UploadCertificate",
        "cdn:DescribeDomainsConfig",
        "cdn:ModifyDomainConfig",
        "cdn:UpdateDomainConfig",
        "teo:DescribeZones",
        "teo:DescribeAccelerationDomains",
        "teo:ModifyHostsCertificate",
        "cos:GetService",
        "cos:GetBucketDomain",
        "cos:GetBucketDomainCertificate",
        "cos:PutBucketDomainCertificate",
        "live:DescribeLiveDomains",
        "live:DescribeLiveDomainCertBindings",
        "live:ModifyLiveDomainCertBindings",
        "vod:DescribeVodDomains",
        "vod:DescribeSubAppIds",
        "vod:SetVodDomainCertificate",
        "dnspod:DescribeDomainList",
        "dnspod:DescribeRecordList",
        "dnspod:CreateRecord",
        "dnspod:DeleteRecord"
      ],
      "resource": ["*"]
    }
  ]
}
```

不用的服务、不用的命令，把对应的行删掉即可。

</details>

## 火山引擎

| 服务 | 查询 | 部署 |
| --- | --- | --- |
| CDN | `CDNReadOnlyAccess` | `CDNFullAccess` |
| 全站加速 DCDN | `DCDNReadOnlyAccess` | `DCDNFullAccess` |
| 对象存储 TOS | `TOSReadOnlyAccess` | `TOSFullAccess` |
| 视频点播 | `VodReadOnlyAccess` | `VodFullAccessV2` |
| 视频直播 | `LIVEReadOnlyAccess` | `LIVEFullAccess` |
| veImageX | `ImageXReadOnlyAccess` | `ImageXFullAccessV2` |
| 证书中心 | `SSLReadOnly` | `SSLFullAccess` |

签发（云解析 DNS）：`DNSFullAccess`；只跑 `--dry-run` 时 `DNSReadOnlyAccess` 就够。

注意：

- 点播、veImageX 的 FullAccess 在 2026-08-20 升级成了带 V2 的版本，旧的 `VodFullAccess`、`ImageXFullAccess` 不要再用。
- **第一次部署前要做跨服务授权。** CDN、全站加速、TOS、点播、veImageX 要获得授权才能访问证书中心里的证书。用主账号在该产品控制台给域名配一次 HTTPS 证书，按提示完成授权即可；子用户默认没有跨服务授权的权限。TOS 没授权时证书状态是 `RoleNotExist`。

最小权限（2026-10 实测：子账号只挂一条含下列 Action 的自定义策略，资源填 `*`，查询、部署、签发都能跑通）：

- 查询
  - 证书中心：`certificate_service:CertificateGetInstanceList`
  - CDN：`CDN:ListCdnDomains`、`CDN:ListCdnCertInfo`；全站加速：`DCDN:ListDomainConfig`
  - TOS：`tos:ListBuckets`、`tos:GetBucketCustomDomain`
  - 点播：`vod:ListSpace`、`vod:ListVodDomains`、`vod:DescribeVodDomainConfig`
  - 直播：`live:ListDomainDetail`、`live:ListCertV2`、`live:DescribeCertDetailSecretV2`
  - veImageX：`ImageX:GetAllImageServices`、`ImageX:GetServiceDomains`、`ImageX:GetDomainConfig`、`ImageX:GetImageAllDomainCert`
- 部署（在查询的基础上再加）
  - 证书中心：`certificate_service:ImportCertificate`（直播以外的服务都先把证书上传到证书中心）
  - CDN：`CDN:BatchDeployCert`；全站加速：`DCDN:CreateCertBind`，给没开 HTTPS 的域名部署时再加 `DCDN:DescribeDomainDetail`、`DCDN:UpdateDomainConfig`
  - TOS：`tos:PutBucketCustomDomain`；点播：`vod:UpdateVodDomainConfig`；veImageX：`ImageX:UpdateHttps`
  - 直播：`live:CreateCert`、`live:BindCert`（直播用自己的证书管理，不用证书中心）
- 签发（只需要这几项）：`dns:ListZones`、`dns:ListRecords`、`dns:CreateRecord`、`dns:DeleteRecord`。`--dry-run` 只要 `dns:ListZones`。

CDN、全站加速、TOS、点播、veImageX 靠跨服务授权读证书中心里的证书，子账号不需要额外的证书读权限（与阿里云 OSS 不同）。

<details>
<summary>完整的自定义策略（查询 + 部署 + 签发，可直接粘贴到访问控制「新建策略 → JSON 编辑」）</summary>

```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "certificate_service:CertificateGetInstanceList",
        "certificate_service:ImportCertificate",
        "CDN:ListCdnDomains",
        "CDN:ListCdnCertInfo",
        "CDN:BatchDeployCert",
        "DCDN:ListDomainConfig",
        "DCDN:DescribeDomainDetail",
        "DCDN:CreateCertBind",
        "DCDN:UpdateDomainConfig",
        "tos:ListBuckets",
        "tos:GetBucketCustomDomain",
        "tos:PutBucketCustomDomain",
        "vod:ListSpace",
        "vod:ListVodDomains",
        "vod:DescribeVodDomainConfig",
        "vod:UpdateVodDomainConfig",
        "live:ListDomainDetail",
        "live:ListCertV2",
        "live:DescribeCertDetailSecretV2",
        "live:CreateCert",
        "live:BindCert",
        "ImageX:GetAllImageServices",
        "ImageX:GetServiceDomains",
        "ImageX:GetDomainConfig",
        "ImageX:GetImageAllDomainCert",
        "ImageX:UpdateHttps",
        "dns:ListZones",
        "dns:ListRecords",
        "dns:CreateRecord",
        "dns:DeleteRecord"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
```

不用的服务、不用的命令，把对应的行删掉即可。

</details>

## 华为云

华为云 IAM 有新旧两套授权，策略名互不通用：新版控制台授予「身份策略」，旧版在「权限管理」里授予「角色与策略」。官方说新版按账号逐步开放，看你的 IAM 控制台是哪套，用对应那一列。

| 服务 | 用途 | 旧版（角色与策略） | 新版（身份策略） |
| --- | --- | --- | --- |
| CDN | 查询 | `CDN DomainReadOnlyAccess` | `CDNDomainReadOnlyPolicy` |
| CDN | 部署（再加） | `CDN DomainConfiguration` | `CDNDomainConfigurationPolicy` |
| 云证书管理 CCM | 查询 | `SCM ReadOnlyAccess` | `SCMReadOnlyPolicy` |
| 云证书管理 CCM | 部署 | `SCM FullAccess` | `SCMFullPolicy` |
| 视频直播 | 查询 | `Live ReadOnlyAccess` | `LiveReadOnlyPolicy` |
| 视频直播 | 部署 | `Live FullAccess` | `LiveFullAccessPolicy` |
| 对象存储 OBS | 查询 | `Tenant Guest`（全部服务只读，范围大），或自定义策略 | 自定义身份策略 |
| 对象存储 OBS | 部署 | `OBS Administrator`，或自定义策略 | `OBSFullAccessPolicy`，或自定义身份策略 |
| 云解析服务 DNS | 签发 | `DNS FullAccess` | `DNSFullAccessPolicy` |

注意：

- **旧版要选对授权范围。** CDN、云证书管理、OBS 是全局服务，选「全局服务资源」；视频直播选直播所在地域的项目；云解析 DNS 选华北-北京四（cn-north-4）。不想区分就选「所有资源」。新版没有这一步。
- `CDN DomainConfiguration` 不能单独给，要和 `CDN DomainReadOnlyAccess` 一起给（官方要求）。
- 只部署 CDN 时不需要云证书管理的写权限。
- OBS 的只读系统策略（`OBS ReadOnlyAccess`、`OBSReadOnlyPolicy`）不含读取桶的自定义域名，不能用。

最小权限（2026-10 实测新版：子账号只挂一条含下列授权项的自定义身份策略，查询、部署、签发都能跑通）：

- 查询
  - 云证书管理：`scm:cert:list`
  - CDN：`cdn:configuration:queryDomainList`
  - OBS：`obs:bucket:listAllMyBuckets`、`obs:bucket:getBucketCustomDomainConfiguration`
  - 视频直播：`live:domain:getDomains`、`live:domain:getCertificates`、`live:domain:getCDNConfig`
- 部署（在查询的基础上再加）
  - 云证书管理（OBS、直播要用）：`scm:cert:get`、`scm:cert:import`；部署直播再加 `scm:cert:export`（直播用你的身份从云证书管理导出证书）
  - CDN：`cdn:configuration:queryDomains`、`cdn:configuration:modifyHttpsConf`、`cdn:configuration:modifyOriginConfInfo`（修改域名配置的接口两项都检查）
  - OBS：`obs:bucket:putBucketCustomDomainConfiguration`；视频直播：`live:domain:updateCDNConfig`
- 签发（只需要这几项）：`dns:zone:list`、`dns:recordset:list`、`dns:recordset:create`、`dns:recordset:update`、`dns:recordset:delete`。官方给其中几项列的云监控（`ces:`）依赖授权项实测不需要。`--dry-run` 只要 `dns:zone:list`。

<details>
<summary>完整的自定义身份策略（新版，查询 + 部署 + 签发，可直接粘贴到 IAM「身份策略 → 创建自定义身份策略 → JSON 视图」）</summary>

```json
{
  "Version": "5.0",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "scm:cert:list",
        "scm:cert:get",
        "scm:cert:import",
        "scm:cert:export",
        "cdn:configuration:queryDomainList",
        "cdn:configuration:queryDomains",
        "cdn:configuration:modifyHttpsConf",
        "cdn:configuration:modifyOriginConfInfo",
        "obs:bucket:listAllMyBuckets",
        "obs:bucket:getBucketCustomDomainConfiguration",
        "obs:bucket:putBucketCustomDomainConfiguration",
        "live:domain:getDomains",
        "live:domain:getCertificates",
        "live:domain:getCDNConfig",
        "live:domain:updateCDNConfig",
        "dns:zone:list",
        "dns:recordset:list",
        "dns:recordset:create",
        "dns:recordset:update",
        "dns:recordset:delete"
      ]
    }
  ]
}
```

不用的服务、不用的命令，把对应的行删掉即可。

</details>

旧版（角色与策略）的自定义策略没有实测，授权项以官方授权项列表为准（如 DNS 的[旧版列表](https://support.huaweicloud.com/api-dns/dns_api_70002.html)）。已知和新版不同的地方：OBS 三项首字母大写（`obs:bucket:ListAllMyBuckets`、`obs:bucket:GetBucketCustomDomainConfiguration`、`obs:bucket:PutBucketCustomDomainConfiguration`），上传证书是 `scm:cert:upload`；DNS 是项目级服务，要单独建一个策略，不能和 OBS、云证书管理放在同一个策略里。

## 百度智能云

| 服务 | 查询 | 部署 |
| --- | --- | --- |
| CDN | `CdnReadAccessPolicy` | `CdnOperateAccessPolicy` |
| 证书管理 | `CASReadPolicy` | `CASWritePolicy` |

签发（智能云解析）：`DNSOperatePolicy`；只跑 `--dry-run` 时 `DNSReadPolicy` 就够。

注意：

- **证书管理只能用这两个系统策略**（产品级）：实例级的自定义策略获取不了证书详情列表，也上传不了证书。
- 证书管理的策略名以 IAM 文档为准；个别官方 API 文档写作 `CASReadAccessPolicy`、`CASOperateAccessPolicy`，以控制台的系统策略列表为准。
- 实测：没开通智能云解析时，签发报缺少服务角色 `BceServiceRole_console_dns`，要先在控制台开通。另外百度智能云解析目前实测签不出证书，见[已知限制](limitations.md#百度智能云)。

最小权限：CDN 可以按域名收紧，自定义策略选服务 `bce:cdn`，授权 `QueryDomainList`（资源 `domain/*`）、`QueryDomainConfig`、`UpdateDomain`（资源 `domain/<域名>`）。

## 七牛云

| 用途 | 授予什么 |
| --- | --- |
| 查询 | 主账号 AK；或给 IAM 子账号建自定义策略：`cdn/GetDomainList`、`cdn/GetDomainInfo` |
| 部署 | 建议用主账号 AK。子账号要再加 `cdn/UpdateHttps` |
| 签发 | 七牛没有 DNS 服务 |

注意：

- **七牛 IAM 没有系统策略，也没有 SSL 证书服务的权限项。** 子账号可能查不到证书列表（`certs` 和到期时间补全会出现在 `issues` 里），也可能上传不了证书，所以部署建议用主账号 AK。
- 全站加速域名对应的权限项是 `dcdn/GetDomainList`、`dcdn/GetDomainInfo`、`dcdn/UpdateHttps`。

## 其他 DNS 服务商

这几家只用于 `issue`。

| 服务商 | 怎么授权 | 注意 |
| --- | --- | --- |
| Cloudflare | dash.cloudflare.com → My Profile → API Tokens → Create Token，选 Custom token：权限 `Zone → Zone → Read` + `Zone → DNS → Edit`，Zone Resources 选要签发的 zone 或 All zones | 「Edit zone DNS」模板缺 `Zone → Zone → Read`，要手动加上。不支持 Global API Key |
| AWS Route 53 | IAM 用户授权 `route53:ListHostedZones`、`route53:ListResourceRecordSets`、`route53:ChangeResourceRecordSets` | 账号里有多个同名公网 zone 时，还要 `route53:GetHostedZone`，否则报 `ZoneAmbiguous` |
| Google Cloud DNS | 服务账号在项目上授予 DNS Administrator（`roles/dns.admin`） | 项目要启用 Cloud DNS API（`dns.googleapis.com`），否则报 `accessNotConfigured` |
| Azure DNS | Microsoft Entra ID → 应用注册，新建应用后在「证书和机密」里新建客户端密码；再给这个应用分配「DNS 区域参与者」（DNS Zone Contributor） | 建议分配在订阅上：列 zone 用的是订阅级接口 |
| DigitalOcean | 控制台 Account → API → Tokens → Generate New Token：Full Access，或 Custom Scopes 勾选 `domain:read` + `domain:update` | Read Only 令牌不能用 |
| GoDaddy | 在 classic-developer.godaddy.com/keys 创建 **Production** 环境的 Key 和 Secret（Secret 只显示一次） | developer.godaddy.com 现在发的是 Personal Access Token，sslbear-cli 还不支持。OTE 测试环境的 Key 不能用。Key 不能限定权限范围。账号里至少要有 1 个域名（或有开通域名管理权限的套餐），否则返回 403 |

想收紧权限时：

- AWS Route 53：`ListHostedZones` 的 Resource 只能是 `*`；`GetHostedZone`、`ListResourceRecordSets`、`ChangeResourceRecordSets` 可以限定为 `arn:aws:route53:::hostedzone/<zone ID>`。写权限还能用条件键收窄到验证记录：用 `ForAllValues:StringEquals` 限定 `route53:ChangeResourceRecordSetsRecordTypes` 为 `TXT`、`route53:ChangeResourceRecordSetsActions` 为 `CREATE` 和 `DELETE`（sslbear-cli 不用 `UPSERT`）；用 `ForAllValues:StringLike` 限定 `route53:ChangeResourceRecordSetsNormalizedRecordNames` 为 `_acme-challenge.*`（小写，不带结尾的点）。
- Google Cloud DNS：自定义角色包含 `dns.managedZones.list`、`dns.resourceRecordSets.list`、`dns.changes.create`、`dns.changes.get`、`dns.resourceRecordSets.create`、`dns.resourceRecordSets.update`、`dns.resourceRecordSets.delete`，在项目上授予。
- Azure DNS：自定义角色最少要 `Microsoft.Network/dnsZones/read`、`Microsoft.Network/dnsZones/TXT/read`、`Microsoft.Network/dnsZones/TXT/write`、`Microsoft.Network/dnsZones/TXT/delete`，同样分配在订阅上。
