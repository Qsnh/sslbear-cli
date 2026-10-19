# 所需权限

缺某个服务的权限时，只有这个服务会出现在 `issues`（或 `failed`）里，其他服务照常输出。`deploy` 只部署部分服务时，只需授予对应服务的写权限。

`issue` 只需要域名所在那家 DNS 服务商的权限：列出 zone，查询、添加、删除解析记录。`--dry-run` 只用到列出 zone。

部分服务的域名接口只返回证书 ID，CLI 会再用该云的证书列表补全证书的到期时间、名称等信息，所以建议同时授予**证书服务的只读权限**。涉及的服务：腾讯云直播、点播、EdgeOne、COS，火山引擎 DCDN、TOS、点播、veImageX，华为云直播、OBS，百度智能云 CDN，七牛云 CDN。补全失败只记一条 issue，域名照常输出。

## 阿里云

- 只读（`domains` / `certs`）：CDN、DCDN、ESA（`AliyunESAReadOnlyAccess`）、OSS、视频直播、视频点播、数字证书管理服务的 ReadOnly 系统策略。CDN、DCDN、直播的证书信息来自各自的 HTTPS 证书列表接口，查不到时只记一条 issue；CDN、DCDN 的 HTTPS 状态以域名列表里的开关为准，直播没有开关，这时显示为关闭。
- `deploy` 追加（也可以直接给各产品的 FullAccess）：
  - 数字证书管理服务：`yundun-cert:UploadUserCertificate`、`ListUserCertificateOrder`、`GetUserCertificateDetail`（或 `AliyunYundunCertFullAccess`）
  - CDN：`cdn:SetCdnDomainSSLCertificate`；DCDN：`dcdn:SetDcdnDomainSSLCertificate`
  - 直播：`live:SetLiveDomainCertificate`；点播：`vod:SetVodDomainSSLCertificate`
  - OSS：`oss:PutCname`，另需让 OSS 读取证书服务里证书的权限：`yundun-cert:DescribeSSLCertificatePrivateKey`、`DescribeSSLCertificatePublicKeyDetail`、`CreateSSLCertificate`
  - ESA：`esa:SetCertificate`、`esa:UpdateCustomHostname`
- `issue`（云解析 DNS）：`AliyunDNSFullAccess`，或包含 `alidns:DescribeDomains`、`alidns:DescribeSubDomainRecords`、`alidns:AddDomainRecord`、`alidns:DeleteDomainRecord` 的自定义策略。`DescribeDomains` 要授权全部资源，其余三个可以限定到域名（`acs:alidns::<账号ID>:domain/<域名>`）。

## 腾讯云

- 只读：CDN、EdgeOne、COS（`QcloudCOSReadOnlyAccess`）、云直播、云点播、SSL 证书的只读策略。
- `deploy` 追加：`ssl:UploadCertificate`、`cdn:ModifyDomainConfig`、`cdn:UpdateDomainConfig`、`teo:ModifyHostsCertificate`、`cos:PutBucketDomainCertificate`、`live:ModifyLiveDomainCertBindings`、`vod:SetVodDomainCertificate`。
- `issue`（DNSPod）：`QcloudDNSPodFullAccess`，或包含 `dnspod:DescribeDomainList`、`dnspod:DescribeRecordList`、`dnspod:CreateRecord`、`dnspod:DeleteRecord` 的自定义策略。后三个可以按域名授权（`qcs::dnspod::uin/<主账号ID>:domain/<DomainId>`），`DescribeDomainList` 要授权全部资源。

## 火山引擎

- 只读：`CDNReadOnlyAccess`、`DCDNReadOnlyAccess`、`TOSReadOnlyAccess`、`VodReadOnlyAccess`、`LIVEReadOnlyAccess`、`ImageXReadOnlyAccess`、`SSLReadOnly`（证书中心）。
- `deploy` 追加（也可以给对应产品的 FullAccess）：
  - 证书中心：`ImportCertificate`
  - CDN：`BatchDeployCert`
  - DCDN：`CreateCertBind`、`DescribeDomainDetail`、`UpdateDomainConfig`
  - TOS：`GetBucketCustomDomain`、`PutBucketCustomDomain`
  - 点播：`DescribeVodDomainConfig`、`UpdateVodDomainConfig`
  - 直播：`ListCertV2`、`DescribeCertDetailSecretV2`、`CreateCert`、`BindCert`
  - veImageX：`GetDomainConfig`、`UpdateHttps`
- `issue`（云解析 DNS）：`DNSFullAccess`，或授权 `dns:ListZones`、`dns:ListRecords`、`dns:CreateRecord`、`dns:DeleteRecord` 的自定义策略。

## 华为云

- 只读：
  - `CDN DomainReadOnlyAccess`、`SCM ReadOnlyAccess`
  - `Live ReadOnlyAccess`：项目级策略，要授权到直播所在地域的项目，或授权所有资源
  - OBS：`OBS ReadOnlyAccess` 不包含「获取桶的自定义域名」，需要另加包含 `obs:bucket:ListAllMyBuckets`、`obs:bucket:GetBucketCustomDomainConfiguration` 的自定义策略，或者直接授予全局只读 `Tenant Guest`
  - 查询项目 ID 用的 IAM 接口不需要额外权限
- `deploy` 追加：
  - CDN：`CDN DomainConfiguration`
  - 直播：`Live FullAccess`（授权到直播所在地域的项目）
  - 云证书管理：`SCM FullAccess`，或包含 `scm:cert:import`、`scm:cert:get`、`scm:cert:list` 的自定义策略（只部署 CDN 时不需要）
  - OBS：包含 `obs:bucket:PutBucketCustomDomainConfiguration` 的自定义策略
- `issue`（云解析服务 DNS）：`DNS FullAccess`，或包含 `dns:zone:list`、`dns:recordset:list`、`dns:recordset:create`、`dns:recordset:update`、`dns:recordset:delete` 的自定义策略。这是项目级策略，要授权到华北-北京四（cn-north-4）项目，或授权所有资源。

## 百度智能云

- 只读：`CdnReadAccessPolicy`（CDN）、`CASReadPolicy`（证书管理，需要产品级权限）。
- `deploy` 追加：证书管理的创建证书和查看证书详情（查重要用）权限，CDN 域名配置的写权限。
- `issue`（智能云解析）：`DNSOperatePolicy`。账号要先在控制台开通智能云解析，否则报缺少服务角色 `BceServiceRole_console_dns`。

## 七牛云

- 只读：没有现成的只读系统策略。可以用主账号 AK，或给 IAM 子账号建自定义策略，授权 `cdn/GetDomainList`、`cdn/GetDomainInfo`。
- `deploy`：主账号 AK，或者有 CDN 域名配置写权限和 SSL 证书上传权限的 IAM 子账号。

## Cloudflare（issue）

- 在 dash.cloudflare.com → My Profile → API Tokens 创建 Custom Token：权限 `Zone → Zone → Read` + `Zone → DNS → Edit`，Zone Resources 选要签发的 zone 或 All zones。模板「Edit zone DNS」缺 Zone Read，要手动加上。不支持 Global API Key。

## AWS Route 53（issue）

- `route53:ListHostedZones`（Resource 只能是 `*`）、`route53:ListResourceRecordSets`、`route53:ChangeResourceRecordSets`（Resource 为 `arn:aws:route53:::hostedzone/<zone ID>` 或 `hostedzone/*`）。
- 可选 `route53:GetHostedZone`：账号里有多个同名公网 zone 时用来取各自的 NS；没有这项权限时这种情况报 `ZoneAmbiguous`。
- 写权限可以用条件键收窄到验证记录：`route53:ChangeResourceRecordSetsRecordTypes` = `TXT`、`route53:ChangeResourceRecordSetsActions` = `UPSERT` / `DELETE`、`route53:ChangeResourceRecordSetsNormalizedRecordNames` 匹配 `_acme-challenge.*`。

## Google Cloud DNS（issue）

- 服务账号授予 DNS 管理员（`roles/dns.admin`），或包含 `dns.managedZones.list`、`dns.resourceRecordSets.list`、`dns.changes.create`、`dns.changes.get`、`dns.resourceRecordSets.create`、`dns.resourceRecordSets.update`、`dns.resourceRecordSets.delete` 的自定义角色。`dns.managedZones.list` 要授予在项目上。
- 项目要启用 Cloud DNS API（`dns.googleapis.com`），否则报 `accessNotConfigured`。

## Azure DNS（issue）

- 给服务主体（应用注册 + 客户端密码）分配「DNS 区域参与者」（DNS Zone Contributor），建议分配在订阅上：列 zone 用的是订阅级接口。
- 自定义角色最少需要 `Microsoft.Network/dnsZones/read`、`Microsoft.Network/dnsZones/TXT/read`、`Microsoft.Network/dnsZones/TXT/write`、`Microsoft.Network/dnsZones/TXT/delete`。

## DigitalOcean（issue）

- Personal Access Token：Full Access，或 Custom Scopes 勾选 `domain:read` + `domain:update`。Read Only 令牌不能用。

## GoDaddy（issue）

- 在 developer.godaddy.com 创建 **Production** 环境的 API Key（OTE 测试环境的不能用）。Key 没有细分权限，等同账号的域名管理权限。
- 账号要满足 GoDaddy 的 API 开放条件，否则所有请求返回 403。
