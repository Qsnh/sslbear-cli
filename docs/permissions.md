# 所需权限

缺某个服务的权限时，只有这个服务会出现在 `issues`（或 `failed`）里，其他服务照常输出。`deploy` 只部署部分服务时，只需授予对应服务的写权限。

部分服务的域名接口只返回证书 ID，CLI 会再用该云的证书列表补全证书的到期时间、名称等信息，所以建议同时授予**证书服务的只读权限**。涉及的服务：腾讯云直播、点播、EdgeOne、COS，火山引擎 DCDN、TOS、点播、veImageX，华为云直播、OBS，百度智能云 CDN，七牛云 CDN。补全失败只记一条 issue，域名照常输出。

## 阿里云

- 只读（`domains` / `certs`）：CDN、DCDN、ESA（`AliyunESAReadOnlyAccess`）、OSS、视频直播、视频点播、数字证书管理服务的 ReadOnly 系统策略。CDN、DCDN、直播的证书信息来自各自的 HTTPS 证书列表接口，查不到时只记一条 issue；CDN、DCDN 的 HTTPS 状态以域名列表里的开关为准，直播没有开关，这时显示为关闭。
- `deploy` 追加（也可以直接给各产品的 FullAccess）：
  - 数字证书管理服务：`yundun-cert:UploadUserCertificate`、`ListUserCertificateOrder`、`GetUserCertificateDetail`（或 `AliyunYundunCertFullAccess`）
  - CDN：`cdn:SetCdnDomainSSLCertificate`；DCDN：`dcdn:SetDcdnDomainSSLCertificate`
  - 直播：`live:SetLiveDomainCertificate`；点播：`vod:SetVodDomainSSLCertificate`
  - OSS：`oss:PutCname`，另需让 OSS 读取证书服务里证书的权限：`yundun-cert:DescribeSSLCertificatePrivateKey`、`DescribeSSLCertificatePublicKeyDetail`、`CreateSSLCertificate`
  - ESA：`esa:SetCertificate`、`esa:UpdateCustomHostname`

## 腾讯云

- 只读：CDN、EdgeOne、COS（`QcloudCOSReadOnlyAccess`）、云直播、云点播、SSL 证书的只读策略。
- `deploy` 追加：`ssl:UploadCertificate`、`cdn:ModifyDomainConfig`、`cdn:UpdateDomainConfig`、`teo:ModifyHostsCertificate`、`cos:PutBucketDomainCertificate`、`live:ModifyLiveDomainCertBindings`、`vod:SetVodDomainCertificate`。

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

## 百度智能云

- 只读：`CdnReadAccessPolicy`（CDN）、`CASReadPolicy`（证书管理，需要产品级权限）。
- `deploy` 追加：证书管理的创建证书和查看证书详情（查重要用）权限，CDN 域名配置的写权限。

## 七牛云

- 只读：没有现成的只读系统策略。可以用主账号 AK，或给 IAM 子账号建自定义策略，授权 `cdn/GetDomainList`、`cdn/GetDomainInfo`。
- `deploy`：主账号 AK，或者有 CDN 域名配置写权限和 SSL 证书上传权限的 IAM 子账号。
