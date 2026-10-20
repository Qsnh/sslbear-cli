# 安全策略

sslbear-cli 会读取云厂商与 DNS 服务商的凭证、处理证书私钥，并修改线上的 HTTPS 配置和 DNS 记录。

## 报告漏洞

请不要公开提 issue。在仓库的 [Security → Report a vulnerability](https://github.com/Qsnh/sslbear-cli/security/advisories/new) 私下报告，写明版本、复现步骤和影响范围。报告里不要附真实凭证或私钥。

以下情况都算安全问题：

- 凭证、Token 或私钥出现在输出、错误信息或日志里
- 签名实现缺陷，导致请求被篡改或重放
- 证书、私钥、ACME 账号私钥文件的权限过宽
- `deploy` 修改了 HTTPS 证书以外的配置，或者 `issue` 删除了不是它添加的 DNS 记录

## 支持的版本

只修复最新发布的版本，请先升级到最新版（`npx sslbear-cli@latest`）确认问题仍然存在。

## 凭证泄露了怎么办

立即到对应的云控制台禁用并轮换 AccessKey / Token，再检查操作审计日志。建议平时就使用只授予所需权限的子账号，见 [docs/permissions.md](docs/permissions.md)。
