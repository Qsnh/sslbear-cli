# sslbear-cli

给 AI agent 用的云服务域名 SSL 证书维护工具。查出各云域名证书的到期时间，向 Let's Encrypt 签发证书（自动设置 11 家 DNS 的验证记录），部署到阿里云、腾讯云、火山引擎、华为云、百度智能云、七牛云的 CDN、对象存储、直播、点播等服务。

## Skill

```bash
npx -y sslbear-cli@latest skill install
```

## 服务表

| 云服务商 | 服务 | 证书 |
| --- | --- | --- |
| `aliyun` | `cdn`、`dcdn`（全站加速）、`esa`（边缘安全加速）、`oss`、`live`（直播）、`vod`（点播） | 数字证书管理服务 |
| `tencent` | `cdn`、`teo`（EdgeOne）、`cos`、`live`、`vod` | SSL 证书 |
| `volcengine` | `cdn`、`dcdn`、`tos`、`vod`、`live`、`imagex`（veImageX） | 证书中心（只含已签发的证书） |
| `huawei` | `cdn`、`live`、`obs` | 云证书管理 CCM（含上传的证书，以及过期不满 3 年的证书） |
| `baidu` | `cdn` | 证书管理 |
| `qiniu` | `cdn`（含全站加速） | SSL 证书（CDN 和 SSL 证书服务共用） |

## 按需查阅

- [docs/permissions.md](docs/permissions.md)：各云需要的只读权限、写权限和 DNS 权限。
- [docs/limitations.md](docs/limitations.md)：各云服务与 DNS 服务商的已知限制，按厂商分节。

## 开发

```bash
npm install && npm test && npm run typecheck && npm run build
```

开发约定、新增云服务的步骤和发布流程见 [CONTRIBUTING.md](CONTRIBUTING.md)；安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

## 许可证

[GPL-3.0](LICENSE)