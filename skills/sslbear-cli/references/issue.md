# 申请证书（issue）

`issue` 向 Let's Encrypt 申请证书，用 DNS 验证：自动在域名所在的 DNS 服务商添加 `_acme-challenge` TXT 记录，验证完就删除。

首次运行会自动注册 Let's Encrypt 账号，即视为同意 [Let's Encrypt 订阅协议](https://letsencrypt.org/repository/)。用户要申请证书就已经包含这层意思，不用单独确认，在汇报里告知用户即可。

## 步骤

1. **定域名。**
   - 一张证书最多 100 个域名。
   - `*.example.com` 只覆盖一级子域，不包括 `example.com` 本身。两个都要，就两个都写。
   - 续期时，照抄 `domains` 输出里的 `cert.sans`。
2. **预检。** 运行 `sslbear-cli issue -d 'example.com,*.example.com' --dry-run --json`。这一步不申请证书，也不改 DNS。
   - `data.dns[]` 列出每个域名由哪家服务商、哪个 zone 解析。
   - 预检失败时，按下面的失败表处理。
3. **签发。** 去掉 `--dry-run` 再运行一次。命令超时设到 10 分钟（600000 毫秒）或更长，不够时放到后台运行并等它结束。
4. **记下文件路径。** `data.files.cert` 和 `data.files.key` 分别是 fullchain 和私钥的绝对路径，部署时用作 `--cert` / `--key`。

常用参数：

- `--key-type ecc`：签 ECC 证书。默认是 RSA，兼容性最好。
- `--dns <服务商>`：多家服务商都托管了同一个 zone 时，用它指定实际使用的那家。
- `--staging`：用 Let's Encrypt 测试环境演练。证书不受浏览器信任，也不占正式配额。
- `--out <目录>`：改保存位置。默认是 `~/.sslbear-cli/certs/<主域名>_<rsa|ecc>/`，主域名里的 `*` 换成 `_`。

## 读结果

- `reused: true`：保存位置已有可用的证书（同一组域名、同一算法、剩余 30 天以上），这次没有重签。用户明确要求重签时，才加 `--force`。
- `dns[]` 里出现 `cleaned: false`：这条 TXT 记录没删掉。把 `message` 转告用户到 DNS 控制台手动删除，`message` 里有记录名和值。残留的 `_acme-challenge` TXT 记录不影响网站访问；CLI 没有单独删除记录的命令。
- `issues[]`：列出查询 zone 失败、或凭证不完整被跳过的 DNS 服务商。域名不在这些服务商上时，可以忽略。

## 失败

失败时看 stderr 里的 `status`：

| `status` | agent 怎么做 |
| --- | --- |
| `ZoneNotFound` | 域名（见 `domains` 字段）不在任何已配置的 DNS 服务商里。带 `nameServerOwner` 时，说明域名的 NS 在那一家：请用户配好那家的凭证（见 [setup.md](setup.md)），或者在那家接入这个域名。不带时，问用户域名在哪家解析。`issues` 里有查询 zone 失败的，多半是缺权限 |
| `ZoneAmbiguous` | 多家服务商（`providers`）都托管了这个 zone。问用户实际用哪家，然后加 `--dns <那家>` 重跑 |
| `DnsRecordFailed` | 添加 TXT 记录失败，多半是缺 DNS 写权限。`retryable: true` 时先重跑一次；否则把 `code`、`requestId` 报给用户 |
| `DnsPropagationTimeout` | 看 `message`。域名的 NS 没指向该服务商时，告诉用户；NS 是对的，就加大 `--dns-timeout`（比如 600）重跑 |
| `AcmeChallengeFailed` | Let's Encrypt 验证失败，把 `detail` 报给用户。常见原因有三种：`_acme-challenge` 有 CNAME 记录；CAA 记录不允许 Let's Encrypt 签发；DNS 服务商限制境外查询（如百度智能云解析） |
| `AcmeRateLimited` | 触发了 Let's Encrypt 频率限制，不要重试。把 `retryAfter`（秒）换算成具体时间告诉用户 |
| `AcmeError` | 其他 ACME 错误，含网络错误。`retryable: true` 时稍后重跑一次；否则报给用户 |
| `Interrupted` | 签发被中止。把 `cleaned: false` 的记录转告用户，然后把命令超时设长，重跑 |
| `UsageError` | exit 2，参数或凭证配置有误，没调用任何接口。按 `message` 改正 |

不要循环重试签发：失败的验证也会计入 Let's Encrypt 的频率限制。
