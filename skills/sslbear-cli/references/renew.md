# 续期与自动续期

## 续期

用户说"续一下"、"看看哪些证书快过期了"时，按这个流程做：

1. **找出要续的。** 运行 `sslbear-cli domains -e 30 --json`，列出 30 天内到期的证书，已过期的也算在内。
   - `data.items` 按 `daysLeft` 升序排列。`daysLeft` 为负数表示已过期，优先处理。
   - `issues[]` 里 `kind: "error"` 的服务没查到，要告诉用户。
2. **按 `cert.sans` 分组。** SAN 相同的域名共用一张证书。每组只签一张、只部署一次，`deploy` 会自动找出这张证书覆盖的所有域名。
3. **逐组处理。**
   - 先签发：`issue -d '<这组的 cert.sans，用逗号连接>' --dry-run --json` 预检，通过后去掉 `--dry-run` 签发，见 [issue.md](issue.md)。
   - 再部署：先 `deploy --dry-run`，再 `deploy`，见 [deploy.md](deploy.md)。
   - 某组签不了（域名的 DNS 不在已配置的服务商，或者用户不想用 Let's Encrypt）时，先接着处理其他组，最后一起问用户：补哪家 DNS 凭证，或者提供现成的证书文件直接部署。
4. **汇报。** 全部处理完后，一次性告诉用户三件事：
   - 已续期的域名和新的到期时间；
   - 失败的域名和原因；
   - 需要用户决定的事项。

用户换了新买的证书时，不用签发，直接拿证书文件按 [deploy.md](deploy.md) 部署。

## 自动续期

用户希望以后不用再管时，设置成每天自动运行同样的 `issue` + `deploy`。

为什么每天跑是安全的：

- 证书剩余 30 天以上时，`issue` 直接复用现有证书，不改 DNS，也不占配额。
- `deploy` 会跳过已经是这张证书的域名。
- 只有进入最后 30 天，才会真正重签并替换。签发失败时第二天再试，每天一次不会触发 Let's Encrypt 的频率限制。
- 脚本里不加 `--force`，需要用户确认的域名不会被自动替换。

### 第 1 步：确认要续的证书组

- 每组的域名：`sslbear-cli domains --json`（不加 `-e`）列出全部域名，按 `cert.sans` 分组。证书都还很新时，用不着重新签发。
- 每组的证书目录：首次 `issue` 输出的 `data.files` 所在目录。也可以按规则推出来：`~/.sslbear-cli/certs/<主域名>_<rsa|ecc>/`，主域名里的 `*` 换成 `_`。
- 对每组跑一次 `deploy --dry-run`，确认没有意外的 `would_update` / `would_deploy`。不该动的云或服务，在脚本的 `deploy` 里加 `-p` / `-s` 排除。
- 征得用户同意，说清楚范围（哪些证书组、会替换哪些域名）和运行时间。
- 在常开的机器（如服务器）上设置。笔记本合盖睡眠时，cron 不会运行。

### 第 2 步：写脚本

写 `~/.sslbear-cli/renew.sh`，每组证书写一行 `renew`：

```sh
#!/bin/sh
# 证书熊自动续期：每天运行一次。证书剩余 30 天以上时，issue 直接复用、deploy 跳过已是这张证书的域名，什么都不改
export PATH="/usr/local/bin:$PATH"  # 换成 npx 所在的目录（dirname "$(command -v npx)"）：cron 的 PATH 里没有 nvm、Homebrew 的路径
cd "$HOME/.sslbear-cli" || exit 1   # 凭证从这里的 .env 读取；凭证在别处时，给两条命令加 --env-file <路径>

# $1 是域名组，$2 是这组证书的目录
renew() {
  npx -y sslbear-cli@latest issue -d "$1" --json &&
    npx -y sslbear-cli@latest deploy --cert "$2/fullchain.pem" --key "$2/privkey.pem" --json
}

{
  date
  renew 'example.com,*.example.com' "$HOME/.sslbear-cli/certs/example.com_rsa"
} >>renew.log 2>&1
```

- nvm 装的 Node，路径里带版本号。以后换了或删了这个版本，要改脚本里的 PATH。
- `@latest` 让定时任务每天用最新版。想固定版本，就换成具体版本号，如 `sslbear-cli@0.4.0`。

### 第 3 步：按 cron 的环境试跑

交互式 shell 里的 PATH 和环境变量，与 cron 不同。用干净的环境试跑一次：

```sh
chmod 700 ~/.sslbear-cli/renew.sh
env -i HOME="$HOME" PATH=/usr/bin:/bin /bin/sh ~/.sslbear-cli/renew.sh
tail -n 3 ~/.sslbear-cli/renew.log
```

日志里应该看到：

- 两条命令都输出 `"ok":true`。
- `issue` 是 `"reused":true`。
- `deploy` 的结果和第 1 步 dry-run 的计划一致：`already_current`，或者 `https_off`、`platform_managed`、`unsupported`、需要确认的跳过。这些都是正常的。

出现 `npx: not found`、`node: No such file or directory` 或凭证报错时，先改好脚本再继续。

### 第 4 步：加进 crontab

保留已有的任务，重复执行也只留一行：

```sh
(crontab -l 2>/dev/null | grep -vF '.sslbear-cli/renew.sh'; echo "17 3 * * * /bin/sh $HOME/.sslbear-cli/renew.sh") | crontab -
crontab -l
```

Windows 上用「任务计划程序」每天运行同样的命令。

### 第 5 步：告诉用户

- 运行时间、范围，以及日志位置 `~/.sslbear-cli/renew.log`。
- 怎么检查是否出问题：`grep -E '"ok":false|"needsConfirm":true|"cleaned":false' ~/.sslbear-cli/renew.log`。有输出就找 agent 处理。
- 以后新增要续期的证书组，要在 `renew.sh` 里加一行。
- 想停掉时，从 crontab 删掉 `renew.sh` 那一行。

如果 agent 平台自带定时任务（比如 Claude Code 的定时任务），也可以用它代替 cron：每次按上面的续期流程执行，并向用户汇报结果。
