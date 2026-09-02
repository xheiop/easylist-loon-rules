# EasyPrivacy for Loon

每天从 [EasyPrivacy](https://easylist-downloads.adblockplus.org/easyprivacy.txt) 下载最新 ABP 规则，转换为 Loon 支持的远程规则集，并由 GitHub Actions 自动提交更新。

## 生成文件

- `rules/easyprivacy.list`：推荐，包含 `DOMAIN-SUFFIX`、IP 的 `DOMAIN` 和 `URL-REGEX`，覆盖面最大。
- `rules/easyprivacy-domain.list`：只包含域名规则，匹配更快，但不会拦截基于 URL 路径的追踪请求。
- `rules/easyprivacy-allow.list`：可安全转换的无条件 ABP 例外规则。它必须以 `DIRECT` 策略放在拦截规则之前。
- `rules/stats.json`：本次转换数量、近似转换的 ABP 选项和舍弃原因。

## Loon 使用方法

将下面两行加入 Loon 配置的 `[Remote Rule]`。请把 `<owner>/<repo>` 和分支名替换成实际仓库信息：

```ini
[Remote Rule]
https://raw.githubusercontent.com/<owner>/<repo>/main/rules/easyprivacy-allow.list, policy=DIRECT, tag=EasyPrivacy Allow, enabled=true
https://raw.githubusercontent.com/<owner>/<repo>/main/rules/easyprivacy.list, policy=REJECT, tag=EasyPrivacy, enabled=true
```

如果更看重性能，可将第二个 URL 改为 `rules/easyprivacy-domain.list`。例外规则必须排在拦截规则前面，因为 ABP 的例外规则具有优先权，而 Loon 按规则顺序匹配。

## 转换范围

转换器会优先生成 Loon 原生且高效的域名规则：

- `||example.com^` → `DOMAIN-SUFFIX,example.com`
- IP 主机 → `DOMAIN,1.2.3.4`
- ABP 域名加路径、通配符、分隔符和普通网络过滤规则 → `URL-REGEX`
- ABP 原生正则 → `URL-REGEX`
- 无选项的 `@@` 例外规则 → 单独的 allow 规则集

Loon 无法完整表达 ABP 的请求类型、第一方/第三方和来源站点限制。为尽量保留 EasyPrivacy 的拦截覆盖，普通拦截规则会保留 URL 模式并忽略这些上下文选项；这属于近似转换，详细数量见 `stats.json`。以下规则会舍弃：

- 元素隐藏等非网络规则；
- 带上下文或资源类型选项的例外规则，避免将它们扩大成全局 `DIRECT`；
- `removeparam`、`redirect`、`csp`、`header` 等不是单纯拦截请求的修改器；
- 无法安全放入 Loon 逗号分隔格式或无法编译的正则。

## 本地生成与测试

```bash
python3 -m unittest discover -s tests -v
python3 scripts/convert_easyprivacy.py \
  --input-file easyprivacy.txt \
  --source-label https://easylist-downloads.adblockplus.org/easyprivacy.txt \
  --output rules/easyprivacy.list \
  --domain-output rules/easyprivacy-domain.list \
  --allow-output rules/easyprivacy-allow.list \
  --stats-output rules/stats.json
```

工作流每天 `03:23 UTC` 运行，也支持在 GitHub Actions 页面手动执行。只有生成内容发生变化时才会创建提交。

## 许可

转换脚本采用 MIT License。生成的规则来自 EasyPrivacy，并保留了来源与上游许可信息；EasyList 官方说明其仓库内容可按 GPL-3.0-or-later 或 CC BY-SA 3.0-or-later 使用。规则内容的著作权与许可归 EasyList authors 所有。
