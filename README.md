# EasyList rules for Loon

每天从官方发布端点下载最新的 [EasyPrivacy](https://easylist-downloads.adblockplus.org/easyprivacy.txt) 与 [EasyList China](https://github.com/easylist/easylistchina) ABP 规则，转换为 Loon 支持的远程规则集，并由 GitHub Actions 自动提交更新。

## 生成文件

- `rules/easyprivacy.list`：EasyPrivacy 完整版，包含域名和 URL 规则。
- `rules/easyprivacy-domain.list`：EasyPrivacy 纯域名高性能版。
- `rules/easyprivacy-allow.list`：EasyPrivacy 无条件例外规则。
- `rules/easylistchina.list`：EasyList China 完整版，包含域名和 URL 规则。
- `rules/easylistchina-domain.list`：EasyList China 纯域名高性能版。
- `rules/easylistchina-allow.list`：EasyList China 无条件例外规则。
- `rules/stats.json`、`rules/easylistchina-stats.json`：转换数量、近似转换选项和舍弃原因。

完整版中的规则类型包括 `DOMAIN-SUFFIX`、IP 主机的 `DOMAIN` 和 `URL-REGEX`。域名版匹配更快，但无法处理基于 URL 路径的广告或追踪请求。

## Loon 使用方法

将下面四行加入 Loon 配置的 `[Remote Rule]`：

```ini
[Remote Rule]
https://raw.githubusercontent.com/xheiop/easylist-loon-rules/main/rules/easyprivacy-allow.list, policy=DIRECT, tag=EasyPrivacy Allow, enabled=true
https://raw.githubusercontent.com/xheiop/easylist-loon-rules/main/rules/easylistchina-allow.list, policy=DIRECT, tag=EasyList China Allow, enabled=true
https://raw.githubusercontent.com/xheiop/easylist-loon-rules/main/rules/easyprivacy.list, policy=REJECT, tag=EasyPrivacy, enabled=true
https://raw.githubusercontent.com/xheiop/easylist-loon-rules/main/rules/easylistchina.list, policy=REJECT, tag=EasyList China, enabled=true
```

如果更看重性能，可将两个拦截 URL 分别改为对应的 `*-domain.list`。所有例外规则必须排在所有拦截规则前面，因为 ABP 的例外规则具有优先权，而 Loon 按规则顺序匹配。

EasyList China 是 EasyList 的中文补充列表，本项目同步的是该仓库自身的 `easylistchina.txt`，不包含英文 EasyList 基础规则；EasyPrivacy 则用于拦截追踪器。

## 转换范围

转换器会优先生成 Loon 原生且高效的域名规则：

- `||example.com^` → `DOMAIN-SUFFIX,example.com`
- IP 主机 → `DOMAIN,1.2.3.4`
- ABP 域名加路径、通配符、分隔符和普通网络过滤规则 → `URL-REGEX`
- ABP 原生正则 → `URL-REGEX`
- 无选项的 `@@` 例外规则 → 单独的 allow 规则集

Loon 无法完整表达 ABP 的请求类型、第一方/第三方和来源站点限制。为尽量保留拦截覆盖，普通拦截规则会保留 URL 模式并忽略这些上下文选项；这属于近似转换，详细数量见对应的统计文件。以下规则会舍弃：

- 元素隐藏等非网络规则；
- 带上下文或资源类型选项的例外规则，避免将它们扩大成全局 `DIRECT`；
- `removeparam`、`redirect`、`csp`、`header` 等不是单纯拦截请求的修改器；
- 无法安全放入 Loon 逗号分隔格式或无法编译的正则。

## 本地生成与测试

```bash
python3 -m unittest discover -s tests -v
python3 scripts/convert_abp_to_loon.py \
  --input-file easyprivacy.txt \
  --source-label https://easylist-downloads.adblockplus.org/easyprivacy.txt \
  --expected-title EasyPrivacy \
  --output rules/easyprivacy.list \
  --domain-output rules/easyprivacy-domain.list \
  --allow-output rules/easyprivacy-allow.list \
  --stats-output rules/stats.json
```

将输入 URL、预期标题和四个输出路径替换为 EasyList China 对应值，即可在本地生成中文规则。GitHub Actions 已同时执行两个来源，并分别设置最低规则数量保护，任一下载或转换异常时都不会提交。

工作流每天 `03:23 UTC` 运行，也支持在 GitHub Actions 页面手动执行。只有生成内容发生变化时才会创建提交。

## 许可

转换脚本采用 MIT License。生成的规则来自 EasyPrivacy 和 EasyList China，并保留来源与上游许可信息；EasyList 官方说明其仓库内容可按 GPL-3.0-or-later 或 CC BY-SA 3.0-or-later 使用。规则内容的著作权与许可归 EasyList authors 所有。
