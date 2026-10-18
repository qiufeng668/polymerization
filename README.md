# polymerization

基于GitHub Actions实现自动聚合并定时启动任务。

禁止复刻！
# 六条改进说明

改动全部在 `main_engine.py`，workflow 和插件原样保留。已用真实数据端到端跑通验证。

## 1. 零成本死节点参数级预筛（新增 `filter_dead_pairs`）
- `deduplicate_and_speedtest` 里，在指纹去重后、lite 真测速前调用。
- 剔除：全零 uuid（`00000000-...`）、回环地址（`127.0.0.1`/`0.0.0.0`/`localhost`/`::1`）、无效端口（`0`/`1`）。
- 实测：上轮 529→425 后，预筛剔除 20 个（黄金节点全零 uuid 死链），剩 405。
- 价值：在烧 LiteSpeedTest 配额前先干掉注定连不上的，省测速资源、加快整体。

## 2. xhttp 传输层转换支持（`uri_to_clash_proxy` vless 分支）
- 新增 `elif network == "xhttp"` 分支，生成 `xhttp-opts`（含 path/mode）。
- iPoW 官方 v4.3.9 新链路（`/v1/vpn/configs`）默认就是 `type=xhttp`，旧代码这段会静默丢弃节点。
- 实测：新版 ipow 的 8 个 vless+xhttp 节点，Clash 转换 405 条全部成功，不再丢。

## 3 & 5. 地区识别增强（重写 `detect_region_flag`）
- 从 20 个硬编码 if，扩展为**多级兜底**：城市名（长优先）→ 中文/英文地区关键词 → 旗帜 emoji → 国家代码 → 自动 → 未知。
- 新增 100+ 城市粒度表：东京/大阪/多伦多/温哥华/法兰克福/圣克拉拉/圣保罗等。
- 城市优先级最高，能区分 `CA-多伦多`、`日本东京`。
- 处理陷阱：`🇨🇳台湾专线01`（旗帜是 CN 但文案是台湾）→ 正确识别为台湾（关键词优先于旗帜）。

## 4. 多层 Base64 递归提取（重写 `extract_nodes_from_text` + `_deep_extract`）
- 旧版只解一层 b64，且遇到 Clash YAML 分支提前 `return` 会漏掉其他来源。
- 新版 `_deep_extract` 递归最多 3 层，能解「b64 套 b64」（如 lanmao_sub_base64.txt / sub_base64.txt 二次嵌套）。
- `try_b64_decode` 放宽 `<16` 限制、支持 urlsafe 变体、去空白、解码结果须为可打印文本（防止随机字节误判）。
- 不再因 yaml 提前返回，yaml 解析和其他来源合并去重。

## 6. gist 双通道冗余备份（新增 `upload_to_gist_backup`）
- 私有库 + CF 绑定是主通道；这是备用通道，防 GIT_TOKEN 失效/私有库异常时订阅断供。
- 只在设置 `GIST_TOKEN` 环境变量时启用；未设置则静默跳过（不干扰现有流程）。
- 复用已有 gist（按 description 匹配），没有则新建，成功后把 raw 直链写进看板。

## 其他
- 修复了原 `extract_nodes_from_text` 里 yaml 分支提前 return 导致漏节点的隐患。
- 所有新函数均为纯逻辑、不联网（除第 6 条的 gist 上传），不改变原有抓取与调度行为。

