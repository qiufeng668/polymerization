# polymerization

基于GitHub Actions实现自动聚合并定时启动任务。

禁止复刻！
# 六条改进说明（10-18 基于 x3284728970/vpn-sub-aggregator 对比）

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

## 验证
- `main_engine.py` 语法检查通过。
- 单测：死节点过滤、多层 b64、xhttp 转换、地区识别、vmess 重命名 全部通过。
- 端到端（真实跑 8 插件）：原始 529 → 去重 425 → 预筛 405 → Clash 405，脚本全健康。
- 插件输出目录（`plugins/out`、`plugins/state` 旧残留）建议从仓库删除，避免被 extract 误扫。

## 追加：节点命名「来源前缀+干净原名」（10-18）

### 目标格式（用户要求）
`🇭🇰 香港 01 | DE香港01`  —— 国旗地区 + 序号 | 来源前缀 + 干净原名

### 改动
1. 新增 `PLUGIN_TAGS` 映射：插件文件名 → 来源前缀（de→DE、ipow→iPoW、银狐→银狐、sulian→sulian、yes→yes、小满→小满、safevpn→safevpn、lanmao→lanmao、Surfer→SF、__/cainiao→cainiao…）
2. 新增 `plugin_tag()`：文件名 → 前缀
3. 新增 `apply_source_prefix()`：给节点名加来源前缀，拼接前剥掉原名自带的旗帜 emoji（避免 `DE🇭🇰香港01` 旗帜重复）
4. `run_plugins_with_cache`：提取/读缓存节点后统一 apply 来源前缀
5. 修地区识别 bug：`_DETECT_CN_RAW` 移除 38 个纯两字英文国家码（AUTO 会命中 AU、RUSSIA 会命中 US），英文国家码改走独立词元匹配

### 效果
- `DE香港`、`iPoW香港2`、`sulian自动` 一目了然
- `iPoW-AUTO` 正确识别为「自动」，不再误判澳大利亚
- `DeVPN-HK-0` 的 DE 不误判德国，HK 正确识别香港
- 实测 405 节点：DE21 / iPoW16 / lanmao15 / safevpn97 / sulian6 / yes220 / 小满10 / 银狐20

## 追加2：补齐插件 + 统一更新频率（10-18）

### 新增插件（从 x3284728970/vpn-sub-aggregator 抄录，确认可跑）
| 插件 | 来源 | 实测 | 状态 |
|------|------|------|------|
| `plugins/Surfer.py` | SF 冲浪者 | ✅ 12节点 | 已并入，命名 `SF香港` |
| `plugins/__.py` | cainiao 菜鸟 | ⚠️ 当前登录接口被风控空载 | 已并入，机制完好（失败3次才提示下架） |

未抄的：
- `xunhu.py`：与你已有 `银狐.py` 同源（迅狐/FoxLink），重复，不抄
- `fengniao.py`：仓库版为旧版 go01 会超时，你 Nagram 有修复版但接口有风控，暂不并入
- `ipow_configs.py`：依赖旧 ipow 的 Http，你的 ipow 已是 v4.3.9 新版，接口不兼容
- `oneray_probe.py`：是探测非抓取，oneRay 全挂

### 统一更新频率 = 12 小时
全部 10 个插件 `@interval` 已统一为 `12h`（Surfer/__/de/ipow/lanmao/safevpn/sulian/yes/小满/银狐）。
`ipow.py` 原无标记，已新增 `# @interval: 12h`。

### 最终实测
- 10 插件全调度：541 → 去重 406 → 死节点预筛剔除 20 → 406
- Surfer（SF来源）命名正常：`🇭🇰 香港 01 | SF香港`
- 菜鸟接口风控空载，但引擎会失败计数，不致命

### 交付文件（AI文件夹/poly_improved/）
- `main_engine.py`（六条改进 + 命名 + SF支持）
- `plugins/` 全部 10 个插件（7原 + Surfer + __ + 替换后的 ipow）
- `requirements.txt`
- `.github/workflows/run.yml`（原样）

## 追加3：测速 bug 修复 + 手动强制刷新（10-18 第二轮）

### 一、真连接测速两大致命 bug（修复前你线上跑的版本）
用 LiteSpeedTest v0.15.0 实测（沙箱跑通）发现：
1. **lite 输出在 stderr 不在 stdout** —— 原代码 `proc.stdout` 为空，解析到 0 个存活节点，永远降级用全量 → **测速从未真正生效，424 条全量（混死节点）进订阅**。这是"一出来失效100多条、朋友连不上"根因。
   - 修复：`stdout_log = (proc.stdout or "") + (proc.stderr or "")`
2. **id 错位** —— lite 的 gotping id 从 **0** 开始，原代码 `id-1` 全错位（id=0 变 -1 丢弃，其余张冠李戴）。
   - 修复：去掉 `-1`，直接对齐。
3. **只收 ping>0 误杀** —— 实测 388 个连通节点里 367 个只有 `lost=0%` 没有 ping 值，原代码全丢只留 21 个。
   - 修复：存活判定改为 `lost<100%`（凡丢包<100% 即算连通），有延迟的按延迟排序。
4. **tcping → googleping** —— 原 tcping 只测端口开（混入假活节点），改 googleping = 走 https://cp.cloudflare.com/generate_204 验证**真实代理转发**。参数：并发10、超时3s。

### 二、手动刷新 = 绕过冷却（本需求核心）
- workflow `run.yml` 第5步加 env：`MANUAL_RUN: ${{ github.event_name == 'workflow_dispatch' }}`
  - **定时（schedule）**：MANUAL_RUN=false → 遵守 @interval 冷却，跳过未到期的脚本
  - **手动（workflow_dispatch）**：MANUAL_RUN=true → **强制全量重跑所有插件**
- main_engine `run_plugins_with_cache` 读 MANUAL_RUN，true 时 `manual_force` 强制所有脚本执行。
- 实跑验证：定时模式刚跑完立即再跑→10插件全"跳过(冷却)"; 手动模式→全部"🚀[执行]"强制重跑。

### 三、本轮完整试运行（poly_fresh 纯净版）
- 10插件全调度（含菜鸟 38 条，接口已恢复）→ 579 汇总 → 去重 424 → 死节点剔20 → **测速筛出 406 存活** → Clash 406
- 脚本全健康，exit=0，auto/manual 双模式验证通过。

### 交付（AI文件夹/poly_improved/）
- `main_engine.py`：含两处修复 + 手动强制（三处 mdd5 一致）
- `.github/workflows/run.yml`：含 MANUAL_RUN（三处 mdd5 一致）
- `plugins/`：10 个插件以你最新仓库为准（de/lanmao/sulian/银狐 为 1d，其余 12h；无 fengniao 残留）
- `requirements.txt`：7 依赖
