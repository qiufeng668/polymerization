# 爱丽丝：单订阅转 TXT 节点

- 插件：`plugins/alice.py`，聚合调度声明 `# @interval: 12h`。
- 一次只维护一个账号、一条有效订阅；优先复用私库缓存，不批量注册。
- 注册/登录 → 订单 → 一条订阅 → Clash YAML → `output/nodes.txt`。
- TXT 是 UTF-8，每行一个 `vless://`、`hy2://` 等节点 URI，不把整个文件 base64，不输出订阅链接。
- URI 自身的标准编码仍保留，例如 SS/VMess 的 userinfo/payload 及百分号转义。
- VLESS 保留 Reality public-key / short-id、flow、WS、gRPC、SNI；HY2 保留 obfs 参数。
- 失败退出码 2，不拿旧节点冒充成功。旧来源缓存由聚合主控管理。

## 本地调用

Runtime: Python 3.11+ / Linux、macOS、Windows。无需编译。

```sh
python -m pip install requests pyyaml
python plugins/alice.py --outdir output
python -m unittest discover -s tests -p test_alice.py -v
```

可选 `--proxy http://127.0.0.1:7890`、`--domain mailo.icu`。

## GitHub 自动聚合

原 workflow 定期唤醒主控；主控按插件头的 12h 冷却运行爱丽丝。
手动 Run workflow 勾选 `alice_only`：只刷新爱丽丝，其它来源沿用缓存，跳过乌拉扫描，然后执行原聚合、测速和私库同步。

主控从插件沙箱 `output/nodes.txt` 采集，统一去重后输出到私库 `nodes_plain.txt`、`sub_base64.txt`、`clash.yaml` 等原有产物，不另建独立订阅工程。

账号和原始订阅仅写 `vault_repo/alice_bank.json`；不提交到公开源码库，不在日志中打印。TXT 节点含连接凭据，默认留在原私有订阅库。GitHub Secrets 继续沿用原有 `GIT_TOKEN`。
