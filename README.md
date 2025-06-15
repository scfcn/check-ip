# DNS Tester with GitHub Actions

这是一个自动化的 DNS 测试工具，使用 GitHub Actions 定时运行并生成详细的测试报告。

## 功能特点

- 使用多个大厂 DNS API 进行域名解析（Google, Quad9, AliDNS, DNSPod）
- 全面的 IP 连通性测试（PING + API 验证）
- 生成美观的 HTML 报告
- 每日定时运行测试
- 自动保存测试结果

## 使用说明

1. 将需要测试的域名添加到 `domains.txt` 文件（每行一个域名）
2. 如果需要屏蔽某些 IP，可以将它们添加到 `ip_blacklist.txt` 文件
3. 每次运行后，测试报告会保存在 `results` 目录
   - `index.html` - 完整的 HTML 报告
   - `summary_<timestamp>.txt` - 文本摘要
   - 各域名的详细 JSON 报告

## GitHub Actions 配置

- 定时运行：每天 UTC 时间 0 点（北京时间 8 点）
- 手动触发：在 GitHub Actions 页面点击 "Run workflow"
- 运行完成后，报告会作为 Artifact 提供下载
- 测试结果也会自动提交回仓库

## 自定义配置

可以修改 `dns_tester.py` 文件中的以下参数：

```python
# 测试参数
PING_RETRY = 3  # PING 重试次数
API1_RETRY = 2  # API1 测试次数
API2_RETRY = 2  # API2 测试次数
API_TIMEOUT = 8  # API 超时时间（秒）
THREADS = 50     # 并发线程数
CACHE_TTL_MINUTES = 30  # 缓存有效期（分钟）