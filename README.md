# DecryptHelperReconstructed

`decrypt_helper.dylib` 的洁净室源码重建项目。目标是依据公开 API、保留符号和 arm64 行为证据，逐步恢复 IOSDecryptHub 闭源运行时引擎的功能；它不是作者原始源码。

当前可用模块：

- CommonCrypto 一次性/流式 Digest、HMAC、对称加密与 PBKDF2 采集；
- OpenSSL/BoringSSL EVP 初始化、Update、Final、Reset、Ctrl 和释放状态采集；
- `dlopen`、`dlsym`、`dladdr` 动态加载诊断；
- 当前进程 Mach-O 镜像清单、slide、段数量与基础运行时诊断；
- 当前进程已加载 Mach-O 镜像导出：解析 `LC_ENCRYPTION_INFO(_64)`、合并内存解密段并清除 `cryptid`；
- Keychain `SecItemCopyMatching/Add/Update/Delete` 采集；
- 可选的 POSIX 文件 open/read/write/pread/mmap/unlink/rename 采集；
- NSURLSession 请求/响应采集；
- OpenSSL/BoringSSL `SSL_read`、`SSL_write`、`SSL_read_ex`、`SSL_write_ex` 明文采集；
- `ptrace`、`csops`、`sysctl` 反调试信息隐藏；
- `stat`/`access`、URL Scheme、dyld 镜像等基础越狱痕迹隐藏；
- UIDevice、NSProcessInfo、IDFV/IDFA、`uname` 设备信息伪装；
- 内存事件仓库和 JSONL 日志；
- 监听 `0.0.0.0:8088...8108` 的轻量 Web UI、JSON API 和基础 MCP endpoint；
- `/api/stats` 返回 `process.bundleId` 与引擎版本，可被 IOSDecryptHub 管理器识别。
- `/api/images` 与 MCP `list_images` 提供当前进程加载镜像清单。
- `/api/dump` 与 MCP `dump_image` 可导出当前进程已加载镜像；输出固定在目标 App 沙盒的
  `Library/Caches/IOSDecryptHub/Dumps`，接口只接受 `outputName`，不允许通过网络指定任意路径。

尚未恢复：

- CommonCrypto 非对称加密的完整状态机；
- Mach-O/IPA dump 与极简 ZIP writer；
- Capstone 5.0 分析工具；
- 128-slot 动态 thunk；
- 原版完整 Web UI 和全部 MCP tools。

## 构建

需要 Theos。默认生成 rootless arm64 包：

```sh
make package FINALPACKAGE=1
```

GitHub Actions 的 `Build rootless package` 工作流会上传 `.deb` 和未打包的 `decrypt_helper.dylib`。

用于现有 IOSDecryptHub 时，主要产物是 `decrypt_helper.dylib`：替换现有引擎后由原项目的
`IOSDecryptHubLoader.dylib` 按启用名单加载。本项目生成的独立 deb 只包含重建引擎，不包含
管理器和注入加载器，不能单独完成注入；如果设备已安装原 IOSDecryptHub，也不建议直接让
两个 deb 争用同一个文件，优先通过测试环境或原项目的引擎更新流程替换 dylib。

## 配置

引擎读取目标 App 沙盒中的：

```text
Library/Preferences/com.decrypthelper.reconstructed.plist
```

示例：

```plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>network</key><true/>
  <key>crypto</key><true/>
  <key>keychain</key><true/>
  <key>file</key><false/>
  <key>dynamic</key><false/>
  <key>anti_debug</key><true/>
  <key>jailbreak_hide</key><true/>
  <key>device_spoof</key><false/>
  <key>http_port</key><integer>8088</integer>
  <key>device</key>
  <dict>
    <key>hw_machine</key><string>iPhone16,2</string>
    <key>hw_model</key><string>D84AP</string>
    <key>os_version</key><string>17.6.1</string>
    <key>device_name</key><string>iPhone</string>
    <key>idfv</key><string>11111111-2222-3333-4444-555555555555</string>
    <key>idfa</key><string>AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE</string>
  </dict>
</dict>
</plist>
```

反调试、越狱隐藏、设备伪装、高频文件采集和动态加载诊断默认关闭；加密、Keychain、网络采集与 HTTP 默认开启。
每个流式输入/输出最多保留 1 MiB，避免无限占用内存。仅对你有权测试的 App 使用。

## 来源与许可证

项目自写部分采用 MIT License。`Vendor/fishhook` 保留 Facebook Fishhook 的 BSD-3-Clause 风格许可证。后续接入 Capstone 时必须保留 Capstone 的 BSD-3-Clause 许可证。
