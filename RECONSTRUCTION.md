# 重建证据

本项目只实现已经能从样本行为验证的部分。

| 模块 | 证据 | 当前状态 |
|---|---|---|
| Fishhook | `rebind_symbols*`、`perform_rebinding_with_section`、`vm_protect` | 复用上游源码 |
| Capstone | `cs_version` 返回 `0x500`，大量 ARM/AArch64 解码符号 | 待接入 5.x |
| NSURLSession | `swz_dtReqCH`、`dh_snap_from_request`、`dh_net_enrich` | 已按行为重建 |
| SSL | `hooked_SSL_read/write` 和 `_ex` 变体 | 已按指令顺序重建 |
| CommonCrypto | `hooked_CC_*`、`DHCryptorState`、`DHHmacState` | 已恢复一次性与主要流式路径 |
| OpenSSL EVP | `EVP_*Init/Update/Final`、`EVP_CIPHER_CTX_*` | 已恢复主要状态路径 |
| Mach-O 镜像清单 | `_dyld_image_count`、`_dyld_get_image_name`、slide | 已恢复基础诊断路径 |
| Mach-O Dump | `LC_ENCRYPTION_INFO(_64)`、内存解密段、`cryptid=0`、FAT 切片选择 | 已恢复当前进程镜像导出 |
| 动态加载 | `dlopen`、`dlsym`、`dladdr` | 已恢复诊断路径 |
| 日志查询 | `/api/events?limit=`、MCP `query_events` | 有界查询，避免大数据事件拖慢 Web 面板 |
| Keychain | `SecItemCopyMatching/Add/Update/Delete` | 已按 API 行为重建 |
| 文件事件 | open/read/write/pread/mmap/unlink/rename | 已重建，默认关闭 |
| anti-debug | `ptrace(31)`、清 `CS_DEBUGGED`、清 `P_TRACED` | 已按位掩码重建 |
| jailbreak hide | stat/access、scheme、dyld image 关键字 | 已重建基础版 |
| device spoof | UIDevice/NSProcessInfo/IDFV/IDFA/uname | 已重建基础版 |
| HTTP/MCP | 原始 socket worker、JSON-RPC `initialize/tools/*` | 已重建精简版 |
| Dump/ZIP | `DHDumpManager`、`dh_dump_decrypt_image_to_file`、`zw_*` | 待恢复 |
| 动态 thunk | 128 个 slot、import/method record-only hook | 待恢复 |

详细二进制分析见同级工作区的 `decrypt_helper_reverse_notes.md`。
