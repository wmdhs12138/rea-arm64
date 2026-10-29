# REA Linux ARM64 适配版

[wmdhs12138/rea-arm64](https://github.com/wmdhs12138/rea-arm64/tree/arm64)
基于 [morluto/rea](https://github.com/morluto/rea) 的
[`rea-agents-6.8.0`](https://github.com/morluto/rea/tree/rea-agents-6.8.0)
维护源码补丁。默认适配分支为 `arm64`，`main` 保留 fork 时的上游版本。
上游 MIT 许可证和第三方许可声明保留。

## 已适配的范围

| 能力                         | ARM64 状态                                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------------------------- |
| `inspect_binary_layout`      | Linux ARM64 主机可用；AArch64 ELF64 大、小端 EXEC/DYN/REL；Evidence 顶层架构为 `arm64`            |
| `inspect_recorded_crash`     | 放开 Linux ARM64 主机限制；使用已有的小端 AArch64 core 解码；不等于所有可选 pwndbg 工作流均已实测 |
| `inspect_evm_interface`      | Linux ARM64 可用，保留原 EVMole 和进程资源限制                                                    |
| `recover_javascript_sources` | 使用 Wakaru 1.14.0 官方原生 ARM64 二进制；保留版本、报告和清理检查                                |
| Ghidra 文档、注释、书签      | 新增 8 个操作，见下文；仍使用无 GUI 的临时 Program                                                |
| Ghidra CodeBrowser 导航      | 新增 attached 模式，接入 6 个导航操作；无头模式也支持显式地址的前后导航，见下文                   |
| 源码构建                     | 可显式选择 JavaScript TypeScript 编译器，适用于默认 Rust 编译器无法映射 arena 的内核              |
| MCP 一致性                   | 从源码重新生成目录、Schema 和摘要；保留运行时完整性检查                                           |

实测平台为 **Linux AArch64 / glibc / Arch Linux ARM，运行于 Droidspaces**。
这不建立 Android Bionic / 原生 Termux 的兼容性。

## 从源码构建

使用 `.nvmrc` 中的 Node.js 和 `package.json#packageManager` 中的 npm。
本机另外实测 Node.js 26.12.1、npm 12.2.1；版本需满足上游 `engines`。

```sh
git clone --branch arm64 https://github.com/wmdhs12138/rea-arm64.git
cd rea-arm64
npm ci --ignore-scripts --no-audit --no-fund
REA_TYPESCRIPT_PACKAGE=typescript6 NODE_OPTIONS=--max-old-space-size=2800 npm run compile
node scripts/generate-skill-metadata.mjs
node scripts/rea.mjs --help
```

上述安装跳过依赖的安装脚本；如需 Frida，再在该目录执行
`npm rebuild frida --foreground-scripts`，并实际验证绑定加载和子进程清理。
Python、Java、Ghidra、Wakaru 等后端由调用者提供，构建命令不替调用者安装这些软件。

`REA_TYPESCRIPT_PACKAGE` 只允许已锁定的 `tsrs`、`typescript`、
`typescript6` 或 `typescript-termux`。未设置时保持上游的自动选择。
显式选择会进入编译器身份和 Turbo 缓存身份；失败不会静默换编译器。
本机默认 tsrs 的实际错误是 arena 预留地址无法映射；`typescript6` 已完成源码编译。

Pi 的 `mcp.json` 可保留已有配置，另加 REA 服务：

```json
{
  "mcpServers": {
    "rea": {
      "command": "/absolute/path/to/node",
      "args": ["/absolute/path/to/rea-arm64/scripts/rea.mjs", "mcp"],
      "timeout": 450,
      "env": {
        "REA_PWNTOOLS_PYTHON": "/absolute/path/to/python",
        "REA_WAKARU_COMMAND": "/absolute/path/to/wakaru"
      }
    }
  }
}
```

后端路径参见上游的 [Ghidra](docs/ghidra-provider.md)、
[ELF 布局](docs/binary-diagnostics.md)、[JavaScript 恢复](docs/javascript-recovery.md)
和 [JEB](docs/jeb-analysis.md) 文档。修改已有配置前备份，并保留其他服务和环境变量。

## Ghidra 新增的 8 个操作

`current_document`、`comment`、`inline_comment`、`list_bookmarks`、
`set_comment`、`set_inline_comment`、`set_bookmark`、`unset_bookmark`。

注释要求显式的已映射地址，普通注释使用 Ghidra PRE，行内注释使用 EOL。
空字符串清除注释。写操作使用事务并验证精确回读，失败或取消回滚，分析缓存随之失效。
这些操作只编辑临时分析数据库，关闭会话后丢弃，不修改原二进制。

书签仅暴露 `Note` 类型、`REA` 类别，名称存于书签注释。省略 `name` 保留已有名称，
空字符串清空名称并回读为 `null`。分析警告和其他类别的书签不属于该工具的读写范围。
Windows P0 仍拒绝所有数据库写操作。

## Ghidra CodeBrowser 导航（attached 模式）

`current_address`、`current_procedure`、`goto_address`、`next_address`、
`prev_address` 和 `get_navigation_context` 读取或移动真实 CodeBrowser 的 Listing 光标。
这是独立的 attached 模式：Ghidra 由用户自己启动，REA 只负责连接，不安装、不启动 GUI，
也不需要本机的 `GHIDRA_INSTALL_DIR`。

1. 在 CodeBrowser 中打开**原始**目标文件，等待自动分析完成。
2. 在 Script Manager 中添加本仓库的 `bridge/ghidra` 目录，运行 `ReaGhidraBridge.java`。
   该任务会一直服务，直到你取消任务或关闭该 Program。
3. 把脚本输出的路径设为 `REA_GHIDRA_ATTACH_ENDPOINT`，再在 REA 中打开同一个文件。

端点默认位于 `$XDG_RUNTIME_DIR/rea-ghidra-attach-<用户名>/`（权限 0700；也可在
Ghidra 进程环境中用 `REA_GHIDRA_ATTACH_DIR` 指定）。记录内的令牌会在诊断中脱敏。
REA 要求 Program 记录的可执行文件 SHA-256 与所打开目标一致，并在每次连接时校验运行 ID。

- `goto_address` 通过 GoToService 移到所在代码单元的起点，并要求光标回读完全一致；
  未映射地址在移动前即失败。光标位于其他 Program 时，读取光标的操作会明确失败。
- 分析、注释和书签在该模式下只读；所有写操作和 `inspect_native_load_image` 不可用。
  REA 不保存、不关闭、不分析该 Program，也不停止 GUI 任务。
- 结果反映实时数据库（含分析员的修改、分析选项、映像基址和语言），从不使用快照缓存；
  Program 有任何修改后，桥接端会丢弃清单和反编译器缓存。未分析或正在分析时请求会失败。
- 关闭或取消只会断开 REA 的连接。Java 无法中断 GUI 任务，被取消的请求会在 Ghidra 中
  执行完，之后桥接端再接受下一个连接。

无头模式下，光标类操作标记为 `not_configured`，`next_address`/`prev_address`
必须显式传入地址，返回映射内存中相邻的 Listing 代码单元。Windows 不支持 attached 模式。
详见 [attached CodeBrowser mode](docs/ghidra-provider.md#attached-codebrowser-mode)。

## JEB 的实际情况

官方 Linux CE `5.48.0.202610071539` 已在 Linux ARM64、JDK 21 上完成免费激活，
通过真实 REA CLI 成功执行客户端信息查询、ARM64 ELF 单元枚举。
它的 ARM64 反编译请求实际返回“没有可用反编译器”；CE 的该结果不建立付费版或 Demo 的能力。
本轮不分发 JEB 二进制、许可证、机器激活数据或其分析输出。

JEB headless MCP 的实测目录不包含 `open_project`，因此应在启动时使用 `--infile`。
需要动态打开项目时，必须使用实际提供该接口的客户端；不把连接成功当成四个操作全可用。
安装和启动见 [JEB 指南](docs/jeb-analysis.md)。

## 可复现验证

Python 环境需要 `pwntools==4.15.0`、`pyelftools==0.33`、`unicorn==2.1.2`。
使用本机 AArch64 GCC、GNU readelf/objdump/strip；交叉工具可通过
`REA_ARM64_CC`、`REA_ARM64_STRIP` 和 `PATH` 选择。

```sh
export REA_PWNTOOLS_PYTHON=/absolute/path/to/python
python3 scripts/verify-arm64-layout.py
node scripts/verify-arm64-catalog.mjs

# 提供含 rea_layout_probe 函数的自有 ELF，并配置 Ghidra/JDK：
node scripts/verify-ghidra-metadata.mjs /absolute/path/to/probe.elf rea_layout_probe
node scripts/verify-ghidra-navigation.mjs /absolute/path/to/probe.elf rea_layout_probe

# attached 模式：CodeBrowser 已打开同一文件并运行 ReaGhidraBridge.java
REA_GHIDRA_ATTACH_ENDPOINT=/run/user/1000/rea-ghidra-attach-$USER/endpoint.json \
  node scripts/verify-ghidra-navigation.mjs /absolute/path/to/probe.elf rea_layout_probe
```

ELF 验证器从仓库的 C 源码生成 10 个大、小端样本，不执行目标，逐项比较节、段、
符号、重定位、GOT/PLT 和保护属性；另验证 3 类拒绝与 x86-64 回归。
结果位于 `.cache/arm64-verification/`，不提交生成的 ELF 或本地分析记录。

本机已通过 14 个 ELF CLI 用例、175 个架构/服务/进程所有权/编译器测试
（另 1 项按原条件跳过），以及 231 个 Ghidra 适配器/会话/缓存测试。
真实 Ghidra MCP 验证还通过 37 次调用，覆盖注释和书签回读、拒绝路径、缓存刷新、
关闭重开后丢弃元数据及原文件 SHA-256 不变。标准 Turbo 构建流程也已在本机跑通。
导航适配另通过 1043 个 Ghidra 适配器/会话/配置/能力清单测试（另 1 项按原条件跳过），
其中包括用模拟桥接端覆盖的握手失败、断线重连、取消和关闭时不发送 `shutdown`。
真实验证使用 Ghidra 12.1.4 与 AArch64 PIE 样本：无头模式通过 10 次 MCP 调用；
attached 模式在虚拟显示器（KWin + Xwayland）中的真实 CodeBrowser 上，
经 Script Manager 服务运行脚本，通过 22 次 MCP 调用。此外还验证了：
REA 能读取由 Listing 直接移动（等同点击）的光标；GUI 中重命名后，清单、名称解析和
反编译结果随之刷新；关闭 Program 后端点与套接字被删除；
三次 GUI 会话后 Program 数据库从未被保存。GUI 的打开与点击由验证专用的启动器自动完成，
未提交到仓库。
compact/full 两套 MCP 目录均验证了 229 个工具、ARM64 描述、AArch64 输出 Schema
和延迟加载后的运行时目录身份一致。
这些结果不代表 229 个工具逐一执行过。
[ARM64 CI](.github/workflows/arm64.yml) 使用 GitHub 的原生 ARM64 runner，
自动编译源码、生成目录并运行相关回归和真实 ELF 验证。

## 继续适配的边界

- Ghidra attached 模式仅在 Linux/macOS 上提供；本轮只在 Linux AArch64 上做了真实 GUI 验证。
  正在执行的请求无法从 REA 一侧中断。
- JEB ARM/Android 反编译需具备对应模块的发行版；以实际服务目录和请求结果为准。
- Hopper 官方 Linux 下载目前为 Intel 64；本轮没有建立其 ARM64 运行支持。
- 依赖 macOS 系统 API 的工具仍要求 macOS，不因 Linux ARM64 适配而变为可用。

本仓库的源码更改不会随官方 `npm install -g rea-agents` 自动安装；升级前保留该分支的提交。
