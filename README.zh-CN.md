# VexZygisk

[English](README.md) · **简体中文**

VexZygisk 是一个面向 KernelSU 与 APatch 的独立 Zygisk 实现，基于 ReZygisk。

整个代码库已用 C 重写，不仅结构更清晰、更易读懂，二进制也更小更快。此外还引入了自定义加载器，让 VexZygisk 能够应对未来的检测手段：模块库改由内置的 csoloader 映射，不再经过系统链接器，从而规避该路径上基于链接器的检测。

本项目**每次只构建一种 Root 方案**：KernelSU 版与 APatch 版是同一次 CI 运行产出的两个独立压缩包，各自只携带自己的后端——包内不含另一种 Root 方案的任何痕迹。

## 为什么？

Zygisk 宿主以 root 权限运行在每个应用进程里，因此它的代码必须可被审计。VexZygisk 是一个独立、开源的实现：注入、挂载处理和模块加载路径都在本仓库中，而不是放在一个闭源的配套组件里。

## 优势

- 永久开源（FOSS）
- ELF 符号查找与 GOT 遍历由一个精简的 `no_std` Rust 核心完成，设备侧路径不做任何分配
- 支持 KernelSU **与** APatch，并提供专用构建
- 黑名单通过在被隐藏的进程自身中回滚挂载来处理，并以缓存好的干净命名空间作为回退
- 连回滚够不到的痕迹也一并隐藏：被隐藏进程里仍映射着的模块库，以及 bionic 留在那个静态缓冲里的挂载行
- 可从 LKM 启动：late-load 会话或 monitor 重启后，会重启（respawn）已在运行的进程，让真正被注入的是那一只全新的 fork

## Root 方案支持

每个压缩包只面向一种 Root 方案，并拒绝从其他方案安装：

| 压缩包 | Root 方案 | 安装方式 |
|---------|---------------|--------------|
| `VexZygisk-<ver>-release.zip` | KernelSU | KernelSU 应用 |
| `VexZygisk-APatch-<ver>-release.zip` | APatch | APatch 应用 |

- KernelSU 版直接与 KernelSU 内核接口通信（基于 ioctl），需要较新的内核与 ksud。
- APatch 版读取 `apd` 的包配置（`/data/adb/ap/package_config`）以获取 Root 授权与黑名单，并同时识别 `me.bmax.apatch` 与 `me.yuki.folk` 两个管理器。它需要较新的 APatch（`APATCH_VER_CODE >= 10762`）。
- APatch 压缩包自带一份针对 `su` 域编写的 `sepolicy.rule`（APatch 基于 magiskpolicy），而 KernelSU 版使用 `ksu` 域。

## 挂载处理

仅回滚（revert-only）是默认的挂载模式，且它作用于被隐藏的进程本身，而不是 zygote。

被列入黑名单的进程会获得一份私有的挂载树副本，root 痕迹从这份副本中**摘除（detach）**。之所以是摘除而不是卸载，是因为 metamodule 的 overlay 以 Root 方案的名称作为 source，并可能覆盖系统路径——其中包含 `framework` 与 provider 资源——一旦真正卸载到文件系统层面，WebView 就会去解析一条它自己 mountinfo 中仍标记为 overlay 的路径，从而初始化失败。摘除只是把这些挂载从该进程的视图中移除，不会拆掉任何东西。zygote 以及所有未被隐藏的进程保留原有挂载，因此 metamodule 的主题与 overlay 对依赖它们的应用依然可见；同时每个被隐藏的进程最终各自持有一个独立的命名空间对象——与普通应用形态一致，而不是与所有其他被隐藏的应用共用同一个。

`webview_zygote` 是唯一一个从未进入黑名单、却同样会被清理的进程。它会 exec 成真正的子 zygote，而每个 WebView 沙箱渲染进程都会继承它持有的命名空间，因此它是被切换到缓存好的干净命名空间，而不是就地回滚：在它内部执行卸载，会波及本不在回滚范围内的进程。

反过来从 zygote 中回滚，正是过去会破坏这些模块的做法：此后 fork 出的**每一个**进程（无论是否被隐藏）都会失去这些挂载。

在 KernelSU 与 APatch 上，模块挂载全部由 metamodule 负责，而它挂上去的东西对选择逻辑而言与 root 痕迹无法区分。只对被隐藏的进程应用回滚正好覆盖了这一点——选择逻辑本身无需区分二者。

当回滚无法应用时——痕迹中包含一个精确的 `/product` 挂载（某些 ROM 用它覆盖 zygote 资源），或其中部分挂载拒绝卸载——进程会改用命名空间方式隐藏，即切换到缓存好的干净命名空间。

两种模式都够不到全部。有两处痕迹留在被隐藏的进程内部，而且都要等模块跑完才定型：

- 仍映射在其中的模块库，每一个都在 `/proc/self/maps` 里写着自身对应的文件。这些映射会被替换成同样字节、同一地址的匿名副本，库因此仍从原处继续运行，而名字消失了。
- 被 bionic 解析进单个静态缓冲的那一行挂载。zygote 在仍带着模块挂载时读入它，此后 fork 出的每个应用都会继承，因此挂载树已被清理的进程仍能从自己的 libc 里读出这些痕迹。在挂载树已经干净的时候解析一次挂载表，就能替换掉它的内容。

在模块旁放置一个标记文件即可让所有进程都走命名空间方式，无需重新编译：

```sh
touch /data/adb/rezygisk/disable-revert   # or /data/adb/modules/rezygisk/disable-revert
```

## Late load

KernelSU 可以被注入进一个已经在运行的系统——也就是那些保持引导锁定的临时 Root 流程。在这样的会话里，`post-fs-data` 经过时 KernelSU 并不存在，模块自己的阶段脚本不会执行，monitor 也就不会启动：管理器仍把模块列为已安装，而所有 Zygisk 模块都是死的。

因此 KernelSU 版还会把自己装进 `late-load.d`——即 `ksud late-load` 在注入完成后紧接着运行的阶段。软重启会重放启动阶段但保留已注入的 KernelSU，所以正是这个阶段把 monitor 带回来；若 monitor 已在运行，它会保持不动。

注入本身只在目标**全新** fork+exec 时才会发生，因此起步太晚的 monitor 用不了那个从真正开机起就一直跑着的 zygote：所有注入入口等的都是它早已走完的启动步骤。monitor 改为把它重启（respawn）——杀掉一次，由把它当服务管理的 init 拉起新的进程，再交给正常的 fork 路径注入。由于 zygote 是 system_server 的父进程，这一步正是 late-load 用户原本要手动在管理器里点一次「软重启」的那个动作，框架恢复时开机动画会重播一次。正常开机时 monitor 早于该进程存在，因此扫描什么也扫不到，不会改变任何行为。

只有 KernelSU 版会装这个。APatch 没有对应阶段，因此 APatch 包是删除已有的副本，而不是安装一份。

## 依赖

| 工具            | 说明                            |
|-----------------|----------------------------------------|
| `Android NDK`   | Android 原生开发工具包     |

### C 依赖

| 依赖        | 说明                                              |
|-------------------|----------------------------------------------------------|
| `PLTI`            | 供注入器自身使用的简单 Android PLT Hook |
| `CSOLoader`       | 自定义 ELF 加载器，用于映射标准 Zygisk 模块          |
| `xz-embedded`     | 用于 ELF `.gnu_debugdata` 的 XZ 解压                |

## 安装

### 1. 选择正确的压缩包

有两件事决定你需要哪个包：

**Root 方案** —— 选择与你的 Root 管理器匹配的版本（KernelSU 用 `VexZygisk`，APatch 用 `VexZygisk-APatch`）。安装脚本会校验你正在刷入的管理器，不匹配则中止，因此选错不会导致设备变砖——它只是拒绝安装。

**构建类型** —— 绝大多数情况应选择 `release`，它移除了应用层日志，二进制也更优化。`debug` 则相反：日志繁重且无优化。正因如此，**它应仅用于调试目的**，以及**在为提交 Issue 采集日志时**。

至于分支，应始终使用 `main`，除非开发者另有说明，或者你希望测试尚未发布的特性并清楚其中的风险。

### 2. 刷入压缩包

在匹配的 Root 管理器中刷入：进入 KernelSU 或 APatch 应用的 `模块` 页面，选择你下载的压缩包。

刷入后，请查看安装日志以确认没有错误；一切正常即可重启设备。

### 3. 验证安装

重启后，可以通过查看 Root 管理器 `模块` 页面中的模块描述来确认 VexZygisk 是否正常工作。描述应表明所需守护进程正在运行，大致如下：`[Monitor: ✅, VexZygisk 64-bit: ✅] Standalone implementation of Zygisk.`

你也可以在 root shell 中直接询问 tracer：

```sh
/data/adb/modules/rezygisk/bin/zygisk-ptrace64 info
```

它会输出守护进程 PID、当前使用的 Root 方案以及已加载的模块。

### 4. 卡片显示已停止时

卡片可能显示监视器已停止，而在此期间不会有任何新的注入。有两种原因，都可以用管理器里这个模块的**操作按钮**（其他模块上显示为"执行"的那个）恢复：

- **刚安装或更新过模块**：安装脚本会停掉监视器（避免它与安装器改写 `module.prop` 相撞），并且不会重新拉起它。卡片会直接这么写；重启可以清除，而点按钮也可以——不必重启。
- **有人或脚本发过 `ctl stop`**：卡片会用另一种措辞说明。

点击按钮：监视器不在了就把它启动，还在但已停止就叫它重新开始跟踪。任何时候点都安全——正在正常跟踪时它什么都不做。

> [!NOTE]
> VexZygisk 仅构建并注入 arm64。64 位设备上次要的 32 位 Zygote 保持不动——它很少被使用，注入它并无收益；纯 32 位设备不再受支持。

## 构建

整个项目用普通的 `make` 即可构建（外加通过 `NDK_PATH` 指向的 NDK）：

```sh
make all                       # KernelSU flavour: debug + release
make apatch                    # APatch flavour: release, into build-apatch/
make ROOT_IMPL=apatch release  # explicit form
```

- `ROOT_IMPL` 选择后端（`ksu` 为默认值，或 `apatch`）；两个版本由同一套源码构建，产物落在各自的目录树中，缓存互不干扰。
- `main` 上的 CI 运行会产出两个 release 压缩包以及生成的 `update.json`，并在发布任何东西之前先运行宿主端测试套件（`tests/host/`）：ELF 读取器与它的 mini-debug 解压器、回滚所依赖的 mountinfo 解析、APatch 包配置解析，以及什么算模块痕迹的判定——这些都是在构建机上只是纯文本、在设备上却会静默失败的部分。

## 支持

如果出现问题，请附上 `debug` 构建的日志提交 [Issue](https://github.com/Lxiaoyao077/VexZygisk/issues)。

## 贡献

欢迎提交 Pull Request。请保持现有代码风格，并在提交前用 `debug` 构建自测。

## 致谢

本仓库建立在其他项目的工作之上，下面的列表说明了各部分与其来源的对应关系。

* [ReZygisk](https://github.com/PerformanC/ReZygisk)：本仓库所 fork 并用 C 重写的上游项目
* [Magisk](https://github.com/topjohnwu/Magisk)：现代 Android Root 与 Zygisk 本身的基石
* [OnyxZygisk](https://github.com/OnyxZygisk/OnyxZygisk)：仅回滚的挂载模型——痕迹选择逻辑，以及被隐藏进程在自身挂载树副本上执行的就地回滚
* [KernelSU](https://github.com/tiann/KernelSU)：KernelSU 版所通信的内核接口
* [APatch](https://github.com/bmax121/APatch)：APatch 版一并管理的内核补丁
* [PLTI](https://github.com/PerformanC/PLTI)：注入器自身使用的 PLT Hook
* [CSOLoader](https://github.com/ThePedroo/CSOLoader)：映射标准 Zygisk 模块的自定义 ELF 加载器
* [xz-embedded](https://tukaani.org/xz/embedded.html)：用于 `.gnu_debugdata` 的公有领域 XZ 解压器

## 许可证

VexZygisk 采用 [AGPL 3.0](./LICENSE) 许可。你可以前往 [Open Source Initiative](https://opensource.org/licenses/AGPL-3.0) 了解更多。
