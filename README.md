# Google JP Guard · ViewTurbo 自动版

装好以后继续在 ViewTurbo Lite 中连接、断开、切换节点和设置 TUN。保护程序在 Windows 登录后自动后台运行。每次重新连接或切换节点，都会先拦截 Google，再确认当前出口。

| ViewTurbo 状态 | 受保护的 Google 连接 |
| --- | --- |
| 断开或退出 | 拦截 |
| 连接非日本节点 | 拦截 |
| 日本节点，TUN 关闭或路由未生效 | 拦截 |
| 日本出口已核验，TUN 正在工作 | 自动放行 |

## 安装与卸载

1. 解压发布页的 Windows x64 ZIP。若装过手动登记节点的旧版，先用旧包的 Guard.cmd Uninstall 卸载。
2. 用平时运行 ViewTurbo 的 Windows 账号打开**管理员 PowerShell**，进入解压目录。GitHub 上的在线安装包首次运行时会下载并校验官方依赖：

       .\Install-Online.cmd

   如已备好包含 engine.zip 的离线包，直接执行：

       .\Guard.cmd Install

3. 首次安装后完整退出再重新打开已经运行的 Chrome、Edge 或 Antigravity，让各应用重建正在使用的旧连接。此后日常只操作 ViewTurbo。

随时查看状态：

    .\Guard.cmd Status

显示 **Japan verified** 时放行。**Google blocked** 会列明原因，例如 TUN 未生效、非日本出口或正在核验。

卸载时在同一账号的管理员 PowerShell 中执行：

    .\Guard.cmd Uninstall

从源码安装时，可从下方链接单独下载同版本的 sing-box 官方 Windows x64 ZIP，并执行：

    .\Guard.cmd Install -EngineArchive C:\path\to\sing-box-1.14.4-windows-amd64.zip

## 普通网站怎么走

普通连接继续按 ViewTurbo 当前模式处理。你可以使用 **AI Proxy + TUN**，把需要加速的 Google 主域名交给 ViewTurbo 的「代理规则」，把原本应直连的常用网站交给「直连规则」。程序匹配 Google 域名和公开服务地址，并使用只处理这些地址的本机虚拟网卡。Windows 已启用 ViewTurbo 的系统代理时，程序会通过本地代理检查目标，把普通网站交回原来的 ViewTurbo 代理。

平时直接填在第三方程序里的手动代理地址如需继续使用，可填本机检查端口 **127.0.0.1:18732**。ViewTurbo 的系统代理开关会自动接入此端口。其他代理软件、自建 PAC 或独立虚拟机网络可能绕过本工具的域名识别。

## 首次验收

先用未登录的浏览器窗口。在 ViewTurbo 依次测试断开、非日本节点、日本节点关闭 TUN、日本节点开启 TUN。每次查看 Guard.cmd Status，并用刷新过的 Gemini 页面和一个普通网站验证。最后可在 Antigravity 里测试一次模型请求。网页缓存可能使已经加载的内容继续显示。

已在 Windows 11 x64 安装验证。日本出口和 TUN 开启时，Gemini 经系统代理与不显式指定代理的两条路径都可访问。三种拦截条件通过状态重放验证，再经本机实际网络确认两条路径都被阻断。四轮测试中普通网站均可访问。开机后的后台启动通过 Windows 登录任务配置，实体重启和 ViewTurbo 界面逐项切换可按上面的步骤复验。

## 机制与限制

- 节点、ViewTurbo 进程和 TUN 路由变化时，程序使原核验结果失效，关闭已识别的 Google 流，并经 ViewTurbo 的同一个 SOCKS5 入口重新读取 Cloudflare 返回的出口地区。客户端没有可原子锁定节点的公开接口。如果 ViewTurbo 或服务商在两次探测之间静默改路由，会有短暂检测窗口。出口地区核验也可能与 Google 的地区判断不同。
- 已识别的 Google 连接使用 TCP，浏览器通常会从 QUIC 回退到 HTTPS/TCP。识别范围包括常用 Google 域名、Antigravity 域名以及已公开的 Google 服务 IPv4/IPv6 网段。未知共享 IP、自定义加密 DNS 返回的未知地址、第三方加密转发属于识别盲区。
- 如果在 ViewTurbo 把 Google 域名明确设成直连，防护规则可能使它连不上。可把相关域名设为代理规则再验收。工具同时设置 Chrome 和 Edge 使用 Windows DNS，以便覆盖 Google 域名。已有企业托管 DNS 或浏览器策略时，安装可能中止。
- 程序使用未经修改的 [sing-box 1.14.4 Windows x64 官方发行文件](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)，安装会校验 SHA-256。[对应源码及许可](https://github.com/SagerNet/sing-box/tree/v1.14.4)。地址列表来自 [Google 公开 IP 范围](https://docs.cloud.google.com/vpc/docs/configure-private-google-access#ip-ranges)，扣除了 Google Cloud 客户地址段。
