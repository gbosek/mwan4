# XG2010G 配套升级评估（2026-10-28）

状态：候选源码分支，未完成整套合并、打包或实机验收；不可据此直接替换正在运行的 XG2010G。

## 固定配套来源

- 前端：brauliobo/luci-app-mwan4 d076ec4a4d794d0d1e570526f7a31462c2dafa11，Makefile 1.0.0-r11。
- 用户前端 fork：gbosek/luci-app-mwan4 main 99f18d88f5fa9fe4f6421ce11ba83d225dccaf67 已包含上述上游提交；本评估分支从该用户提交开始，保留 fork 内容。
- 后端：brauliobo/mwan4 b2a4ffd715ce9768cba92c3a20f8cb9c3c647865，Makefile 0.1.1-r26。
- 用户后端原 main：c3cc7f50b4658d881fd33452056363fdaf2cc08c。与上游分叉，上游侧 11 个提交，用户侧 2 个提交。本后端分支从上游精确提交建立，是评估基线，尚未声称保留所有原定制修复。
- 配套分支：两仓库均为 review/brauliobo-paired-20261028；main 未更新。

## 已核实的契约

前端 connections RPC 参数 rule/interface/strategy/family/proto/search/limit/offset 与后端声明一致。前端读取 interfaces.<wan>.active_connections.total，与后端文档中的对象结构一致。前端域名/MAC/DSCP/规则开关/PBR 导入由该后端实际实现，不能仅装前端便声称这些规则生效。连接数和规则命中次数不是硬件卸载率或完整 PPE 字节占比。

后端最新 family 升级迁移只转换单值，保留已有多值 family 列表，避免把 IPv4/IPv6 合成一个无效字符串。

## 必须完成的适配和验收

1. 对照设备正在使用的定制后端 0.1.1-r10，逐项回移或确认已有等效实现：DNS guard、IPv6 源路由、IPv4 启动不等待 IPv6、rtmon 路由恢复、停止状态、首次刷机默认关闭、无预设站点/测速规则。不能仅与仓库 main 比较，因为设备还有构建阶段补丁。
2. RPC 装载目前调用 m.init()；该函数会创建运行目录/写掩码文件。需保留本机已验证的“读取状态不启动或制造运行态目录”修复，不能把状态读取当服务启动。
3. 上游 LuCI 应用配置会无条件 restart；需回移“原来停止则保持停止”的逻辑。刷新只读，不主动 start/restart。
4. 新后端默认规则只匹配转发，路由器本机流量需要 local=1。升级时应明确迁移旧规则语义，尤其 DNS guard、本机验证和测速分流；不能直接认定旧配置完全等价。
5. 新 rule_mask 默认 0x00fc0000，需与实际 MWAN4、PBR、代理和 QoS 标记逐项核对。原有四接口 WAN 标记、策略与测速 nft sets 必须保留。
6. 验证稳定 id/table_id/mark、双 WAN IPv4、新连接 1:1、HTTPS sticky、两 ISP IPv6 源路由；不通过压测或主动断线代替必要的静态检查。
7. 完整 ucode/前端语法、配置迁移、nftables 生成、ACL、旧配置回归和只读状态测试通过后，再生成单独 APK 与回滚包。不需要重新编译完整固件；仅在版本/ABI 匹配后才能直接更新包。
8. 设备升级前后保存配置哈希、拨号 PID、启动身份、路由和服务状态。新版连接扫描只读但有 CPU/内存成本，必须量化，不能承诺性能提升。

## 当前设备与阻塞

设备当前原生后端仍为定制 0.1.1-r10。此前尝试的前端兼容包 r13 已写入，但 post-upgrade 脚本的 Windows 换行导致 execve 127，APK 带脚本失败标记；已准备 Unix 换行修正版和 r12 回滚包，尚未完成重装和验收，不得写成更新成功。

后续本机 shell/SSH 修复和测试被自动审批服务因账户额度不足而中断；这是审批未完成，不是安全性否定。不得借 GitHub Actions、其他传输或新进程绕过这项审批去操作设备。GitHub 只读核查及用户明确要求的新评估分支独立完成。

本地证据目录：C:/Users/40777/Desktop/XG2010G/output/mwan4-luci-update-20261028。后台持续监控与本次评估独立，不要暂停或重新启动监控，不恢复自动消息。
