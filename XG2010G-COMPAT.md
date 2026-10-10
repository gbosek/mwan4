# XG2010G compatibility branch (2026-10-11)

Backend: mossdef-org/mwan4 @ 28b384183bdf7ab43bef52d3d8ae648ba2565610 (fork gbosek/mwan4).
Frontend: brauliobo/luci-app-mwan4 @ 4412343c4484477c98991d7c29df94289cd306af (fork gbosek/luci-app-mwan4).

Basic UCI interfaces/routes/strategies/rules and status are compatible. Upstream
frontend additionally expects control/validate/capabilities/diagnostics/advanced_control.
This branch adds bounded operator control RPC and real procd runtime reporting;
removes unavailable advanced/MPTCP/diagnostics views and backend-validation calls.
Existing browser form validation and native backend configuration handling remain.
No backend validation success or unsupported counters are fabricated.

Firmware packaging uses feeds/luci/luci.mk and includes Simplified Chinese.
An incompatible prior Rust config is backed up as /etc/config/mwan4.pre-mossdef-rust.
Default WAN policy participation is disabled until WAN links are configured in LuCI.
Network/PPPoE credentials are neither copied into this repository nor rewritten.

Static review does not prove on-device failover or PPE compatibility. Keep hardware
offload settings and pinned drivers unchanged; verify matched NAT/BND/HW_OFFLOAD
flows on both WANs after flashing. IRQ rate alone is not an offload percentage.
