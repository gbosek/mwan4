# LuCI app for mossdef-org/mwan4 — XG2010G development branch

This is a **first-stage LuCI integration package**, built from the configuration and read-only status portions of [brauliobo/luci-app-mwan4](https://github.com/brauliobo/luci-app-mwan4) (AGPL-3.0-or-later), for the [mossdef-org/mwan4](https://github.com/mossdef-org/mwan4) ucode/nftables backend.

## Available now

- Status summary using the existing `ubus call mwan4 status` RPC.
- UCI editors for `globals`, `interface`, `route`, `strategy` and `rule`.
- Read-only permissions on the `network` UCI package; write permissions only on `mwan4`.
- LuCI configuration tracking to reload mwan4 following an Apply operation.

## Intentionally omitted (not falsely advertised as functional)

- Runtime start/stop, per-WAN ifup/ifdown buttons.
- Validate/capabilities/diagnostics/advanced_control RPC buttons and advanced screens.
- Automatic migration between old `member/policy` and current `route/strategy` sections.
- Any modification to current dual-WAN, PON, PBR, firewall or NPU configuration.
- Full Chinese translation and verified firmware integration.

The mossdef RPC currently exposes `status` only; the rest of brauliobo's RPC-driven screens need an explicit backend implementation and tests before enabling.

## Using it with an OpenWrt/ImmortalWrt source tree

Copy this `luci-app-mwan4` folder to `package/custom/luci-app-mwan4`.
Ensure the firmware provides mossdef-org/mwan4 as package `mwan4` and **do not install claus778's unrelated Rust backend alongside it**.

Enable with `CONFIG_PACKAGE_luci-app-mwan4=y`; the dependency pulls `mwan4`.
Make a backup before changing multi-WAN rules. `mwan3` conflicts with this backend; do not run both.

This branch has **not** been built against the AN7581 Linux 6.18 tree or validated on an XG2010G device yet. Do not flash a production unit solely to try this code.

## Next implementation tasks

1. Implement permission-constrained `mwan4.control` RPC (start, stop, restart, ifup/ifdown).
2. Implement backend `validate` and a safe read-only `diagnostics` RPC.
3. Add translations and PBR compatibility status.
4. Integrate with XG2010G's existing NPU diagnostic app, without fabricating hardware offload counts.
5. Compare per-WAN real PPE/NPU offloads and failover behavior on the device.
