# Changelog

## 0.1.1-r5

- Define `delete_iface_rules_family()` before its first use, so ucode can build
  interface rules without failing partway through startup.
- Invoke address-family callbacks directly with their documented arguments.
- Read the global `mmx_mask` option using the correct UCI key.
- Identify tracker processes by their NUL-separated argv entries instead of a
  substring match; compare both interface name and address family.
- Read nftables chain contents from `list table`, so strategy weights can be
  reported. Use floating-point arithmetic for percentage shares.
- Read tracker files from the exported package status directory, report actual
  network interface aliases, and preserve absent measurements as null.
- Report per-family health, tracker scores, failed targets, and actual procd
  service/tracker coverage to LuCI.
- Reload the long-lived RPC UCI cursor before status and control requests.
- Provide constrained start/stop/restart and configured-interface ifup/ifdown
  RPC actions, protected by the existing LuCI operator ACL.

This change contains package source fixes only. Router-specific DNS, WAN
credentials, address lists, and NIKKI settings are not part of this repository.
