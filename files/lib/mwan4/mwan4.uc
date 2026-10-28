'use strict';
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
// Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>

import { readfile, writefile, popen, stat, unlink } from 'fs';
import { cursor } from 'uci';
import package_ctl from 'packages';
import dnsmasq from 'dnsmasq';
import connections from 'connections';

// Forward declarations — defined later but referenced by the export block.
// ucode does not hoist function declarations.
let rebuild_dynamic;
let prefetch_domains;
let _ensure_init;

// ── Constants ────────────────────────────────────────────────────────

const STATUS_DIR = '/var/run/mwan4';
const STATUS_NFT_LOG_DIR = STATUS_DIR + '/nft_log';
const TRACK_STATUS_DIR = '/var/run/mwan4track';
const CONNTRACK_FILE = '/proc/net/nf_conntrack';
const CONNTRACK_ACCT_FILE = '/proc/sys/net/netfilter/nf_conntrack_acct';
const CONNTRACK_CACHE_TTL = 2;
// Bits 18-23 of the PBR range: pbr never touches conntrack marks, and no other default mark layout leaves bits free.
const DEFAULT_RULE_MASK = '0x00fc0000';
const CONNECTIONS_DEFAULT_LIMIT = 200;
const CONNECTIONS_MAX_LIMIT = 1000;
const DEFAULT_LOWEST_METRIC = 256;
const MPTCP_STATE_FILE = STATUS_DIR + '/mptcp.endpoints';

const NFT_TABLE = 'fw4';
const NFT_PREFIX = 'mwan4';
const NFT_IPV4 = 'ip';
const NFT_IPV6 = 'ip6';
const NFT_TEMP = '/var/run/mwan4.nft';
const STATUS_DIAGNOSTIC_ACTION = 'Start or restart mwan4 from LuCI, or run `/etc/init.d/mwan4 restart`, then re-check `mwan4 status`.';
const SERVICE_DIAGNOSTIC_CHECK = 'Verify service instances with `ubus call service list \'{"name":"mwan4"}\'`.';
const TRACKER_DIAGNOSTIC_ACTION = 'Restart mwan4, then verify tracker instances named `track_<iface>_<family>` are running.';
const TRACKER_DIAGNOSTIC_CHECK = 'Check enabled interfaces with `track_ip` and status files under `/var/run/mwan4track`.';
const NFT_DIAGNOSTIC_ACTION = 'Restart mwan4 or reload firewall, then re-check generated nftables chains.';
const NFT_DIAGNOSTIC_CHECK = 'Run `nft list table inet fw4` and inspect `/usr/share/nftables.d/ruleset-post/10-mwan4.nft`.';
const TUNNEL_DIAGNOSTIC_ACTION = 'Review tunnel underlay_strategy and route references; keep tunnel underlays on physical WAN strategies.';
const TUNNEL_DIAGNOSTIC_CHECK = 'Review Diagnostics > Tunnels and keep tunnel underlay strategies on physical WAN routes.';

const CONTRACT_VERSION = 2;
const STATUS_SECTIONS = ['interfaces', 'connected', 'strategies', 'rules', 'diagnostics', 'counters', 'tunnels'];
const DIAGNOSTIC_SECTIONS = ['all', 'summary', 'interfaces', 'routes', 'rules', 'connections', 'strategies', 'nftables', 'service', 'tunnels', 'counters', 'ownership', 'pbr', 'mptcp', 'quality', 'probes', 'vrf', 'explain', 'packages'];
const RUNTIME_CONTROL_ACTIONS = ['ifup', 'ifdown', 'start', 'stop', 'restart', 'reload', 'reset_counters'];
const ADVANCED_CONTROL_ACTIONS = ['install_feature', 'wireguard_keygen', 'apply_tunnel_exemptions', 'apply_bfd'];
const CONTROL_ACTIONS = ['ifup', 'ifdown', 'start', 'stop', 'restart', 'reload', 'reset_counters', 'install_feature', 'wireguard_keygen', 'apply_tunnel_exemptions', 'apply_bfd'];

// 2-file architecture: dynamic (rebuilt on hotplug) + rules (init only)
const NFT_FILES = {
	dynamic: '/usr/share/nftables.d/ruleset-post/10-mwan4.nft',
	rules:   '/usr/share/nftables.d/ruleset-post/11-mwan4-rules.nft',
};

const IPv4_RE = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/[0-9]+)?$/;
const IPv6_RE = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(\/[0-9]+)?$/;
const SECTION_RE = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$/;
const NFT_ID_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const NFT_ID_PART_RE = /^[A-Za-z0-9_]{1,64}$/;
const DEVICE_RE = /^[A-Za-z0-9_.:@+-]{1,64}$/;
const ROUTE_TABLE_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,31}$/;
const MAC_RE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
const HOSTNAME_RE = /^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$/;

// Generated catch-all rules: always evaluated last and applied to router-originated traffic.
const DEFAULT_RULES = {
	default_rule_v4: true,
	default_rule_v6: true,
};

const VALID_PROTOCOLS = {
	all:          true,
	tcp:          true,
	udp:          true,
	udplite:      true,
	icmp:         true,
	'ipv6-icmp':  true,
	esp:          true,
	ah:           true,
	sctp:         true,
	dccp:         true,
	gre:          true,
};

const VALID_NPING_PROTOCOLS = {
	tcp:   true,
	udp:   true,
	icmp:  true,
	arp:   true,
	sctp:  true,
};

const VALID_TRACK_METHODS = {
	ping:      true,
	arping:    true,
	httping:   true,
	nslookup:  true,
};

const QUALITY_TRACK_METHODS = {
	ping:    true,
	httping: true,
};

const TRACK_METHOD_HELPERS = {
	arping:   'arping',
	httping:  'httping',
	nslookup: 'nslookup',
};

const MPTCP_ENDPOINT_FLAGS = {
	signal:   true,
	subflow:  true,
	backup:   true,
	fullmesh: true,
};

const VALID_LOGLEVELS = {
	emerg:    true,
	alert:    true,
	crit:     true,
	err:      true,
	error:    true,
	warn:     true,
	warning:  true,
	notice:   true,
	info:     true,
	debug:    true,
};

const VALID_TUNNEL_TRANSPORTS = {
	wireguard: true,
	gre:       true,
	ipip:      true,
	sit:       true,
	openvpn:   true,
	ipsec:     true,
	tunnel:    true,
	generic:   true,
};

const VALID_TUNNEL_FAIL_MODES = {
	hold:        true,
	fail_open:   true,
	fail_closed: true,
};

const BFD_SCHEMA = {
	'mode':        'metadata_only',
	'owner':       'frr',
	'apply_action': 'apply_bfd',
	'fields':      ['bfd_peer', 'bfd_vrf', 'bfd_min_rx', 'bfd_min_tx', 'bfd_multiplier'],
};

// ── Package Constants ────────────────────────────────────────────────

const pkg = {
	STATUS_DIR, STATUS_NFT_LOG_DIR, TRACK_STATUS_DIR,
	CONNTRACK_FILE, DEFAULT_LOWEST_METRIC,
	MPTCP_STATE_FILE,
	NFT_TABLE, NFT_PREFIX, NFT_IPV4, NFT_IPV6, NFT_TEMP, NFT_FILES,
	STATUS_DIAGNOSTIC_ACTION, SERVICE_DIAGNOSTIC_CHECK,
	TRACKER_DIAGNOSTIC_ACTION, TRACKER_DIAGNOSTIC_CHECK,
	NFT_DIAGNOSTIC_ACTION, NFT_DIAGNOSTIC_CHECK,
	TUNNEL_DIAGNOSTIC_ACTION, TUNNEL_DIAGNOSTIC_CHECK,
	CONTRACT_VERSION, STATUS_SECTIONS, DIAGNOSTIC_SECTIONS, CONTROL_ACTIONS,
	IPv4_RE, IPv6_RE,
};

// ── Module State ─────────────────────────────────────────────────────

let uci_ctx = null;
let ubus_conn = null;
let mm_blackhole = '';
let mm_unreachable = '';
let _loaded = false;

let mwan4 = {
	scriptname: 'mwan4',
	no_ipv6: 1,
	mmx_mask: '', mmx_default: '', mmx_blackhole: '', mmx_unreachable: '',
	rule_mask: '', rule_mask_n: 0, rule_mask_inv: '',
	iface_max: 0,
	iface_tbl: {}, iface_table_tbl: {}, iface_mark_tbl: {}, dev_tbl: { ipv4: {}, ipv6: {} },
	source_routing: false,
	errors: [], warnings: [],
	reset: function() { this.errors = []; this.warnings = []; },
};

// ── Utility Functions ────────────────────────────────────────────────

function set_scriptname(name) { mwan4.scriptname = name; }

function LOG(facility, ...args) {
	if (facility == 'debug') return;
	let msg = replace(join(' ', args), "'", "'\\''");
	system(sprintf("logger -t '%s' -p %s '%s'", mwan4.scriptname, facility, msg));
}

function shell_quote(s) {
	return "'" + replace('' + s, "'", "'\\''") + "'";
}

function run(c) {
	return system(c + ' >/dev/null 2>&1');
}

function cmd_output(c) {
	let p = popen(c, 'r');
	if (!p) return '';
	let out = p.read('all') || '';
	p.close();
	return out;
}

function cmd_lines(c) {
	let raw = cmd_output(c);
	if (!length(raw)) return [];
	return split(rtrim(raw, '\n'), '\n');
}

function read_str(path) {
	return rtrim(readfile(path) || '', '\n') || null;
}

function read_int(path) {
	return int(read_str(path) || '0');
}

function read_int_nullable(path) {
	let value = read_str(path);
	return value == null ? null : int(value);
}

function parse_hex_int(value) {
	if (value == null) return 0;
	let text = lc(trim('' + value));
	if (!length(text)) return 0;
	if (index(text, '0x') != 0)
		return int(hex(text));
	return int(hex(substr(text, 2)));
}

function format_hex(value) {
	if (value == null) return null;
	let text = lc(trim('' + value));
	if (!length(text)) return null;
	return index(text, '0x') == 0 ? text : '0x' + text;
}

function int_list(text) {
	let result = [];
	let seen = {};

	for (let value in split(trim(text || ''), /[ \t\n]+/)) {
		if (!length(value)) continue;
		let n = int(value);
		if (!seen[n]) {
			seen[n] = true;
			push(result, n);
		}
	}

	sort(result, (a, b) => a - b);
	return result;
}

function external_uci_get(config, section, option) {
	let c = cursor();
	if (!c) return null;
	c.load(config);
	return c.get(config, section, option);
}

function elapsed_since(path, uptime) {
	let value = read_int_nullable(path);
	if (value == null || value <= 0) return null;
	return uptime - value;
}

function as_list(value) {
	if (value == null) return [];
	if (type(value) == 'array') return value;
	return [value];
}

function ensure_dir(path) {
	if (!stat(path))
		system(sprintf("mkdir -p '%s'", path));
}

function file_exists(path) {
	return !!stat(path);
}

// ── nft_file Dispatcher ──────────────────────────────────────────────
// IIFE encapsulates private state (targets map) and helpers (check, apply,
// install_all, install_targets).  Only the returned dispatcher is visible.

let nft_file = (function() {
	let targets = {};

	function check(filepath) {
		let err = trim(cmd_output(sprintf('nft -c -f %s 2>&1', filepath)));
		if (length(err)) {
			push(mwan4.errors, { code: 'errorNftCheck', info: filepath + ': ' + err });
			LOG('error', 'nft check failed for', filepath + ':', err);
			return false;
		}
		return true;
	}

	function apply(filepath) {
		if (!check(filepath))
			return false;
		let err = trim(cmd_output(sprintf('nft -f %s 2>&1', filepath)));
		if (length(err)) {
			push(mwan4.errors, { code: 'errorNftApply', info: filepath + ': ' + err });
			LOG('error', 'nft -f', filepath + ':', err);
			return false;
		}
		return true;
	}

	function install_all() {
		let dest_dir = match(NFT_FILES.dynamic, /^(.+)\//);
		if (dest_dir) ensure_dir(dest_dir[1]);

		let combined_content = '';
		let has_content = false;
		for (let target in keys(NFT_FILES)) {
			let lines = targets[target];
			if (!lines || !length(lines)) continue;
			has_content = true;
			combined_content += join('\n', lines) + '\n\n';
		}

		if (!has_content) return true;

		let combined = NFT_TEMP + '.combined';
		writefile(combined, combined_content);
		let err = trim(cmd_output(sprintf('nft -c -f %s 2>&1', combined)));
		unlink(combined);
		if (length(err)) {
			push(mwan4.errors, { code: 'errorNftCombinedCheck', info: err });
			LOG('error', 'Combined nft validation failed:', err);
			return false;
		}

		for (let target in keys(NFT_FILES)) {
			let lines = targets[target];
			if (!lines || !length(lines)) continue;
			writefile(NFT_FILES[target], join('\n', lines) + '\n');
			LOG('info', 'Installed nft file to', NFT_FILES[target]);
		}
		return true;
	}

	function install_targets(changed) {
		let dest_dir = match(NFT_FILES.dynamic, /^(.+)\//);
		if (dest_dir) ensure_dir(dest_dir[1]);

		let combined_content = '';
		for (let target in keys(NFT_FILES)) {
			if (index(changed, target) >= 0 && targets[target] && length(targets[target])) {
				combined_content += join('\n', targets[target]) + '\n\n';
			} else {
				let existing = readfile(NFT_FILES[target]);
				if (existing)
					combined_content += existing + '\n';
			}
		}

		let combined = NFT_TEMP + '.combined';
		writefile(combined, combined_content);
		let err = trim(cmd_output(sprintf('nft -c -f %s 2>&1', combined)));
		unlink(combined);
		if (length(err)) {
			push(mwan4.errors, { code: 'errorNftCombinedCheck', info: err });
			LOG('error', 'Combined nft validation failed:', err);
			return false;
		}

		for (let target in changed) {
			let lines = targets[target];
			if (!lines || !length(lines)) continue;
			writefile(NFT_FILES[target], join('\n', lines) + '\n');
			LOG('info', 'Installed nft file to', NFT_FILES[target]);
		}
		return true;
	}

	return function(command, target, ...extra) {
		switch (command) {
		case 'create':
			targets[target] = [];
			break;
		case 'add':
			if (!targets[target]) targets[target] = [];
			for (let line in extra)
				push(targets[target], line);
			break;
		case 'install':
			if (target == 'all')
				return install_all();
			return install_targets(type(target) == 'array' ? target : [target]);
		case 'check':
			return check(target);
		case 'apply':
			return apply(target);
		case 'delete':
			if (target == 'all') {
				for (let t in keys(NFT_FILES)) unlink(NFT_FILES[t]);
				targets = {};
			} else if (NFT_FILES[target]) {
				unlink(NFT_FILES[target]);
				delete targets[target];
			}
			break;
		case 'exists': {
			let s = stat(NFT_FILES[target]);
			return s != null && s.size > 0;
		}
		case 'show':
			return readfile(NFT_FILES[target]) || '';
		}
		return true;
	};
})();

function fw4_reload() {
	let rc = system('fw4 -q reload 2>/dev/null');
	if (rc != 0) {
		push(mwan4.errors, { code: 'errorFw4Reload', info: 'fw4 reload exit code ' + rc });
		LOG('error', 'fw4 reload failed');
	} else {
		prefetch_domains();
	}
	return rc == 0;
}

function nft_output(args) {
	return cmd_output('nft ' + args);
}

function nft_counter_name(...parts) {
	let cleaned = [];
	for (let part in parts) {
		let value = lc('' + part);
		value = replace(value, /[^a-z0-9_]+/g, '_');
		value = replace(value, /^_+/, '');
		value = replace(value, /_+$/, '');
		if (length(value)) push(cleaned, value);
	}
	return NFT_PREFIX + '_counter_' + join('_', cleaned);
}

function nft_add_counter(counter_defs, counter_seen, ...parts) {
	let name = nft_counter_name(...parts);
	if (!counter_seen[name]) {
		counter_seen[name] = true;
		push(counter_defs, '', sprintf('\tcounter %s {', name), '\t}');
	}
	return name;
}

function nft_counter_use(name) {
	return sprintf('counter name %s', name);
}

// ── Ubus Helpers ─────────────────────────────────────────────────────

function ubus_call(path, method, args) {
	if (!ubus_conn)
		ubus_conn = require('ubus').connect();
	return ubus_conn?.call(path, method, args || {});
}

function network_get_device(iface) {
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	return s?.l3_device || s?.device;
}

function network_get_ipaddr(iface) {
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	let addrs = s?.['ipv4-address'];
	return (type(addrs) == 'array' && length(addrs)) ? addrs[0]?.address : null;
}

function network_get_ipaddr6(iface) {
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	let addrs = s?.['ipv6-address'];
	return (type(addrs) == 'array' && length(addrs)) ? addrs[0]?.address : null;
}

function network_get_prefix6(iface) {
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	let pfxs = s?.['ipv6-prefix'];
	if (type(pfxs) == 'array' && length(pfxs)) {
		let pfx = pfxs[0];
		return sprintf('%s/%d', pfx.address, pfx.mask);
	}
	return null;
}

function network_get_uptime(iface) { // ucode-lsp disable
	let s = ubus_call(sprintf('network.interface.%s', iface), 'status');
	return s?.uptime || 0;
}

// ── Bit Manipulation ─────────────────────────────────────────────────

function count_one_bits(n) { // ucode-lsp disable
	let count = 0;
	n = +n;
	while (n > 0) {
		n = n & (n - 1);
		count++;
	}
	return count;
}

function id2mask(id, mask) {
	let bit_val = 0, result = 0;
	let m = +mask, v = +id;
	for (let bit = 0; bit < 32; bit++) {
		if ((m >> bit) & 1) {
			if ((v >> bit_val) & 1)
				result |= (1 << bit);
			bit_val++;
		}
	}
	return sprintf('0x%x', result);
}

function parse_positive_int(val) {
	if (val == null || val == '') return null;
	let s = '' + val;
	if (!match(s, /^[0-9]+$/)) return null;
	let n = int(s);
	return n > 0 ? int(n) : null;
}

function parse_mark(val) {
	if (val == null || val == '') return null;
	let s = lc('' + val);
	if (!match(s, /^(0x[0-9a-f]+|[0-9]+)$/)) return null;
	let n = +s;
	return n > 0 ? sprintf('0x%x', n) : null;
}

function stable_iface_id(section, ordinal) {
	return parse_positive_int(section.id) || ordinal;
}

function stable_iface_table_id(section, id) {
	return parse_positive_int(section.table_id) || id;
}

function stable_iface_mark(section, id) {
	return parse_mark(section.mark) || id2mask(id, mwan4.mmx_mask);
}

// ── UCI Helpers ──────────────────────────────────────────────────────

function uci_bool(val) {
	if (val == null) return false;
	switch ('' + val) {
		case '1': case 'yes': case 'on': case 'true': case 'enabled':
			return true;
		default:
			return false;
	}
}

// ── Validation Helpers ───────────────────────────────────────────────

function warn_invalid(kind, value, context) {
	let where = context ? sprintf(' in %s', context) : '';
	LOG('warn', sprintf('Ignoring invalid %s%s: %s', kind, where, '' + value));
}

function validate_section_name(value) {
	if (value == null) return false;
	return !!match('' + value, SECTION_RE);
}

function validate_nft_identifier(value) {
	if (value == null) return false;
	return !!match('' + value, NFT_ID_RE);
}

function validate_nft_identifier_part(value) {
	if (value == null) return false;
	return !!match('' + value, NFT_ID_PART_RE);
}

function validate_nft_section_name(value) {
	return validate_section_name(value) && validate_nft_identifier_part(value);
}

function validate_device_name(value) {
	if (value == null) return false;
	return !!match('' + value, DEVICE_RE);
}

function validate_family(value) {
	return value == 'ipv4' || value == 'ipv6';
}

function normalize_family(value) {
	if (validate_family(value)) return value;
	return null;
}

function filter_valid_families(values, context) {
	let valid = [];
	for (let family in values) {
		let raw = family;
		family = normalize_family(raw);
		if (!family) {
			warn_invalid('family', raw, context);
			continue;
		}
		if (index(valid, family) < 0)
			push(valid, family);
	}
	return valid;
}

function validate_uint_range(value, min, max) {
	if (value == null) return false;
	let s = '' + value;
	if (!match(s, /^[0-9]+$/)) return false;
	let n = +s;
	return n >= min && n <= max;
}

function validate_route_table_lookup(value) {
	if (value == null) return false;
	let s = '' + value;
	if (validate_uint_range(s, 0, 4294967295)) return true;
	return !!match(s, ROUTE_TABLE_RE);
}

function filter_route_table_lookups(values, context) {
	let valid = [];
	for (let table in values) {
		if (!validate_route_table_lookup(table)) {
			warn_invalid('route table lookup', table, context);
			continue;
		}
		push(valid, table);
	}
	return valid;
}

function valid_prefix(value, max) {
	let m = match(value, /\/([0-9]+)$/);
	if (!m) return true;
	return validate_uint_range(m[1], 0, max);
}

function validate_ipv4_cidr(value) {
	if (value == null) return false;
	let s = '' + value;
	return !!match(s, IPv4_RE) && valid_prefix(s, 32);
}

function validate_ipv6_cidr(value) {
	if (value == null) return false;
	let s = '' + value;
	return !!match(s, IPv6_RE) && valid_prefix(s, 128);
}

function validate_rule_address(value, family) {
	if (!value) return true;
	if (family == 'ipv4') return validate_ipv4_cidr(value);
	if (family == 'ipv6') return validate_ipv6_cidr(value);
	return false;
}

function validate_hostname(value) {
	if (value == null) return false;
	let s = '' + value;
	if (!length(s) || length(s) > 253) return false;
	if (index(s, '..') >= 0) return false;
	return !!match(s, HOSTNAME_RE);
}

function validate_track_target(value) {
	if (value == null) return false;
	let s = '' + value;
	if (index(s, '/') >= 0) return false;
	return validate_ipv4_cidr(s) || validate_ipv6_cidr(s) || validate_hostname(s);
}

function canonical_protocol(value) {
	let proto = lc('' + value);
	return proto == 'icmpv6' ? 'ipv6-icmp' : proto;
}

function validate_protocol(value) {
	if (value == null) return false;
	let proto = canonical_protocol(value);
	if (exists(VALID_PROTOCOLS, proto)) return true;
	return validate_uint_range(proto, 0, 255);
}

function normalize_protocol(value) {
	if (value == null) return null;
	let proto = canonical_protocol(value);
	return validate_protocol(proto) ? proto : null;
}

function validate_track_method_name(value) {
	if (value == null) return false;
	let method = lc('' + value);
	if (exists(VALID_TRACK_METHODS, method)) return true;
	let nping = match(method, /^nping-(.+)$/);
	return !!nping && exists(VALID_NPING_PROTOCOLS, nping[1]);
}

function normalize_track_method(value) {
	let method = lc('' + (value || 'ping'));
	return validate_track_method_name(method) ? method : 'ping';
}

function track_method_helper(method) {
	method = normalize_track_method(method);
	if (match(method, /^nping-/)) return 'nping';
	return TRACK_METHOD_HELPERS[method] || null;
}

function track_method_supports_quality(method) {
	return !!QUALITY_TRACK_METHODS[normalize_track_method(method)];
}

function helper_available(name) {
	if (!name) return true;
	return length(trim(cmd_output(sprintf('command -v %s 2>/dev/null', shell_quote(name))))) > 0;
}

function generate_wireguard_keypair() {
	let out = trim(cmd_output("sh -c 'k=$(wg genkey) || exit 1; p=$(printf \"%s\\n\" \"$k\" | wg pubkey) || exit 1; printf \"%s\\n%s\\n\" \"$k\" \"$p\"' 2>/dev/null"));
	let lines = split(out, '\n');
	let errors = [];

	if (length(lines) < 2 || !length(lines[0]) || !length(lines[1]))
		push(errors, contract_problem('wireguardKeygenFailed', 'wireguard',
			'Unable to generate WireGuard keypair with wg genkey/wg pubkey.'));

	return {
		'ok':          length(errors) == 0,
		'private_key': length(errors) ? null : lines[0],
		'public_key':  length(errors) ? null : lines[1],
		'errors':      errors,
	};
}

function track_method_available(method) {
	method = normalize_track_method(method);
	if (method == 'ping')
		return helper_available('ping') || helper_available('ping6') || file_exists('/bin/ping') || file_exists('/usr/bin/ping');
	return helper_available(track_method_helper(method));
}

function probe_helper_statuses() {
	let methods = ['ping', 'httping', 'nslookup', 'arping', 'nping-tcp', 'nping-udp', 'nping-icmp', 'nping-arp'];
	let result = {};

	for (let method in methods) {
		let helper = method == 'ping' ? 'ping' : track_method_helper(method);
		result[method] = {
			'helper':            helper,
			'available':         track_method_available(method),
			'quality_supported': track_method_supports_quality(method),
		};
	}

	return result;
}

function validate_mptcp_flag(value) {
	if (value == null) return false;
	return !!MPTCP_ENDPOINT_FLAGS[lc('' + value)];
}

function validate_mptcp_endpoint_id(value) {
	return validate_uint_range(value, 1, 255);
}

function validate_mptcp_limit(value) {
	return validate_uint_range(value, 0, 65535);
}

function validate_mptcp_address(value) {
	if (value == null) return false;
	let s = trim('' + value);
	if (!length(s) || index(s, '/') >= 0) return false;
	if (match(s, /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/)) return true;
	return index(s, ':') >= 0 && !!match(s, /^[0-9A-Fa-f:]+$/);
}

function mptcp_address_family(value) {
	if (!validate_mptcp_address(value)) return null;
	return index('' + value, ':') >= 0 ? 'ipv6' : 'ipv4';
}

function validate_port_element(value) {
	if (!length(value)) return false;
	let range = match(value, /^([0-9]{1,5})-([0-9]{1,5})$/);
	if (range) {
		let first = int(range[1]);
		let last = int(range[2]);
		return first <= last && first >= 0 && last <= 65535;
	}
	if (match(value, /^[0-9]{1,5}$/))
		return validate_uint_range(value, 0, 65535);
	return !!match(value, /^[A-Za-z][A-Za-z0-9_-]{0,31}$/);
}

function normalize_ports(value) {
	if (value == null) return '';
	let ports = replace(trim('' + value), /[ \t]/g, '');
	if (!length(ports)) return '';
	let elements = split(ports, ',');
	for (let element in elements)
		if (!validate_port_element(element)) return null;
	return join(',', elements);
}

function validate_ports(value) {
	return normalize_ports(value) != null;
}

function parse_uint_number(value) {
	if (value == null || value == '') return null;
	let s = trim('' + value);
	if (!match(s, /^[0-9]+$/)) return null;
	return int(s);
}

function parse_mark_number(value) {
	if (value == null || value == '') return null;
	let s = lc(trim('' + value));
	if (match(s, /^0x[0-9a-f]+$/)) return int(hex(substr(s, 2)));
	if (match(s, /^[0-9]+$/)) return int(s);
	return null;
}

function rule_address_valid_any(value) {
	return validate_rule_address(value, 'ipv4') || validate_rule_address(value, 'ipv6');
}

function validate_mac(value) {
	return value != null && !!match('' + value, MAC_RE);
}

function validate_dscp(value) {
	return validate_uint_range(value, 1, 63);
}

function rule_enabled(rule) {
	return rule.enabled == null || uci_bool(rule.enabled);
}

// IPv6 addresses stored as "/N" by older UI versions lose their leading "::".
function fix_rule_address(addr, family) {
	return (family == 'ipv6' && substr(addr, 0, 1) == '/') ? ':' + addr : addr;
}

// Entries valid for the family; null when the option is set but nothing applies to it.
function rule_family_values(rule, option, family) {
	let all = map(as_list(rule[option]), addr => fix_rule_address(trim('' + addr), family));
	let values = filter(all, addr => validate_rule_address(addr, family));
	return (length(all) && !length(values)) ? null : values;
}

// Entries accepted by `valid`; null when the option is set but nothing is usable.
function rule_valid_values(rule, option, valid, kind) {
	let all = map(as_list(rule[option]), v => trim('' + v));
	let values = filter(all, v => valid(v));
	for (let v in all)
		if (!valid(v)) warn_invalid(kind, v, sprintf('rule %s', rule['.name']));
	return (length(all) && !length(values)) ? null : values;
}

function nft_value_set(values) {
	return length(values) == 1 ? values[0] : sprintf('{ %s }', join(', ', values));
}

function endpoint_family(endpoint) {
	if (!endpoint || index(endpoint, '/') >= 0) return null;
	if (validate_ipv4_cidr(endpoint)) return 'ipv4';
	if (validate_ipv6_cidr(endpoint)) return 'ipv6';
	return null;
}

function validate_endpoint_host(value) {
	if (!value) return false;
	return endpoint_family(value) != null || validate_hostname(value);
}

function validate_fail_mode(value) {
	return value == null || exists(VALID_TUNNEL_FAIL_MODES, '' + value);
}

function validate_bfd_interval(value) {
	return value == null || validate_uint_range(value, 1, 60000);
}

function validate_bfd_multiplier(value) {
	return value == null || validate_uint_range(value, 1, 255);
}

function validate_loglevel(value) {
	if (value == null) return false;
	return exists(VALID_LOGLEVELS, lc('' + value));
}

function normalize_loglevel(value) {
	if (value == null) return null;
	let level = lc('' + value);
	return validate_loglevel(level) ? level : null;
}

function uci_get(section, option, def) {
	_ensure_init();
	let val = uci_ctx?.get('mwan4', section, option);
	return val ?? def ?? null;
}

function uci_get_list(section, option) {
	_ensure_init();
	let val = uci_ctx?.get('mwan4', section, option);
	return as_list(val);
}

function uci_get_bool(section, option, def) { // ucode-lsp disable
	let val = uci_get(section, option);
	if (val == null) return def || false;
	return uci_bool(val);
}

function uci_get_alias(section, option, alias, def) {
	let val = uci_get(section, option);
	if (val != null) return val;

	val = uci_get(section, alias);
	if (val != null) return val;

	return def ?? null;
}

function uci_get_bool_alias(section, option, alias, def) {
	let val = uci_get_alias(section, option, alias);
	if (val == null) return def || false;
	return uci_bool(val);
}

function uci_foreach(stype, callback) {
	_ensure_init();
	uci_ctx?.foreach('mwan4', stype, callback);
}

function uci_section_names(stype) {
	let result = [];
	uci_foreach(stype, function(s) {
		push(result, s['.name']);
	});
	return result;
}

function uci_section_map(stype) {
	let result = {};
	uci_foreach(stype, function(s) {
		result[s['.name']] = s;
	});
	return result;
}

// Config order is the rule priority; the generated catch-alls always go last.
function ordered_rules() {
	let rules = [];
	uci_foreach('rule', s => push(rules, s));
	return [...filter(rules, s => !DEFAULT_RULES[s['.name']]), ...filter(rules, s => DEFAULT_RULES[s['.name']])];
}

// ── Rule IDs ─────────────────────────────────────────────────────────

// Id 0 is reserved for connections without rule bits (the catch-alls).
function rule_capacity() {
	return (1 << count_one_bits(mwan4.rule_mask_n)) - 1;
}

function valid_rule_id(value) {
	let id = parse_uint_number(value);
	return (id != null && id >= 1 && id <= rule_capacity()) ? id : 0;
}

function user_rule_sections(c) {
	let sections = [];
	c.foreach('mwan4', 'rule', s => push(sections, s));
	return filter(sections, s => !DEFAULT_RULES[s['.name']]);
}

function lowest_free_rule_id(used) {
	for (let id = 1; id <= rule_capacity(); id++)
		if (!used[id]) return id;
	return 0;
}

// Give every user rule without a valid, unique rule_id the lowest free one. Ids are
// never reassigned while the section exists, so reordering or deleting other rules keeps them.
// Returns the number of changed sections; the caller saves and commits.
function assign_rule_ids(c) {
	_ensure_init();
	let used = {}, pending = [];
	for (let s in user_rule_sections(c)) {
		let id = valid_rule_id(s.rule_id);
		if (id && !used[id]) used[id] = true;
		else push(pending, s['.name']);
	}

	let changed = 0;
	for (let name in pending) {
		let id = lowest_free_rule_id(used);
		if (!id) break;
		used[id] = true;
		c.set('mwan4', name, 'rule_id', '' + id);
		changed++;
	}
	return changed;
}

function ensure_rule_ids() {
	_ensure_init();
	if (!assign_rule_ids(uci_ctx)) return;
	uci_ctx.save('mwan4');
	uci_ctx.commit('mwan4');
}

// ── Lazy Initialization ──────────────────────────────────────────────

_ensure_init = function() {
	if (_loaded) return;
	_loaded = true;

	if (!uci_ctx) {
		uci_ctx = cursor();
		uci_ctx.load('mwan4');
	}

	mwan4.no_ipv6 = (system('ip -6 addr show >/dev/null 2>&1') == 0) ? 0 : 1;

	if (!mwan4.mmx_mask) {
		mwan4.mmx_mask = uci_get_alias('globals', 'mmx_mask', 'mwan4.mmx_mask', '0x3F00');
		mwan4.mmx_mask = lc(mwan4.mmx_mask);
	}
	if (!mwan4.mmx_mask_inv)
		mwan4.mmx_mask_inv = sprintf('0x%08x', 0xffffffff & ~(+mwan4.mmx_mask));

	let bitcnt = count_one_bits(mwan4.mmx_mask);
	let mmdefault = (1 << bitcnt) - 1;
	if (!mwan4.iface_max)
		mwan4.iface_max = mmdefault - 3;

	mm_blackhole = mmdefault - 2;
	mm_unreachable = mmdefault - 1;
	mwan4.mmx_default = id2mask(mmdefault, mwan4.mmx_mask);
	mwan4.mmx_blackhole = id2mask(mm_blackhole, mwan4.mmx_mask);
	mwan4.mmx_unreachable = id2mask(mm_unreachable, mwan4.mmx_mask);

	mwan4.source_routing = uci_get_bool_alias('globals', 'source_routing', 'mwan4.source_routing', false);

	// An invalid or overlapping rule_mask disables rule bits (validate reports it).
	mwan4.rule_mask = lc(uci_get_alias('globals', 'rule_mask', 'mwan4.rule_mask', DEFAULT_RULE_MASK));
	let rule_mask = parse_mark_number(mwan4.rule_mask);
	mwan4.rule_mask_n = (rule_mask > 0 && rule_mask <= 0xffffffff && !(rule_mask & +mwan4.mmx_mask)) ? rule_mask : 0;
	mwan4.rule_mask_inv = sprintf('0x%08x', 0xffffffff & ~mwan4.rule_mask_n);
};

function load() {
	_ensure_init();
}

// Long-lived consumers (rpcd) must see UCI changes made after they started.
function reload() {
	uci_ctx = null;
	_loaded = false;
	_ensure_init();
}

// ── Uptime ───────────────────────────────────────────────────────────

function get_uptime() {
	return int(split(readfile('/proc/uptime') || '0', '.')[0]);
}

function get_online_time(iface) {
	let time_u = read_int(sprintf('%s/%s/ONLINE', TRACK_STATUS_DIR, iface));
	if (!time_u || time_u == 0) return 0;
	return get_uptime() - time_u;
}

// ── Family Helpers ───────────────────────────────────────────────────

function get_families(iface) {
	let families = uci_get_list(iface, 'family');
	if (!length(families)) return ['ipv4'];
	return filter_valid_families(families, sprintf('interface %s', iface));
}

function foreach_family(iface, cb, ...extra) {
	let families = get_families(iface);
	for (let family in families)
		cb(iface, family, ...extra);
}

// ── Interface Helpers ────────────────────────────────────────────────

function get_true_iface(iface, family) {
	if (!validate_section_name(iface)) return iface;
	if (!family) {
		let families = get_families(iface);
		family = families[0] || 'ipv4';
	}
	family = normalize_family(family) || 'ipv4';
	let v = (family == 'ipv4') ? '4' : '6';
	let alt = sprintf('%s_%s', iface, v);
	let s = ubus_call(sprintf('network.interface.%s', alt), 'status');
	return s ? alt : iface;
}

function get_src_ip(iface, family) {
	if (!validate_section_name(iface)) return '0.0.0.0';
	if (!family) {
		let families = get_families(iface);
		family = families[0] || 'ipv4';
	}
	family = normalize_family(family) || 'ipv4';
	let true_iface = get_true_iface(iface, family);
	let src_ip = '';
	let device;

	if (family == 'ipv4') {
		src_ip = network_get_ipaddr(true_iface);
	} else {
		src_ip = network_get_ipaddr6(true_iface);
	}

	if (!src_ip && family == 'ipv6') {
		let pfx = network_get_prefix6(true_iface);
		if (pfx) {
			let prefix_part = replace(pfx, /:*\/.*$/, '');
			for (let line in cmd_lines('ip -6 address ls')) {
				let m = match(line, /inet6 ([0-9a-fA-F:]+)/);
				if (m && index(m[1], prefix_part) == 0) {
					src_ip = m[1];
					break;
				}
			}
		}
	}

	if (!src_ip) {
		device = network_get_device(true_iface);
		if (device) {
			if (!validate_device_name(device)) {
				warn_invalid('device name', device, sprintf('interface %s', true_iface));
				return (family == 'ipv4') ? '0.0.0.0' : '::';
			}
			let ip_cmd = (family == 'ipv4') ? 'ip -4' : 'ip -6';
			for (let line in cmd_lines(sprintf('%s address ls dev %s', ip_cmd, shell_quote(device)))) {
				let m;
				if (family == 'ipv4')
					m = match(line, /inet ([^ \/]+)/);
				else
					m = match(line, /inet6 ([^ \/]+).* scope/);
				if (m) { src_ip = m[1]; break; }
			}
			if (src_ip)
				LOG('warn', sprintf("guessing src %s addr %s for '%s' dev '%s'", family, src_ip, true_iface, device));
			else
				LOG('warn', sprintf("no src %s addr for '%s' dev '%s'", family, true_iface, device));
		}
	}

	return src_ip || ((family == 'ipv4') ? '0.0.0.0' : '::');
}

// ── Track Status ─────────────────────────────────────────────────────

function get_mwan4track_status(iface, family) {
	if (!validate_section_name(iface)) return 'disabled';
	if (family && !validate_family(family)) return 'disabled';
	let status_iface = family ? sprintf('%s_%s', iface, family) : iface;
	let track_ips = [];
	for (let target in uci_get_list(iface, 'track_ip'))
		if (validate_track_target(target)) push(track_ips, target);
	if (!length(track_ips)) return 'disabled';

	let pid = read_str(sprintf('%s/%s/PID', TRACK_STATUS_DIR, status_iface));
	if (!pid) return 'down';

	let cmdline = read_str(sprintf('/proc/%s/cmdline', pid));
	if (!cmdline || index(cmdline, 'mwan4track') < 0 || index(cmdline, iface) < 0 || (family && index(cmdline, family) < 0))
		return 'down';

	let started = read_str(sprintf('%s/%s/STARTED', TRACK_STATUS_DIR, status_iface));
	switch (started) {
		case '0': return 'paused';
		case '1': return 'active';
		default: return 'down';
	}
}

// ── Tunnel Metadata ──────────────────────────────────────────────────

function metadata_string(value) {
	if (value == null) return null;
	let text = trim('' + value);
	return length(text) ? text : null;
}

function get_interface_section(iface) {
	if (!validate_section_name(iface)) return null;

	let result = null;
	uci_foreach('interface', function(s) {
		if (s['.name'] == iface) {
			result = s;
			return false;
		}
	});

	return result;
}

function get_tunnel_metadata(iface_or_section) {
	_ensure_init();

	let section = null;
	let iface = null;

	if (type(iface_or_section) == 'object') {
		section = iface_or_section;
		iface = section['.name'];
	} else {
		iface = iface_or_section;
		section = get_interface_section(iface);
	}

	if (!section || !validate_section_name(iface)) return null;

	let prevent_raw = section.prevent_recursion;
	let has_prevent = prevent_raw != null;
	let meta = {
		'interface':          iface,
		'type':               metadata_string(section.type),
		'transport_type':     metadata_string(section.transport_type),
		'underlay_strategy':  metadata_string(section.underlay_strategy),
		'endpoint':           metadata_string(section.endpoint || section.remote_endpoint || section.endpoint_host),
		'endpoint_host':      metadata_string(section.endpoint_host || section.endpoint || section.remote_endpoint),
		'endpoint_port':      metadata_string(section.endpoint_port),
		'local_endpoint':     metadata_string(section.local_endpoint),
		'endpoint_fail_mode': metadata_string(section.endpoint_fail_mode),
		'data_fail_mode':     metadata_string(section.data_fail_mode),
		'prevent_recursion':  uci_bool(prevent_raw),
		'configured':         false,
		'underlay_interfaces': [],
	};

	meta.configured = !!(
		meta.type || meta.transport_type || meta.underlay_strategy ||
		meta.endpoint || meta.endpoint_host || meta.endpoint_port || meta.local_endpoint ||
		meta.endpoint_fail_mode || meta.data_fail_mode || has_prevent
	);

	return meta;
}

function strategy_underlay_interfaces(strategy_name, routes, strategies) {
	let result = [];
	if (!strategy_name || !validate_section_name(strategy_name)) return result;
	if (!strategies[strategy_name]) return result;

	for (let route_name in as_list(strategies[strategy_name].use_route)) {
		let iface = routes[route_name]?.interface;
		if (!iface || !validate_section_name(iface)) continue;
		if (index(result, iface) < 0)
			push(result, iface);
	}

	return result;
}

function get_tunnel_context() {
	_ensure_init();

	let routes = uci_section_map('route');
	let strategies = uci_section_map('strategy');
	let tunnels = {};

	uci_foreach('interface', function(s) {
		let meta = get_tunnel_metadata(s);
		if (!meta || !meta.configured) return;

		meta.underlay_interfaces = strategy_underlay_interfaces(meta.underlay_strategy, routes, strategies);
		tunnels[meta.interface] = meta;
	});

	return {
		'tunnels':    tunnels,
		'routes':     routes,
		'strategies': strategies,
	};
}

function tunnel_cycle_signature(cycle) {
	let nodes = [];
	for (let i = 0; i < length(cycle) - 1; i++)
		if (index(nodes, cycle[i]) < 0)
			push(nodes, cycle[i]);
	sort(nodes);
	return join('|', nodes);
}

function tunnel_cycle_walk(current, path, graph, warnings, seen_cycles) {
	for (let next in graph[current] || []) {
		if (next == current) continue;

		let pos = index(path, next);
		if (pos >= 0) {
			let cycle = [];
			for (let i = pos; i < length(path); i++)
				push(cycle, path[i]);
			push(cycle, next);

			let signature = tunnel_cycle_signature(cycle);
			if (!seen_cycles[signature]) {
				seen_cycles[signature] = true;
				push(warnings, {
					'code':      'tunnelUnderlayCycle',
					'interface': cycle[0],
					'path':      cycle,
					'message':   sprintf('Tunnel underlay strategy cycle detected: %s.', join(' -> ', cycle)),
				});
			}
			continue;
		}

		if (graph[next]) {
			let next_path = [];
			for (let hop in path)
				push(next_path, hop);
			push(next_path, next);
			tunnel_cycle_walk(next, next_path, graph, warnings, seen_cycles);
		}
	}
}

function get_tunnel_warnings(context) {
	context = context || get_tunnel_context();

	let tunnels = context.tunnels || {};
	let graph = {};
	let warnings = [];
	let seen_cycles = {};

	for (let iface in keys(tunnels)) {
		let meta = tunnels[iface];
		graph[iface] = meta.underlay_interfaces || [];

		if (index(graph[iface], iface) >= 0)
			push(warnings, {
				'code':              'tunnelUnderlaySelfReference',
				'interface':         iface,
				'underlay_strategy': meta.underlay_strategy,
				'message':           sprintf("Tunnel '%s' underlay strategy '%s' routes back to the same interface.", iface, meta.underlay_strategy),
			});
	}

	for (let iface in keys(tunnels))
		tunnel_cycle_walk(iface, [ iface ], graph, warnings, seen_cycles);

	return warnings;
}

function endpoint_route(endpoint) {
	let family = endpoint_family(endpoint);
	if (!family) return null;
	let ip_cmd = (family == 'ipv4') ? 'ip -4' : 'ip -6';
	let line = trim(cmd_output(sprintf('%s route get %s 2>/dev/null', ip_cmd, shell_quote(endpoint))));
	if (!length(line)) return null;

	let dev = match(line, / dev ([^ ]+)/);
	let via = match(line, / via ([^ ]+)/);
	let src = match(line, / src ([^ ]+)/);
	let table = match(line, / table ([^ ]+)/);
	return {
		'family': family,
		'raw':    line,
		'device': dev ? dev[1] : null,
		'gateway': via ? via[1] : null,
		'source': src ? src[1] : null,
		'table':  table ? table[1] : null,
	};
}

function tunnel_endpoint_diagnostics(context) {
	context = context || get_tunnel_context();
	let tunnels = context.tunnels || {};
	let endpoints = {};
	let warnings = [];

	for (let iface in keys(tunnels)) {
		let meta = tunnels[iface];
		let endpoint = meta.endpoint_host || meta.endpoint;
		let route = endpoint_route(endpoint);
		let device = network_get_device(iface);
		let entry = {
			'interface':      iface,
			'endpoint':       endpoint || null,
			'endpoint_port':  meta.endpoint_port || null,
			'underlay_strategy': meta.underlay_strategy || null,
			'underlay_interfaces': meta.underlay_interfaces || [],
			'route':          route,
		};

		if (!endpoint) {
			push(warnings, {
				'code':      'tunnelEndpointMissing',
				'interface': iface,
				'message':   sprintf("Tunnel '%s' has no endpoint metadata configured.", iface),
			});
		} else if (!endpoint_family(endpoint) && !validate_hostname(endpoint)) {
			push(warnings, {
				'code':      'invalidTunnelEndpoint',
				'interface': iface,
				'endpoint':  endpoint,
				'message':   sprintf("Tunnel '%s' endpoint '%s' is not an IP address or hostname.", iface, endpoint),
			});
		}

		if (!meta.underlay_strategy)
			push(warnings, {
				'code':      'tunnelUnderlayMissing',
				'interface': iface,
				'message':   sprintf("Tunnel '%s' has no underlay_strategy configured.", iface),
			});

		if (route?.device && device && route.device == device)
			push(warnings, {
				'code':      'tunnelEndpointRecursion',
				'interface': iface,
				'endpoint':  endpoint,
				'device':    route.device,
				'message':   sprintf("Tunnel '%s' endpoint route resolves through its own device '%s'.", iface, route.device),
			});

		endpoints[iface] = entry;
	}

	return {
		'interfaces': endpoints,
		'warnings':   warnings,
	};
}

function tunnel_recursion_diagnostics(context) {
	context = context || get_tunnel_context();
	let tunnels = context.tunnels || {};
	let graph = {};

	for (let iface in keys(tunnels))
		graph[iface] = tunnels[iface].underlay_interfaces || [];

	return {
		'graph':    graph,
		'warnings': get_tunnel_warnings(context),
	};
}

function get_tunnel_status() {
	let context = get_tunnel_context();
	return {
		'interfaces': context.tunnels,
		'warnings':   get_tunnel_warnings(context),
	};
}

// ── Interface Table Mapping ──────────────────────────────────────────

function update_iface_to_table() {
	mwan4.iface_tbl = {};
	mwan4.iface_table_tbl = {};
	mwan4.iface_mark_tbl = {};
	let tid = 0;
	uci_foreach('interface', function(s) {
		tid++;
		let iface = s['.name'];
		if (!validate_section_name(iface)) {
			warn_invalid('section name', iface, 'interface table');
			return;
		}
		let id = stable_iface_id(s, tid);
		let table_id = stable_iface_table_id(s, id);
		let mark = stable_iface_mark(s, id);

		mwan4.iface_tbl[iface] = id;
		mwan4.iface_table_tbl[iface] = table_id;
		mwan4.iface_mark_tbl[iface] = mark;
	});
}

function ensure_iface_maps() {
	if (!length(keys(mwan4.iface_tbl))) update_iface_to_table();
}

function get_iface_id(iface) {
	if (!validate_section_name(iface)) return null;
	ensure_iface_maps();
	return mwan4.iface_tbl[iface];
}

function get_iface_table_id(iface) {
	if (!validate_section_name(iface)) return null;
	ensure_iface_maps();
	return mwan4.iface_table_tbl[iface];
}

function get_iface_mark(iface) {
	if (!validate_section_name(iface)) return null;
	ensure_iface_maps();
	return mwan4.iface_mark_tbl[iface];
}

function tunnel_exemption_prefix(endpoint, family) {
	return family == 'ipv6' ? endpoint + '/128' : endpoint + '/32';
}

function tunnel_exemption_command(meta) {
	let endpoint = meta.endpoint_host || meta.endpoint;
	let family = endpoint_family(endpoint);
	if (!family) return null;
	if (!length(meta.underlay_interfaces || [])) return null;

	let underlay = meta.underlay_interfaces[0];
	let device = network_get_device(underlay);
	let table = get_iface_table_id(underlay);
	if (!device || !table || !validate_device_name(device)) return null;

	let current = endpoint_route(endpoint);
	let ip_cmd = family == 'ipv6' ? 'ip -6' : 'ip -4';
	let parts = [ ip_cmd, 'route replace table', table, shell_quote(tunnel_exemption_prefix(endpoint, family)) ];
	if (current?.gateway)
		push(parts, 'via ' + shell_quote(current.gateway));
	push(parts, 'dev ' + shell_quote(device));
	if (current?.source)
		push(parts, 'src ' + shell_quote(current.source));

	return {
		'interface': meta.interface,
		'underlay':  underlay,
		'family':    family,
		'endpoint':  endpoint,
		'command':   join(' ', parts),
	};
}

function apply_tunnel_exemptions(selected_iface) {
	let context = get_tunnel_context();
	let applied = [];
	let errors = [];

	if (selected_iface && !validate_section_name(selected_iface)) {
		push(errors, contract_problem('invalidInterface', selected_iface,
			sprintf("Unknown or unsafe interface '%s'.", selected_iface || '')));
		return { 'ok': false, 'interface': selected_iface || null, 'applied': applied, 'errors': errors };
	}

	if (selected_iface && !context.tunnels[selected_iface]) {
		push(errors, contract_problem('invalidInterface', selected_iface,
			sprintf("Interface '%s' is not configured as a tunnel.", selected_iface)));
		return { 'ok': false, 'interface': selected_iface, 'applied': applied, 'errors': errors };
	}

	for (let iface in keys(context.tunnels || {})) {
		if (selected_iface && iface != selected_iface) continue;
		let cmd = tunnel_exemption_command(context.tunnels[iface]);
		if (!cmd) {
			push(errors, contract_problem('tunnelExemptionUnavailable', iface,
				sprintf("Tunnel '%s' needs an IP endpoint and a routable underlay strategy before mwan4 can install a host-route exemption.", iface)));
			continue;
		}
		if (run(cmd.command) == 0)
			push(applied, cmd);
		else
			push(errors, contract_problem('tunnelExemptionApplyFailed', iface,
				sprintf("Unable to apply endpoint host-route exemption for tunnel '%s'.", iface)));
	}

	return {
		'ok':        length(errors) == 0,
		'interface': selected_iface || null,
		'applied':   applied,
		'errors':    errors,
	};
}

function get_policy_ownership() {
	_ensure_init();
	ensure_iface_maps();

	let interfaces = [];
	let tables = [];
	let marks = [];
	let ids = [];
	let rule_prefs = [];
	let warnings = [];
	let seen_tables = {};
	let seen_marks = {};
	let seen_ids = {};
	let seen_prefs = {};

	function add_unique(list, seen, value) {
		if (value == null || seen[value]) return;
		seen[value] = true;
		push(list, value);
	}

	uci_foreach('interface', function(s) {
		let iface = s['.name'];
		if (!validate_section_name(iface)) return;

		let id = get_iface_id(iface);
		let table_id = get_iface_table_id(iface);
		let mark = get_iface_mark(iface);
		let entry = {
			'interface': iface,
			'id':        id,
			'table_id':  table_id,
			'mark':      mark,
		};
		push(interfaces, entry);

		if (id != null) {
			if (seen_ids[id])
				push(warnings, { 'code': 'duplicateInterfaceId', 'interface': iface, 'id': id });
			add_unique(ids, seen_ids, id);
			add_unique(rule_prefs, seen_prefs, id + 1000);
			add_unique(rule_prefs, seen_prefs, id + 2000);
			add_unique(rule_prefs, seen_prefs, id + 3000);
		}

		if (table_id != null) {
			if (seen_tables[table_id])
				push(warnings, { 'code': 'duplicateTableId', 'interface': iface, 'table_id': table_id });
			add_unique(tables, seen_tables, table_id);
		}

		if (mark != null) {
			if (seen_marks[mark])
				push(warnings, { 'code': 'duplicateMark', 'interface': iface, 'mark': mark });
			add_unique(marks, seen_marks, mark);
		}
	});

	add_unique(rule_prefs, seen_prefs, mm_blackhole + 2000);
	add_unique(rule_prefs, seen_prefs, mm_unreachable + 2000);
	sort(tables, (a, b) => a - b);
	sort(rule_prefs, (a, b) => a - b);

	return {
		'interfaces': interfaces,
		'tables':     tables,
		'marks':      marks,
		'rule_prefs': rule_prefs,
		'warnings':   warnings,
	};
}

function persist_policy_ownership() {
	ensure_dir(STATUS_DIR);
	let ownership = get_policy_ownership();
	writefile(STATUS_DIR + '/mwan4.tables', join(' ', ownership.tables) + '\n');
	writefile(STATUS_DIR + '/mwan4.rule_prefs', join(' ', ownership.rule_prefs) + '\n');
}

function get_installed_policy_ownership() {
	return {
		'tables':     int_list(read_str(STATUS_DIR + '/mwan4.tables')),
		'rule_prefs': int_list(read_str(STATUS_DIR + '/mwan4.rule_prefs')),
	};
}

function update_dev_to_table() {
	mwan4.dev_tbl = { ipv4: {}, ipv6: {} };
	let tid = 0;
	uci_foreach('interface', function(s) {
		tid++;
		if (!validate_section_name(s['.name'])) return;
		if (!uci_bool(s.enabled)) return;
		let table_id = get_iface_table_id(s['.name']);
		if (!table_id) return;
		let device = network_get_device(s['.name']);
		if (!device || !validate_device_name(device)) return;
		for (let family in get_families(s['.name']))
			mwan4.dev_tbl[family][device] = table_id;
	});
}

function route_line_dev(route_line, route_family) {
	let m = match(route_line, /dev ([^ ]+)/);
	if (!m) return null;
	return mwan4.dev_tbl[route_family]?.[m[1]];
}

// ── Route Line Cleaning ──────────────────────────────────────────────

function clean_route_line(line) {
	line = replace(line, /offload/, '');
	line = replace(line, /linkdown /, '');
	line = replace(line, /expires [0-9]+sec/, '');
	line = replace(line, /error [0-9]+/, '');
	if (!mwan4.source_routing)
		line = replace(line, /default(.*) from [^ ]*/, 'default$1');
	return trim(line);
}

function get_routes(family) {
	family = normalize_family(family);
	if (!family) return [];
	let ip_cmd = (family == 'ipv4') ? 'ip -4' : 'ip -6';
	let seen = {};
	let routes = [];

	let all_lines = cmd_lines(sprintf('%s route list table main', ip_cmd));
	let lookups = filter_route_table_lookups(uci_get_list('globals', 'rt_table_lookup'), 'globals');
	for (let tbl_id in lookups)
		push(all_lines, ...cmd_lines(sprintf('%s route list table %s', ip_cmd, tbl_id)));

	for (let line in all_lines) {
		let cleaned = clean_route_line(line);
		if (length(cleaned) && !seen[cleaned]) {
			seen[cleaned] = true;
			push(routes, cleaned);
		}
	}
	return routes;
}

// ── Hotplug State ────────────────────────────────────────────────────

function set_iface_hotplug_state(iface, state) {
	if (!validate_section_name(iface)) {
		warn_invalid('section name', iface, 'hotplug state');
		return;
	}
	ensure_dir(STATUS_DIR + '/iface_state');
	writefile(sprintf('%s/iface_state/%s', STATUS_DIR, iface), state);
}

function get_iface_hotplug_state(iface) {
	if (!validate_section_name(iface)) return 'offline';
	return read_str(sprintf('%s/iface_state/%s', STATUS_DIR, iface)) || 'offline';
}

function init_iface_hotplug_states() {
	uci_foreach('interface', function(s) {
		let iface = s['.name'];
		if (!validate_section_name(iface)) {
			warn_invalid('section name', iface, 'hotplug state init');
			return;
		}

		let state = 'offline';
		if (uci_bool(s.enabled)) {
			let tracked = false;
			for (let family in get_families(iface)) {
				let status_iface = sprintf('%s_%s', iface, family);
				let status = read_str(sprintf('%s/%s/STATUS', TRACK_STATUS_DIR, status_iface));
				if (status == 'online') {
					state = 'online';
					tracked = true;
					break;
				}
				if (status == 'offline' || status == 'disabled' || status == 'disconnecting')
					tracked = true;
			}

			if (!tracked) {
				let current = read_str(sprintf('%s/iface_state/%s', STATUS_DIR, iface));
				if (current == 'online' || current == 'offline') {
					state = current;
				} else if ((s.initial_state || 'online') != 'offline') {
					let true_iface = get_true_iface(iface);
					let status = ubus_call(sprintf('network.interface.%s', true_iface), 'status');
					let device = status?.l3_device || status?.device || '';
					if (status?.up && validate_device_name(device))
						state = 'online';
				}
			}
		}

		set_iface_hotplug_state(iface, state);
	});
}

// ── Initialization ───────────────────────────────────────────────────

function init(name) {
	if (name) mwan4.scriptname = name;

	ensure_dir(STATUS_DIR + '/iface_state');
	ensure_dir(STATUS_NFT_LOG_DIR);
	ensure_dir(TRACK_STATUS_DIR);

	let saved_mask = read_str(STATUS_DIR + '/mwan4.mmx_mask');
	if (saved_mask) {
		mwan4.mmx_mask = saved_mask;
		mwan4.iface_max = read_int(STATUS_DIR + '/mwan4.iface_max');
	}

	_loaded = false;
	_ensure_init();

	if (!saved_mask) {
		writefile(STATUS_DIR + '/mwan4.mmx_mask', mwan4.mmx_mask);
		LOG('debug', 'Using firewall mask', mwan4.mmx_mask);
		writefile(STATUS_DIR + '/mwan4.iface_max', '' + mwan4.iface_max);
		LOG('debug', 'Max interface count is', '' + mwan4.iface_max);
	}
}

// ── General IP Rules ─────────────────────────────────────────────────

function set_general_rules() {
	for (let ip_ver in ['ip -4', 'ip -6']) {
		if (ip_ver == 'ip -6' && mwan4.no_ipv6 != 0) continue;

		let rule_no = mm_blackhole + 2000;
		let existing = cmd_output(sprintf('%s rule list', ip_ver));
		if (index(existing, rule_no + ':') < 0)
			run(sprintf('%s rule add pref %d fwmark %s/%s blackhole', ip_ver, rule_no, mwan4.mmx_blackhole, mwan4.mmx_mask));

		rule_no = mm_unreachable + 2000;
		if (index(existing, rule_no + ':') < 0)
			run(sprintf('%s rule add pref %d fwmark %s/%s unreachable', ip_ver, rule_no, mwan4.mmx_unreachable, mwan4.mmx_mask));
	}
}

// ── nftables Base ────────────────────────────────────────────────────

function _nft_set_check_rules(family, zero_check) { // ucode-lsp disable
	let flag = (family == 'ipv4') ? NFT_IPV4 : NFT_IPV6;
	let mark_expr = zero_check
		? sprintf('meta mark & %s == 0', mwan4.mmx_mask)
		: sprintf('meta mark & %s != %s', mwan4.mmx_mask, mwan4.mmx_default);
	let mark_set = sprintf('meta mark set meta mark & %s | %s', mwan4.mmx_mask_inv, mwan4.mmx_default);

	let rules = [];
	for (let settype in ['custom', 'connected', 'dynamic'])
		push(rules, sprintf('\t\t%s %s daddr @%s_%s_%s %s',
			mark_expr, flag, NFT_PREFIX, settype, family, mark_set));
	return rules;
}

function _nft_conntrack_save_rules() {
	let marks = [], seen = {}, ordinal = 0;
	uci_foreach('interface', function(section) {
		ordinal++;
		let id   = stable_iface_id(section, ordinal);
		let mark = stable_iface_mark(section, id);
		if (!seen[mark]) {
			seen[mark] = true;
			push(marks, mark);
		}
	});
	for (let mark in [ mwan4.mmx_default, mwan4.mmx_blackhole, mwan4.mmx_unreachable ]) {
		if (!seen[mark]) {
			seen[mark] = true;
			push(marks, mark);
		}
	}

	let rules = [ sprintf('\t\tmeta mark & %s == 0 ct mark set ct mark & %s', mwan4.mmx_mask, mwan4.mmx_mask_inv) ];
	for (let mark in marks)
		push(rules, sprintf('\t\tmeta mark & %s == %s ct mark set ct mark & %s | %s',
			mwan4.mmx_mask, mark, mwan4.mmx_mask_inv, mark));
	return rules;
}

function set_general_nftables() {
	let L = [];

	push(L, sprintf('table inet %s {', NFT_TABLE));

	// Sets
	for (let fam in ['ipv4', 'ipv6']) {
		if (fam == 'ipv6' && mwan4.no_ipv6 != 0) continue;
		let addr_type = (fam == 'ipv4') ? 'ipv4_addr' : 'ipv6_addr';
		for (let settype in ['connected', 'custom', 'dynamic']) {
			push(L, '',
				sprintf('\tset %s_%s_%s {', NFT_PREFIX, settype, fam),
				sprintf('\t\ttype %s', addr_type),
				'\t\tflags interval',
				'\t\tauto-merge',
				'\t}'
			);
		}
	}

	// Empty dispatch chains
	push(L, '',
		sprintf('\tchain %s_ifaces_in {', NFT_PREFIX),
		'\t}'
	);

	// Per-family rules chains (populated later by set_user_rules)
	for (let suffix in ['', '_out'])
		for (let fam in ['ipv4', 'ipv6'])
			if (fam == 'ipv4' || mwan4.no_ipv6 == 0)
				push(L, '', sprintf('\tchain %s_rules%s_%s {', NFT_PREFIX, suffix, fam), '\t}');

	// Rules dispatch chains: jump to per-family rules chains. Router-originated traffic
	// only sees the rules flagged `local`.
	for (let suffix in ['', '_out']) {
		push(L, '', sprintf('\tchain %s_rules%s {', NFT_PREFIX, suffix),
			sprintf('\t\tmeta nfproto ipv4 jump %s_rules%s_ipv4', NFT_PREFIX, suffix));
		if (mwan4.no_ipv6 == 0)
			push(L, sprintf('\t\tmeta nfproto ipv6 jump %s_rules%s_ipv6', NFT_PREFIX, suffix));
		push(L, '\t}');
	}

	// RA exemption block (shared between prerouting and output)
	let ra_exempt = [
		'\t\tip6 nexthdr icmpv6 icmpv6 type {',
		'\t\t\tnd-router-solicit,',
		'\t\t\tnd-router-advert,',
		'\t\t\tnd-neighbor-solicit,',
		'\t\t\tnd-neighbor-advert,',
		'\t\t\tnd-redirect',
		'\t\t} return',
	];

	// Build prerouting and output chains (same logic, different hook)
	for (let chain_info in [
		[sprintf('%s_prerouting', NFT_PREFIX), 'type filter hook prerouting priority mangle; policy accept;', 'rules'],
		[sprintf('%s_output', NFT_PREFIX), 'type route hook output priority mangle; policy accept;', 'rules_out'],
	]) {
		push(L, '', sprintf('\tchain %s {', chain_info[0]),
			sprintf('\t\t%s', chain_info[1])
		);
		push(L, ...ra_exempt);

		// Restore mark from conntrack
		// Use single-register form (ct mark & constant) for kernel compatibility;
		// meta mark is 0 at this point so the masked-OR form is equivalent.
		push(L, sprintf('\t\tct mark & %s != 0 meta mark set ct mark & %s', mwan4.mmx_mask, mwan4.mmx_mask));
		// Interface input
		push(L, sprintf('\t\tmeta mark & %s == 0 jump %s_ifaces_in', mwan4.mmx_mask, NFT_PREFIX));
		// Pre-rule set checks (mark == 0)
		push(L, ..._nft_set_check_rules('ipv4', true));
		if (mwan4.no_ipv6 == 0)
			push(L, ..._nft_set_check_rules('ipv6', true));
		// User rules
		push(L, sprintf('\t\tmeta mark & %s == 0 jump %s_%s', mwan4.mmx_mask, NFT_PREFIX, chain_info[2]));
		// Save only mwan4-owned bits. Constant mark rules avoid cross-register
		// bitwise expressions rejected by older kernels.
		push(L, ..._nft_conntrack_save_rules());
		// Post-rule set checks (mark != default)
		push(L, ..._nft_set_check_rules('ipv4', false));
		if (mwan4.no_ipv6 == 0)
			push(L, ..._nft_set_check_rules('ipv6', false));

		push(L, '\t}');
	}

	push(L, '}');

	nft_file('add', 'dynamic', ...L);
}

// ── nftables Sets ────────────────────────────────────────────────────

function set_custom_nftset() {
	let lines = [
		sprintf('table inet %s {', NFT_TABLE),
		sprintf('\tset %s_custom_ipv4 {', NFT_PREFIX),
		'\t\ttype ipv4_addr',
		'\t\tflags interval',
		'\t\tauto-merge',
		'\t\telements = {',
	];

	let has_v4 = false;
	let lookups = filter_route_table_lookups(uci_get_list('globals', 'rt_table_lookup'), 'globals');
	for (let tbl_id in lookups) {
		for (let line in cmd_lines(sprintf('ip -4 route list table %s', tbl_id))) {
			let addr = split(line, ' ')[0];
			if (match(addr, IPv4_RE)) {
				push(lines, sprintf('\t\t\t%s,', addr));
				has_v4 = true;
			}
		}
	}
	if (!has_v4) push(lines, '\t\t\t127.0.0.1,');
	push(lines, '\t\t}', '\t}');

	if (mwan4.no_ipv6 == 0) {
		push(lines,
			'',
			sprintf('\tset %s_custom_ipv6 {', NFT_PREFIX),
			'\t\ttype ipv6_addr',
			'\t\tflags interval',
			'\t\tauto-merge',
			'\t\telements = {'
		);
		let has_v6 = false;
		for (let tbl_id in lookups) {
			for (let line in cmd_lines(sprintf('ip -6 route list table %s', tbl_id))) {
				let addr = split(line, ' ')[0];
				if (match(addr, IPv6_RE)) {
					push(lines, sprintf('\t\t\t%s,', addr));
					has_v6 = true;
				}
			}
		}
		if (!has_v6) push(lines, '\t\t\t::1,');
		push(lines, '\t\t}', '\t}');
	}

	push(lines, '}');
	let tmpfile = NFT_TEMP + '.custom_sets';
	writefile(tmpfile, join('\n', lines) + '\n');
	nft_file('apply', tmpfile);
	unlink(tmpfile);
	nft_file('add', 'rules', ...lines);
}

function set_connected_ipv4() {
	let cidr_list = [], host_list = [];

	let all_lines = cmd_lines('ip -4 route');
	push(all_lines, ...cmd_lines('ip -4 route list table 0'));

	for (let line in all_lines) {
		let addr;
		// table 0 uses column 2
		if (index(line, 'table ') >= 0)
			addr = split(line, ' ')[1];
		else
			addr = split(line, ' ')[0];
		if (!match(addr, IPv4_RE)) continue;
		if (index(addr, '/') >= 0)
			push(cidr_list, addr);
		else
			push(host_list, addr);
	}

	let lines = [
		sprintf('table inet %s {', NFT_TABLE),
		sprintf('\tset %s_connected_ipv4 {', NFT_PREFIX),
		'\t\ttype ipv4_addr',
		'\t\tflags interval',
		'\t\tauto-merge',
		'\t\telements = {',
	];
	for (let addr in cidr_list) push(lines, sprintf('\t\t\t%s,', addr));
	for (let addr in host_list) push(lines, sprintf('\t\t\t%s,', addr));
	push(lines, '\t\t\t224.0.0.0/3');
	push(lines, '\t\t}', '\t}', '}');

	let tmpfile = NFT_TEMP + '.connected_v4';
	writefile(tmpfile, join('\n', lines) + '\n');
	nft_file('apply', tmpfile);
	unlink(tmpfile);
	nft_file('add', 'rules', ...lines);
}

function set_connected_ipv6() {
	if (mwan4.no_ipv6 != 0) return;

	let lines = [
		sprintf('table inet %s {', NFT_TABLE),
		sprintf('\tset %s_connected_ipv6 {', NFT_PREFIX),
		'\t\ttype ipv6_addr',
		'\t\tflags interval',
		'\t\tauto-merge',
		'\t\telements = {',
	];

	let has = false;
	for (let line in cmd_lines('ip -6 route')) {
		let addr = split(line, ' ')[0];
		if (match(addr, IPv6_RE)) {
			push(lines, sprintf('\t\t\t%s,', addr));
			has = true;
		}
	}
	if (!has) push(lines, '\t\t\t::1,');
	push(lines, '\t\t}', '\t}', '}');

	let tmpfile = NFT_TEMP + '.connected_v6';
	writefile(tmpfile, join('\n', lines) + '\n');
	nft_file('apply', tmpfile);
	unlink(tmpfile);
	nft_file('add', 'rules', ...lines);
}

function set_dynamic_nftset() {
	let lines = [
		sprintf('table inet %s {', NFT_TABLE),
		sprintf('\tset %s_dynamic_ipv4 {', NFT_PREFIX),
		'\t\ttype ipv4_addr',
		'\t\tflags interval',
		'\t\tauto-merge',
		'\t}',
	];
	if (mwan4.no_ipv6 == 0) {
		push(lines, '',
			sprintf('\tset %s_dynamic_ipv6 {', NFT_PREFIX),
			'\t\ttype ipv6_addr',
			'\t\tflags interval',
			'\t\tauto-merge',
			'\t}'
		);
	}
	push(lines, '}');

	let tmpfile = NFT_TEMP + '.dynamic_init';
	writefile(tmpfile, join('\n', lines) + '\n');
	nft_file('apply', tmpfile);
	unlink(tmpfile);
	nft_file('add', 'rules', ...lines);
}

// ── nftables Interfaces ──────────────────────────────────────────────

function rebuild_iface_nftfile() {
	let L            = [sprintf('table inet %s {', NFT_TABLE)];
	let chain_lines  = [];
	let jump_rules   = [];
	let counter_defs = [];
	let counter_seen = {};

	uci_foreach('interface', function(s) {
		let iface = s['.name'];
		if (!validate_nft_section_name(iface)) {
			warn_invalid('nft section name', iface, 'interface nft generation');
			return;
		}
		if (!uci_bool(s.enabled)) return;
		let device = network_get_device(iface);
		if (!device) return;
		if (!validate_device_name(device)) {
			warn_invalid('device name', device, sprintf('interface %s', iface));
			return;
		}

		for (let family in get_families(iface)) {
			if (family == 'ipv6' && mwan4.no_ipv6 != 0) continue;
			let nftflag = (family == 'ipv4') ? NFT_IPV4 : NFT_IPV6;
			let id = get_iface_id(iface);
			if (!id) return;
			let chain_name = sprintf('%s_iface_in_%s_%s', NFT_PREFIX, iface, family);
			let mark = get_iface_mark(iface);
			if (!mark) return;

			push(chain_lines, '', sprintf('\tchain %s {', chain_name));
			for (let settype in ['custom', 'connected', 'dynamic']) {
				let counter = nft_add_counter(counter_defs, counter_seen, 'iface', iface, family, settype, 'default');
				push(chain_lines, sprintf('\t\tiifname "%s" %s saddr @%s_%s_%s meta mark & %s == 0 %s meta mark set %s comment "default"',
					device, nftflag, NFT_PREFIX, settype, family, mwan4.mmx_mask, nft_counter_use(counter), mwan4.mmx_default));
			}
			let counter = nft_add_counter(counter_defs, counter_seen, 'iface', iface, family);
			push(chain_lines, sprintf('\t\tiifname "%s" meta mark & %s == 0 %s meta mark set %s comment "%s"',
				device, mwan4.mmx_mask, nft_counter_use(counter), mark, iface));
			push(chain_lines, '\t}');

			let nfproto = (family == 'ipv4') ? 'ipv4' : 'ipv6';
			push(jump_rules, sprintf('\t\tmeta mark & %s == 0 meta nfproto %s jump %s',
				mwan4.mmx_mask, nfproto, chain_name));
		}
	});

	push(chain_lines, '', sprintf('\tchain %s_ifaces_in {', NFT_PREFIX));
	push(chain_lines, ...jump_rules);
	push(chain_lines, '\t}');

	push(L, ...counter_defs, ...chain_lines);
	push(L, '}');

	nft_file('add', 'dynamic', ...L);
}

// ── nftables Strategies ──────────────────────────────────────────────

function _create_strategy_chain(strategy_name, accumulator, counter_defs, counter_seen) { // ucode-lsp disable
	let last_resort = uci_get(strategy_name, 'last_resort') || 'unreachable';
	let last_resort_mark;
	if (!validate_nft_section_name(strategy_name)) {
		warn_invalid('nft section name', strategy_name, 'strategy nft generation');
		return;
	}

	if (length(strategy_name) > 15) {
		push(mwan4.warnings, { code: 'warningStrategyNameTooLong', info: strategy_name });
		LOG('warn', sprintf('Strategy %s exceeds 15 chars, skipping', strategy_name));
		return;
	}

	switch (last_resort) {
		case 'blackhole':   last_resort_mark = mwan4.mmx_blackhole; break;
		case 'default':     last_resort_mark = mwan4.mmx_default; break;
		case 'unreachable': last_resort_mark = mwan4.mmx_unreachable; break;
		default:
			warn_invalid('last_resort', last_resort, sprintf('strategy %s', strategy_name));
			last_resort = 'unreachable';
			last_resort_mark = mwan4.mmx_unreachable;
			break;
	}

	// Collect route info per family
	let route_names = uci_get_list(strategy_name, 'use_route');
	let family_routes = { ipv4: [], ipv6: [] };

	for (let route_name in route_names) {
		if (!validate_section_name(route_name)) {
			warn_invalid('section name', route_name, sprintf('strategy %s', strategy_name));
			continue;
		}
		let iface = uci_get(route_name, 'interface');
		let metric = int(uci_get(route_name, 'metric') || '1');
		let weight = int(uci_get(route_name, 'weight') || '1');
		if (!iface) continue;
		if (!validate_nft_section_name(iface)) {
			warn_invalid('nft section name', iface, sprintf('route %s', route_name));
			continue;
		}
		if (metric < 1 || weight < 1) {
			warn_invalid('route metric/weight', sprintf('%d/%d', metric, weight), route_name);
			continue;
		}
		if (metric > DEFAULT_LOWEST_METRIC) {
			LOG('warn', sprintf('Route %s metric >%d, skipping', route_name, DEFAULT_LOWEST_METRIC));
			continue;
		}

		let mark = get_iface_mark(iface);
		if (!mark) continue;

		let device = network_get_device(iface);
		if (device && !validate_device_name(device)) {
			warn_invalid('device name', device, sprintf('interface %s', iface));
			device = null;
		}
		let is_online = (get_iface_hotplug_state(iface) == 'online');

		for (let family in get_families(iface)) {
			if (family == 'ipv6' && mwan4.no_ipv6 != 0) continue;
			push(family_routes[family], { iface, metric, weight, mark, device, is_online });
		}
	}

	// Build nft chain lines
	let L = [];

	for (let family in ['ipv4', 'ipv6']) {
		if (family == 'ipv6' && mwan4.no_ipv6 != 0) continue;

		push(L, sprintf('\tchain %s_strategy_%s_%s {', NFT_PREFIX, strategy_name, family));

		// Find routes at lowest metric that are online
		let routes = family_routes[family];
		let online = filter(routes, r => r.is_online);

		if (length(online)) {
			// Sort by metric, pick lowest
			sort(online, (a, b) => a.metric - b.metric);
			let lowest = online[0].metric;
			let active = filter(online, r => r.metric == lowest);
			let total_weight = 0;
			for (let r in active) total_weight += r.weight;

			// Generate load-balancing rules with correct probability
			let remaining = total_weight;
			for (let i = 0; i < length(active); i++) {
				let r = active[i];
				let counter = nft_add_counter(counter_defs, counter_seen, 'strategy', strategy_name, family, r.iface);
				if (i == length(active) - 1) {
					// Last route: catch-all
					push(L, sprintf('\t\tmeta mark & %s == 0 %s meta mark set %s comment "%s %d %d"',
						mwan4.mmx_mask, nft_counter_use(counter), r.mark, r.iface, r.weight, total_weight));
				} else {
					// Probabilistic: weight/remaining chance
					push(L, sprintf('\t\tmeta mark & %s == 0 numgen random mod %d < %d %s meta mark set %s comment "%s %d %d"',
						mwan4.mmx_mask, remaining, r.weight, nft_counter_use(counter), r.mark, r.iface, r.weight, total_weight));
					remaining -= r.weight;
				}
			}
		} else {
			// All offline: add device-based defaults for any with devices
			let offline_with_dev = filter(routes, r => !r.is_online && r.device);
			for (let r in offline_with_dev) {
				let counter = nft_add_counter(counter_defs, counter_seen, 'strategy', strategy_name, family, 'out', r.iface);
				push(L, sprintf('\t\toifname "%s" meta mark & %s == 0 %s meta mark set %s comment "out %s %s"',
					r.device, mwan4.mmx_mask, nft_counter_use(counter), mwan4.mmx_default, r.iface, r.device));
			}
		}

		// Last resort fallback (always last in chain)
		let counter = nft_add_counter(counter_defs, counter_seen, 'strategy', strategy_name, family, last_resort);
		push(L, sprintf('\t\tmeta mark & %s == 0 %s meta mark set %s comment "%s"',
			mwan4.mmx_mask, nft_counter_use(counter), last_resort_mark, last_resort));
		push(L, '\t}');
	}

	push(accumulator, ...L);
	return true;
}

function set_strategies_nftables() {
	let all_lines    = [];
	let counter_defs = [];
	let counter_seen = {};
	uci_foreach('strategy', function(s) {
		_create_strategy_chain(s['.name'], all_lines, counter_defs, counter_seen);
	});

	if (!length(all_lines)) return;

	let L = [sprintf('table inet %s {', NFT_TABLE)];
	push(L, ...counter_defs);
	push(L, ...all_lines);
	push(L, '}');

	nft_file('add', 'dynamic', ...L);
}

// ── nftables User Rules ──────────────────────────────────────────────

function _collect_sticky_ifaces(rule_name, family, strategy_name) { // ucode-lsp disable
	let route_names = uci_get_list(strategy_name, 'use_route');
	let sticky_ifaces = [];

	for (let route_name in route_names) {
		if (!validate_section_name(route_name)) continue;
		let iface = uci_get(route_name, 'interface');
		if (!iface) continue;
		if (!validate_nft_section_name(iface)) continue;
		if (!uci_bool(uci_get(iface, 'enabled'))) continue;

		let families = get_families(iface);
		let has_family = false;
		for (let f in families)
			if (f == family) { has_family = true; break; }
		if (!has_family) continue;

		let mark = get_iface_mark(iface);
		if (!mark) continue;
		push(sticky_ifaces, { iface, mark });
	}

	return sticky_ifaces;
}

function rule_families(s) {
	let families = as_list(s.family);
	if (!length(families)) return mwan4.no_ipv6 == 0 ? ['ipv4', 'ipv6'] : ['ipv4'];
	return filter_valid_families(families, sprintf('rule %s', s['.name']));
}

function rule_src_device(s) {
	if (!s.src_iface) return '';
	let rule = s['.name'];
	if (!validate_section_name(s.src_iface)) {
		warn_invalid('section name', s.src_iface, sprintf('rule %s src_iface', rule));
		return null;
	}
	let device = network_get_device(s.src_iface);
	if (!device) {
		LOG('notice', sprintf('could not find device for src_iface %s in rule %s', s.src_iface, rule));
		return null;
	}
	if (!validate_device_name(device)) {
		warn_invalid('device name', device, sprintf('rule %s src_iface', rule));
		return null;
	}
	return device;
}

// Ports only exist for tcp/udp; returns null when a port list is invalid.
function rule_ports(s, proto) {
	if (proto != 'tcp' && proto != 'udp') return { src: '', dest: '' };
	let ports = { src: normalize_ports(s.src_port), dest: normalize_ports(s.dest_port) };
	if (ports.src == null) warn_invalid('source port', s.src_port, sprintf('rule %s', s['.name']));
	if (ports.dest == null) warn_invalid('destination port', s.dest_port, sprintf('rule %s', s['.name']));
	return (ports.src == null || ports.dest == null) ? null : ports;
}

function rule_port_match(proto, ports) {
	if (ports.src && ports.dest)
		return [sprintf('%s sport { %s } %s dport { %s }', proto, ports.src, proto, ports.dest)];
	if (ports.src) return [sprintf('%s sport { %s }', proto, ports.src)];
	if (ports.dest) return [sprintf('%s dport { %s }', proto, ports.dest)];
	return [];
}

function rule_ipset_name(s, family) {
	if (!s.ipset) return '';
	return (family == 'ipv4' || length(rule_families(s)) == 1) ? s.ipset : s.ipset + '_ipv6';
}

function rule_domain_set(rule, family) {
	return sprintf('%s_dom_%s_%s', NFT_PREFIX, rule, family);
}

function rule_mark_action(use_strategy, family) {
	switch (use_strategy) {
		case 'default':     return { action: sprintf('meta mark set %s', mwan4.mmx_default) };
		case 'unreachable': return { action: sprintf('meta mark set %s', mwan4.mmx_unreachable) };
		case 'blackhole':   return { action: sprintf('meta mark set %s', mwan4.mmx_blackhole) };
	}
	return { action: sprintf('jump %s_strategy_%s_%s', NFT_PREFIX, use_strategy, family), jump: true };
}

function _build_user_rule(s, family_flag) { // ucode-lsp disable
	if (!rule_enabled(s)) return null;
	if (family_flag == 'ipv6' && mwan4.no_ipv6 != 0) return null;

	let rule = s['.name'];
	if (!validate_nft_section_name(rule)) {
		warn_invalid('nft section name', rule, 'rule nft generation');
		return null;
	}
	if (length(rule) > 15) {
		push(mwan4.warnings, { code: 'warningRuleNameTooLong', info: rule });
		LOG('warn', sprintf('Rule %s exceeds 15 chars, skipping', rule));
		return null;
	}

	let sticky = int(s.sticky || '0');
	let timeout = int(s.timeout || '600');
	let proto = normalize_protocol(s.proto || 'all');
	let use_strategy = s.use_strategy || '';
	let loglevel = normalize_loglevel(uci_get('globals', 'loglevel') || 'notice') || 'notice';

	if (!proto) {
		warn_invalid('protocol', s.proto, sprintf('rule %s', rule));
		return null;
	}
	if (timeout < 1) timeout = 600;
	if (sticky < 0) sticky = 0;

	if (index(rule_families(s), family_flag) < 0) return null;

	let src_ip = rule_family_values(s, 'src_ip', family_flag);
	let dest_ip = rule_family_values(s, 'dest_ip', family_flag);
	let src_mac = rule_valid_values(s, 'src_mac', validate_mac, 'source mac');
	let domains = rule_valid_values(s, 'domain', validate_hostname, 'domain');
	if (src_ip == null || dest_ip == null || src_mac == null || domains == null) return null;

	if (s.dscp != null && !validate_dscp(s.dscp)) {
		warn_invalid('dscp', s.dscp, sprintf('rule %s', rule));
		return null;
	}

	let src_dev = rule_src_device(s);
	if (src_dev == null) return null;

	let ports = rule_ports(s, proto);
	if (!ports) return null;

	if (!use_strategy) return null;
	if (s.ipset && !validate_nft_identifier(s.ipset)) {
		warn_invalid('nft identifier', s.ipset, sprintf('rule %s ipset', rule));
		return null;
	}
	if (use_strategy != 'default' && use_strategy != 'unreachable' && use_strategy != 'blackhole' && !validate_nft_section_name(use_strategy)) {
		warn_invalid('strategy name', use_strategy, sprintf('rule %s', rule));
		return null;
	}

	let nftflag = (family_flag == 'ipv4') ? NFT_IPV4 : NFT_IPV6;
	let domain_set = length(domains) ? rule_domain_set(rule, family_flag) : '';
	let ipset = rule_ipset_name(s, family_flag);

	let parts = [];
	if (proto != 'all') push(parts, sprintf('meta l4proto %s', proto));
	if (length(src_ip)) push(parts, sprintf('%s saddr %s', nftflag, nft_value_set(src_ip)));
	if (length(src_mac)) push(parts, sprintf('ether saddr %s', nft_value_set(src_mac)));
	if (src_dev) push(parts, sprintf('iifname "%s"', src_dev));
	if (s.dscp != null) push(parts, sprintf('%s dscp %d', nftflag, s.dscp));
	if (length(dest_ip)) push(parts, sprintf('%s daddr %s', nftflag, nft_value_set(dest_ip)));
	if (domain_set) push(parts, sprintf('%s daddr @%s', nftflag, domain_set));
	if (ipset) push(parts, sprintf('%s daddr @%s', nftflag, ipset));
	push(parts, ...rule_port_match(proto, ports));

	let mark = rule_mark_action(use_strategy, family_flag);

	return {
		rule, family_flag, match_str: join(' ', parts), mark_action: mark.action,
		rule_id: DEFAULT_RULES[rule] ? 0 : valid_rule_id(s.rule_id),
		is_strategy_jump: !!mark.jump, sticky, timeout, use_strategy, ipset,
		domains: map(domains, d => lc(d)), domain_set,
		local: DEFAULT_RULES[rule] || uci_bool(s.local),
		rule_logging: int(s.logging || '0'),
		global_logging: int(uci_get('globals', 'logging') || '0'),
		loglevel,
	};
}

// Built rules per family, in priority order.
function collect_user_rules() {
	let rule_data = { ipv4: [], ipv6: [] };

	for (let s in ordered_rules()) {
		for (let fam in ['ipv4', 'ipv6']) {
			let rd = _build_user_rule(s, fam);
			if (!rd) continue;

			if (rd.is_strategy_jump && rd.sticky)
				rd.sticky_ifaces = _collect_sticky_ifaces(rd.rule, fam, rd.use_strategy);
			rd.has_sticky = length(rd.sticky_ifaces) > 0;
			push(rule_data[fam], rd);
		}
	}

	return rule_data;
}

function set_defs(names, type) {
	let lines = [];
	for (let name in names)
		push(lines, sprintf('\tset %s {', name), sprintf('\t\ttype %s', type), '\t\tflags interval', '\t\tauto-merge', '\t}');
	return lines;
}

// Sets referenced by rules: ipset option and dnsmasq-filled domain sets, typed per family.
function rule_set_defs(rule_data) {
	let lines = [];
	for (let fam in ['ipv4', 'ipv6']) {
		let rules = rule_data[fam];
		let names = uniq(filter([...map(rules, rd => rd.ipset), ...map(rules, rd => rd.domain_set)], v => v));
		push(lines, ...set_defs(names, fam == 'ipv4' ? 'ipv4_addr' : 'ipv6_addr'));
	}
	return lines;
}

function sticky_map_defs(rule_name, timeout) {
	let lines = [];
	for (let fam in ['ipv4', 'ipv6']) {
		if (fam == 'ipv6' && mwan4.no_ipv6 != 0) continue;
		push(lines,
			sprintf('\tmap %s_rule_%s_%s {', NFT_PREFIX, fam, rule_name),
			sprintf('\t\ttypeof %s saddr : meta mark', fam == 'ipv4' ? 'ip' : 'ip6'),
			'\t\tflags timeout',
			sprintf('\t\ttimeout %ds', timeout),
			'\t}'
		);
	}
	return lines;
}

function sticky_chain_lines(rd, fam) {
	let saddr = (fam == 'ipv4') ? 'ip saddr' : 'ip6 saddr';
	let map_name = sprintf('%s_rule_%s_%s', NFT_PREFIX, fam, rd.rule);
	let mask = mwan4.mmx_mask;
	return [
		sprintf('\tchain %s_rule_%s_%s {', NFT_PREFIX, rd.rule, fam),
		// Restore the mark from the previous session, else let the strategy assign one, then refresh the map.
		sprintf('\t\tmeta mark & %s == 0 meta mark set %s map @%s', mask, saddr, map_name),
		sprintf('\t\tmeta mark & %s == 0 jump %s_strategy_%s_%s', mask, NFT_PREFIX, rd.use_strategy, fam),
		sprintf('\t\tmeta mark & %s != 0 meta mark & %s != %s meta mark & %s != %s meta mark & %s != %s update @%s { %s : meta mark }',
			mask, mask, mwan4.mmx_default, mask, mwan4.mmx_blackhole, mask, mwan4.mmx_unreachable, map_name, saddr),
		'\t}',
	];
}

// Record the matching rule in the conntrack mark with constant same-register ops,
// leaving the WAN bits and every other owner's bits untouched. Id 0 clears the rule bits.
function rule_ct_mark_action(rule_id) {
	let bits = rule_id ? ' | ' + id2mask(rule_id, mwan4.rule_mask_n) : '';
	return sprintf('ct mark set ct mark & %s%s', mwan4.rule_mask_inv, bits);
}

function rule_chain_lines(chain, rules) {
	let lines = [sprintf('\tchain %s {', chain)];
	for (let rd in rules) {
		let prefix = sprintf('%s meta mark & %s == 0', rd.match_str, mwan4.mmx_mask);

		if (rd.global_logging && rd.rule_logging)
			push(lines, sprintf('\t\t%s log prefix "MWAN4(%s) " comment "%s"', prefix, rd.rule, rd.rule));

		push(lines, sprintf('\t\t%s ct state new %s', prefix, nft_counter_use(rd.conn_counter)));
		if (mwan4.rule_mask_n)
			push(lines, sprintf('\t\t%s %s', prefix, rule_ct_mark_action(rd.rule_id)));

		let action = rd.has_sticky ? sprintf('jump %s_rule_%s_%s', NFT_PREFIX, rd.rule, rd.family_flag) : rd.mark_action;
		push(lines, sprintf('\t\t%s %s %s comment "%s"', prefix, nft_counter_use(rd.counter), action, rd.rule));
	}
	push(lines, '\t}');
	return lines;
}

function set_user_rules(rule_data) {
	rule_data ??= collect_user_rules();

	let L = [sprintf('table inet %s {', NFT_TABLE)];
	push(L, ...rule_set_defs(rule_data));

	let sticky_timeouts = {};
	for (let fam in ['ipv4', 'ipv6'])
		for (let rd in rule_data[fam])
			if (rd.has_sticky) sticky_timeouts[rd.rule] = rd.timeout;
	for (let rule_name in keys(sticky_timeouts))
		push(L, ...sticky_map_defs(rule_name, sticky_timeouts[rule_name]));

	let counter_defs = [];
	let counter_seen = {};
	for (let fam in ['ipv4', 'ipv6'])
		for (let rd in rule_data[fam]) {
			rd.counter = nft_add_counter(counter_defs, counter_seen, 'rule', rd.rule, fam);
			rd.conn_counter = nft_add_counter(counter_defs, counter_seen, 'conn', rd.rule, fam);
		}
	push(L, ...counter_defs);

	for (let fam in ['ipv4', 'ipv6'])
		for (let rd in filter(rule_data[fam], rd => rd.has_sticky))
			push(L, ...sticky_chain_lines(rd, fam));

	for (let fam in ['ipv4', 'ipv6']) {
		if (fam == 'ipv6' && mwan4.no_ipv6 != 0) continue;
		push(L, ...rule_chain_lines(sprintf('%s_rules_%s', NFT_PREFIX, fam), rule_data[fam]));
		push(L, ...rule_chain_lines(sprintf('%s_rules_out_%s', NFT_PREFIX, fam), filter(rule_data[fam], rd => rd.local)));
	}

	push(L, '}');

	nft_file('add', 'rules', ...L);
}

// ── dnsmasq Domain Sets ──────────────────────────────────────────────

// One entry per domain rule: the domains and the per-family nftset specs dnsmasq must fill.
function domain_entries(rule_data) {
	let entries = {};
	for (let fam in ['ipv4', 'ipv6']) {
		for (let rd in filter(rule_data[fam], rd => length(rd.domains))) {
			entries[rd.rule] ??= { domains: rd.domains, specs: [] };
			push(entries[rd.rule].specs, sprintf('%s#inet#%s#%s', fam == 'ipv4' ? '4' : '6', NFT_TABLE, rd.domain_set));
		}
	}
	return values(entries);
}

function sync_dnsmasq(rule_data) {
	if (dnsmasq.sync(domain_entries(rule_data)))
		dnsmasq.restart();
}

// Domains of enabled rules, read straight from UCI (usable without building nft rules).
prefetch_domains = function() {
	let domains = [];
	for (let s in ordered_rules())
		if (rule_enabled(s)) push(domains, ...filter(map(as_list(s.domain), v => trim('' + v)), validate_hostname));
	dnsmasq.prefetch(uniq(map(domains, d => lc(d))));
};

// ── Rebuild Dynamic File ─────────────────────────────────────────────

rebuild_dynamic = function() {
	nft_file('create', 'dynamic');
	set_general_nftables();
	rebuild_iface_nftfile();
	set_strategies_nftables();
};

// ── Interface Routes ─────────────────────────────────────────────────

// Tunnels have no netifd default route to copy, so their table gets `default dev <dev>`.
function needs_default_route(iface) {
	return uci_get(iface, 'type') == 'tunnel' || uci_get_bool(iface, 'default_route', false);
}

function create_default_route(iface, family, table_id) {
	let device = network_get_device(iface);
	if (!device || !validate_device_name(device)) return;
	run(sprintf('%s route replace table %d default dev %s', family == 'ipv4' ? 'ip -4' : 'ip -6', table_id, shell_quote(device)));
}

function create_iface_route(iface) {
	if (!validate_section_name(iface)) return;
	foreach_family(iface, function(iface, family) {
		let table_id = get_iface_table_id(iface);
		if (!table_id) return;

		let ip_cmd = (family == 'ipv4') ? 'ip -4' : 'ip -6';
		if (family == 'ipv6' && mwan4.no_ipv6 != 0) return;

		let existing = cmd_output(sprintf('%s route list table %d 2>/dev/null', ip_cmd, table_id));
		update_dev_to_table();

		for (let route_line in get_routes(family)) {
			let tid = route_line_dev(route_line, family);
			// Skip default/link-local routes belonging to other interfaces
			if ((index(route_line, 'default') == 0 || index(route_line, 'fe80::/64') == 0) && tid != table_id)
				continue;
			if (tid != null && tid != table_id)
				continue;
			// Skip if already in table
			if (length(existing) && index(existing, route_line) >= 0)
				continue;
			let rc = run(sprintf('%s route add table %d %s', ip_cmd, table_id, route_line));
			if (rc != 0)
				LOG('debug', sprintf("Route '%s' already in table %d", route_line, table_id));
		}

		if (needs_default_route(iface))
			create_default_route(iface, family, table_id);
	});
}

function delete_iface_route(iface) {
	if (!validate_section_name(iface)) return;
	foreach_family(iface, function(iface, family) {
		let table_id = get_iface_table_id(iface);
		if (!table_id) return;
		if (family == 'ipv4')
			run(sprintf('ip -4 route flush table %d', table_id));
		else if (family == 'ipv6' && mwan4.no_ipv6 == 0)
			run(sprintf('ip -6 route flush table %d', table_id));
	});
}

// ── Interface IP Rules ───────────────────────────────────────────────

function delete_iface_rules_family(iface, family) { // ucode-lsp disable
	if (!validate_section_name(iface)) return;
	family = normalize_family(family);
	if (!family) return;
	let id = get_iface_id(iface);
	if (!id) return;

	let ip_cmd;
	if (family == 'ipv4')
		ip_cmd = 'ip -4';
	else if (family == 'ipv6' && mwan4.no_ipv6 == 0)
		ip_cmd = 'ip -6';
	else
		return;

	for (let line in cmd_lines(sprintf('%s rule list', ip_cmd))) {
		let m = match(line, /^([0-9]+):/);
		if (!m) continue;
		let pref = int(m[1]);
		if (pref > 1000 && pref < 4000 && (pref % 1000) == id)
			run(sprintf('%s rule del pref %d', ip_cmd, pref));
	}
}

function create_iface_rules(iface, device) {
	if (!validate_section_name(iface)) return;
	if (!validate_device_name(device)) {
		warn_invalid('device name', device, sprintf('interface %s rules', iface));
		return;
	}
	foreach_family(iface, function(iface, family, device) {
		let id = get_iface_id(iface);
		let table_id = get_iface_table_id(iface);
		let mark = get_iface_mark(iface);
		if (!id || !table_id || !mark) return;

		let ip_cmd;
		if (family == 'ipv4')
			ip_cmd = 'ip -4';
		else if (family == 'ipv6' && mwan4.no_ipv6 == 0)
			ip_cmd = 'ip -6';
		else
			return;

		// Delete existing rules first
		delete_iface_rules_family(iface, family);

		run(sprintf('%s rule add pref %d iif %s lookup %d', ip_cmd, id + 1000, shell_quote(device), table_id));
		run(sprintf('%s rule add pref %d fwmark %s/%s lookup %d', ip_cmd, id + 2000, mark, mwan4.mmx_mask, table_id));
		run(sprintf('%s rule add pref %d fwmark %s/%s unreachable', ip_cmd, id + 3000, mark, mwan4.mmx_mask));
	}, device);
}

function delete_iface_rules(iface) {
	if (!validate_section_name(iface)) return;
	foreach_family(iface, function(iface, family) {
		delete_iface_rules_family(iface, family);
	});
}

// ── Reporting ────────────────────────────────────────────────────────

function parse_nft_counters(out) {
	let result  = {};
	let current = null;

	for (let line in split(out || '', '\n')) {
		line = trim(line);

		let inline = match(line, /^counter ([A-Za-z0-9_]+) \{ packets ([0-9]+) bytes ([0-9]+) \}$/);
		if (inline) {
			result[inline[1]] = {
				packets: int(inline[2]),
				bytes:   int(inline[3]),
			};
			current = null;
			continue;
		}

		let start = match(line, /^counter ([A-Za-z0-9_]+) \{/);
		if (start) {
			current = start[1];
			result[current] = {
				packets: 0,
				bytes:   0,
			};
			continue;
		}

		if (!current) continue;

		let stats = match(line, /^packets ([0-9]+) bytes ([0-9]+)/);
		if (stats) {
			result[current].packets = int(stats[1]);
			result[current].bytes = int(stats[2]);
			continue;
		}

		if (index(line, '}') >= 0)
			current = null;
	}

	return result;
}

function report_counters() {
	let out = nft_output(sprintf('list counters inet %s 2>/dev/null', NFT_TABLE));
	return parse_nft_counters(out);
}

// ── Connections ──────────────────────────────────────────────────────

let conntrack_cache = { time: 0, counts: null };

function connection_layout() {
	return { wan_mask: parse_mark_number(mwan4.mmx_mask), rule_mask: mwan4.rule_mask_n };
}

// One conntrack pass serves every status poll within the cache TTL.
function connection_counts() {
	if (!conntrack_cache.counts || time() - conntrack_cache.time >= CONNTRACK_CACHE_TTL)
		conntrack_cache = { time: time(), counts: connections.scan(readfile(CONNTRACK_FILE) || '', connection_layout()).counts };
	return conntrack_cache.counts;
}

function conntrack_accounting() {
	return read_str(CONNTRACK_ACCT_FILE) == '1';
}

function sum(numbers) {
	let total = 0;
	for (let n in numbers) total += n;
	return total;
}

function sum_counts(a, b) {
	return connections.family_counts(a.ipv4 + b.ipv4, a.ipv6 + b.ipv6);
}

// Every rule section in priority order; the catch-alls have id 0 and share the unmarked bucket.
function rule_records() {
	return map(ordered_rules(), s => {
		let catch_all = !!DEFAULT_RULES[s['.name']];
		return {
			name: s['.name'], label: s.label || s['.name'], enabled: rule_enabled(s), strategy: s.use_strategy || '',
			id: catch_all ? 0 : valid_rule_id(s.rule_id), catch_all,
			families: length(as_list(s.family)) ? as_list(s.family) : ['ipv4', 'ipv6'],
		};
	});
}

// Connections of ids no rule owns (a deleted rule, rule bits from before an upgrade) belong to the catch-alls.
function rules_active(recs, counts) {
	let owned = uniq(map(filter(recs, rec => rec.id), rec => rec.id));
	let in_rules = family => sum(map(owned, id => counts.rules['' + id]?.[family] ?? 0));
	let pick = (rec, family) => rec.catch_all
		? (index(rec.families, family) >= 0 ? counts.total[family] - in_rules(family) : 0)
		: (rec.id ? counts.rules['' + rec.id]?.[family] ?? 0 : 0);

	let result = {};
	for (let rec in recs)
		result[rec.name] = connections.family_counts(pick(rec, 'ipv4'), pick(rec, 'ipv6'));
	return result;
}

function active_by_rule() {
	return rules_active(rule_records(), connection_counts());
}

function rule_new_connections(rec, counters) {
	let pick = family => counters[nft_counter_name('conn', rec.name, family)]?.packets ?? 0;
	return connections.family_counts(pick('ipv4'), pick('ipv6'));
}

function interface_active(iface) {
	return connection_counts().wans['' + parse_mark_number(get_iface_mark(iface))] ?? connections.family_counts();
}

function interfaces_active() {
	let result = {};
	uci_foreach('interface', function(s) {
		result[s['.name']] = interface_active(s['.name']);
	});
	return result;
}

function strategies_active() {
	let active = active_by_rule(), result = {};
	for (let rec in filter(rule_records(), rec => rec.strategy))
		result[rec.strategy] = sum_counts(result[rec.strategy] ?? connections.family_counts(), active[rec.name]);
	return result;
}

function get_status_rules() {
	let active = active_by_rule(), counters = report_counters(), result = {};
	for (let rec in rule_records())
		result[rec.name] = {
			id: rec.id, label: rec.label, enabled: rec.enabled, strategy: rec.strategy,
			new_connections: rule_new_connections(rec, counters), active_connections: active[rec.name],
		};
	return result;
}

function wan_names() {
	let names = {};
	for (let name, mark in { default: mwan4.mmx_default, blackhole: mwan4.mmx_blackhole, unreachable: mwan4.mmx_unreachable })
		names['' + parse_mark_number(mark)] = name;
	uci_foreach('interface', function(s) {
		names['' + parse_mark_number(get_iface_mark(s['.name']))] = s['.name'];
	});
	return names;
}

// Rule of a connection: the record owning its rule id, else the catch-all of its family.
function rule_resolver() {
	let by_id = {}, catch_all = {};
	for (let rec in rule_records()) {
		if (!rec.catch_all) by_id['' + rec.id] ??= rec;
		else for (let family in rec.families) catch_all[family] ??= rec;
	}
	return (family, id) => by_id['' + id] ?? catch_all[family];
}

function connection_item(entry, resolve, names) {
	let rec = resolve(entry.family, entry.rule_id);
	let own = rec && !rec.catch_all;
	return {
		family: entry.family, proto: entry.proto, src: entry.src, sport: entry.sport, dst: entry.dst, dport: entry.dport,
		state: entry.state, timeout: entry.timeout, packets: entry.packets, bytes: entry.bytes,
		rule: own ? rec.name : '', rule_label: own ? rec.label : '',
		interface: names['' + entry.wan] ?? sprintf('0x%x', entry.wan), strategy: rec?.strategy ?? '',
	};
}

function connection_matches_text(item, text) {
	let fields = [item.family, item.proto, item.src, item.dst, item.state, item.rule, item.rule_label, item.interface, item.strategy,
		item.sport, item.dport, item.src + ':' + item.sport, item.dst + ':' + item.dport];
	return index(lc(join(' ', fields)), lc(text)) >= 0;
}

// Most traffic first (bytes when conntrack accounting is on), then the longest remaining timeout.
function get_connections(args) {
	_ensure_init();
	args = args || {};

	let limit = min(max(int(args.limit) || CONNECTIONS_DEFAULT_LIMIT, 1), CONNECTIONS_MAX_LIMIT);
	let offset = max(int(args.offset) || 0, 0);
	let resolve = rule_resolver(), names = wan_names();
	let want = (family, id, wan) => {
		let rec = resolve(family, id);
		return (!args.family || args.family == family) && (!args.interface || names['' + wan] == args.interface)
			&& (!args.rule || rec?.name == args.rule) && (!args.strategy || rec?.strategy == args.strategy);
	};

	let items = map(connections.scan(readfile(CONNTRACK_FILE) || '', connection_layout(), want).entries, e => connection_item(e, resolve, names));
	items = filter(items, item => (!args.proto || lc(args.proto) == item.proto) && (!args.search || connection_matches_text(item, args.search)));
	sort(items, (a, b) => b.bytes - a.bytes || b.timeout - a.timeout);

	return {
		ok: true, total: length(items), truncated: length(items) > offset + limit,
		accounting: conntrack_accounting(), items: slice(items, offset, offset + limit),
	};
}

function report_iface_status() {
	let result = [];
	uci_foreach('interface', function(s) {
		let iface = s['.name'];
		foreach_family(iface, function(iface, family) {
			let id = get_iface_id(iface);
			let table_id = get_iface_table_id(iface);
			let device = network_get_device(iface);
			let ip_cmd = (family == 'ipv4') ? 'ip -4' : 'ip -6';
			let status_iface = sprintf('%s_%s', iface, family);
			let iface_st = read_str(sprintf('%s/%s/STATUS', TRACK_STATUS_DIR, status_iface)) || 'unknown';
			let tracking = get_mwan4track_status(iface, family);
			let detail;

			if (iface_st == 'online') {
				let online = get_online_time(status_iface);
				let uptime = network_get_uptime(iface);
				let hotplug_state = get_iface_hotplug_state(iface);
				detail = sprintf('%s %02dh:%02dm:%02ds, uptime %02dh:%02dm:%02ds',
					hotplug_state,
					online / 3600, (online % 3600) / 60, online % 60,
					uptime / 3600, (uptime % 3600) / 60, uptime % 60);
			} else {
				let err = 0;
				let rules = cmd_output(sprintf('%s rule list', ip_cmd));
				if (id) {
					if (index(rules, (id + 1000) + ':') < 0) err += 1;
					if (index(rules, (id + 2000) + ':') < 0) err += 2;
					if (index(rules, (id + 3000) + ':') < 0) err += 4;
				}
				let chain_name = sprintf('%s_iface_in_%s_%s', NFT_PREFIX, iface, family);
				if (!length(nft_output(sprintf('list chain inet %s %s 2>/dev/null', NFT_TABLE, chain_name))))
					err += 8;
				if (table_id && device) {
					if (validate_device_name(device) && index(cmd_output(sprintf('%s route list table %d default dev %s 2>/dev/null', ip_cmd, table_id, shell_quote(device))), 'default') < 0)
						err += 16;
				}
				detail = err ? '' + err : '';
			}

			let msg;
			if (detail)
				msg = sprintf(' interface %s (%s) is %s and tracking is %s (%s)', iface, family, iface_st, tracking, detail);
			else
				msg = sprintf(' interface %s (%s) is %s and tracking is %s', iface, family, iface_st, tracking);
			push(result, sprintf('%s, %d active connections', msg, interface_active(iface)[family]));
		});
	});
	return result;
}

function parse_strategy_chain(strategy, family_suffix, chain_out) {
	let chain_name = sprintf('%s_strategy_%s_%s', NFT_PREFIX, strategy, family_suffix);
	let status = {
		'exists':          length(trim(chain_out || '')) > 0,
		'chain':           chain_name,
		'status':          'missing',
		'active':          [],
		'fallback_routes': [],
		'fallback':        null,
	};

	if (!status.exists)
		return status;

	for (let cline in split(chain_out, '\n')) {
		let active = match(cline, /comment "([^ ]+) ([0-9]+) ([0-9]+)"/);
		if (active) {
			push(status.active, {
				'interface': active[1],
				'weight':    int(active[2]),
				'total':     int(active[3]),
				'percent':   int(active[3]) > 0 ? int(active[2]) / int(active[3]) * 100 : 0,
			});
			continue;
		}

		let out = match(cline, /comment "out ([^ ]+) ([^"]+)"/);
		if (out) {
			push(status.fallback_routes, {
				'interface': out[1],
				'device':    out[2],
			});
			continue;
		}

		let fallback = match(cline, /comment "(unreachable|blackhole|default)"/);
		if (fallback)
			status.fallback = { 'mode': fallback[1] };
	}

	if (length(status.active))
		status.status = 'active';
	else if (length(status.fallback_routes))
		status.status = 'fallback';
	else if (status.fallback)
		status.status = 'last_resort';
	else
		status.status = 'empty';

	return status;
}

function get_strategy_status(family_suffix) {
	let result = {};
	let active = strategies_active();

	uci_foreach('strategy', function(s) {
		let strategy = s['.name'];
		if (!validate_nft_section_name(strategy)) return;

		let chain_name = sprintf('%s_strategy_%s_%s', NFT_PREFIX, strategy, family_suffix);
		let chain_out = nft_output(sprintf('list chain inet %s %s 2>/dev/null', NFT_TABLE, chain_name));
		result[strategy] = parse_strategy_chain(strategy, family_suffix, chain_out);
		result[strategy].active_connections = (active[strategy] ?? connections.family_counts())[family_suffix];
	});

	return result;
}

function get_strategies_data(family_suffix) {
	let strategies = {};
	let status = get_strategy_status(family_suffix);

	for (let strategy in keys(status)) {
		if (!status[strategy].exists) continue;
		strategies[strategy] = [];
		for (let entry in status[strategy].active)
			push(strategies[strategy], {
				iface:  entry.interface,
				weight: entry.weight,
				total:  entry.total,
			});
	}

	return strategies;
}

function get_status_strategies(family_suffix) {
	let data = get_strategies_data(family_suffix);
	let result = {};

	for (let name in keys(data)) {
		result[name] = [];
		for (let e in data[name]) {
			if (e.total > 0)
				push(result[name], {
					'interface': e.iface,
					'percent':   e.weight / e.total * 100,
				});
		}
	}

	return result;
}

function report_strategies(family_suffix) {
	let result = [];
	let strategies = get_strategies_data(family_suffix);
	let active = strategies_active();
	for (let name in keys(strategies)) {
		push(result, sprintf('%s: (%d active connections)', name, (active[name] ?? connections.family_counts())[family_suffix]));
		let entries = strategies[name];
		let total = length(entries) ? entries[0].total : 0;
		if (total > 0) {
			for (let e in entries)
				push(result, sprintf(' %s (%d%%)', e.iface, e.weight * 100 / total));
		} else if (length(entries)) {
			push(result, sprintf(' %s', entries[0].iface));
		}
	}
	return result;
}

function report_connected(family) {
	let setname = sprintf('%s_connected_%s', NFT_PREFIX, family);
	let out = nft_output(sprintf('list set inet %s %s 2>/dev/null', NFT_TABLE, setname));
	let result = [];
	let in_elements = false;
	for (let line in split(out, '\n')) {
		line = trim(line);
		if (match(line, /elements = \{/)) { in_elements = true; continue; }
		if (in_elements && match(line, /\}/)) break;
		if (in_elements && length(line)) {
			line = replace(line, /[,\s]+$/, '');
			if (length(line)) push(result, line);
		}
	}
	return result;
}

function report_rules(family) {
	let chain = sprintf('%s_rules_%s', NFT_PREFIX, family);
	let out = nft_output(sprintf('list chain inet %s %s 2>/dev/null', NFT_TABLE, chain));
	let stats = get_status_rules();
	let result = [];
	for (let line in split(out, '\n')) {
		let name = match(line, /comment "([^"]+)"/)?.[1];
		if (!name) continue;
		let rule = stats[name];
		line = replace(line, /meta mark.*/, '');
		line = replace(line, NFT_PREFIX + '_strategy_', '- ');
		line = replace(line, NFT_PREFIX + '_rule_', 'S ');
		push(result, sprintf('%s  [%s id %d: %d active, %d new connections]', trim(line), name, rule?.id ?? 0,
			rule?.active_connections[family] ?? 0, rule?.new_connections[family] ?? 0));
	}
	return result;
}

function report_tunnels() {
	let status = get_tunnel_status();
	let result = [];
	let names = keys(status.interfaces);

	if (!length(names)) {
		push(result, 'No tunnel interfaces configured.');
		return result;
	}

	for (let iface in names) {
		let meta = status.interfaces[iface];
		let underlays = join(',', meta.underlay_interfaces || []);
		push(result, sprintf(' %s: type=%s transport=%s underlay_strategy=%s endpoint_fail_mode=%s data_fail_mode=%s prevent_recursion=%s underlay_interfaces=%s',
			iface,
			meta.type || '-',
			meta.transport_type || '-',
			meta.underlay_strategy || '-',
			meta.endpoint_fail_mode || '-',
			meta.data_fail_mode || '-',
			meta.prevent_recursion ? 'true' : 'false',
			length(underlays) ? underlays : '-'));
	}

	for (let warning in status.warnings)
		push(result, sprintf('Warning: %s: %s', warning.code, warning.message));

	return result;
}

function parse_nft_counter_references(out) {
	let result = {};
	let chain = null;

	for (let line in split(out || '', '\n')) {
		line = trim(line);

		let chain_start = match(line, /^chain ([A-Za-z0-9_]+) \{/);
		if (chain_start) {
			chain = chain_start[1];
			continue;
		}

		if (line == '}') {
			chain = null;
			continue;
		}

		let refs = split(line, /counter name "?/);
		for (let i = 1; i < length(refs); i++) {
			let name = match(refs[i], /^([A-Za-z0-9_]+)/);
			if (!name) continue;
			if (!result[name[1]]) result[name[1]] = [];
			push(result[name[1]], {
				'chain': chain,
				'rule':  line,
			});
		}
	}

	return result;
}

function summarize_counters(counters) {
	let summary = {
		'total':       0,
		'packets':     0,
		'bytes':       0,
		'interfaces':  0,
		'strategies':  0,
		'rules':       0,
		'connections': 0,
		'other':       0,
	};

	for (let name in keys(counters || {})) {
		let counter = counters[name] || {};
		summary.total++;

		// New-connection counters count connections, not traffic.
		if (index(name, NFT_PREFIX + '_counter_conn_') == 0) {
			summary.connections++;
			continue;
		}

		summary.packets += int(counter.packets || 0);
		summary.bytes += int(counter.bytes || 0);

		if (index(name, NFT_PREFIX + '_counter_iface_') == 0)
			summary.interfaces++;
		else if (index(name, NFT_PREFIX + '_counter_strategy_') == 0)
			summary.strategies++;
		else if (index(name, NFT_PREFIX + '_counter_rule_') == 0)
			summary.rules++;
		else
			summary.other++;
	}

	return summary;
}

function counter_summary_empty() {
	return {
		'total':   0,
		'packets': 0,
		'bytes':   0,
	};
}

function counter_summary_add(summary, counter) {
	summary.total++;
	summary.packets += int(counter?.packets || 0);
	summary.bytes += int(counter?.bytes || 0);
}

function join_parts(parts, start, end) {
	let result = [];
	for (let i = start; i < end; i++)
		push(result, parts[i]);
	return join('_', result);
}

function last_family_index(parts) {
	let found = -1;
	for (let i = 0; i < length(parts); i++)
		if (parts[i] == 'ipv4' || parts[i] == 'ipv6')
			found = i;
	return found;
}

function parse_counter_identity(name) {
	let prefix = NFT_PREFIX + '_counter_';
	if (index(name, prefix) != 0)
		return { 'kind': 'other', 'name': name };

	let tail = substr(name, length(prefix));
	let kind = match(tail, /^(iface|strategy|rule|conn)_(.+)$/);
	if (!kind)
		return { 'kind': 'other', 'name': name };

	let parts = split(kind[2], '_');
	let family_pos = last_family_index(parts);
	if (family_pos < 0)
		return { 'kind': 'other', 'name': name };

	let family = parts[family_pos];
	switch (kind[1]) {
	case 'iface':
		return {
			'kind':      'interface',
			'interface': join_parts(parts, 0, family_pos),
			'family':    family,
			'detail':    join_parts(parts, family_pos + 1, length(parts)),
			'name':      name,
		};
	case 'strategy': {
		let detail = join_parts(parts, family_pos + 1, length(parts));
		let target = detail;
		let target_type = 'interface';
		if (index(detail, 'out_') == 0) {
			target = substr(detail, 4);
			target_type = 'fallback_route';
		} else if (detail == 'default' || detail == 'blackhole' || detail == 'unreachable') {
			target_type = 'last_resort';
		}
		return {
			'kind':        'strategy',
			'strategy':    join_parts(parts, 0, family_pos),
			'family':      family,
			'target':      target,
			'target_type': target_type,
			'name':        name,
		};
	}
	case 'rule':
	case 'conn':
		return {
			'kind':   kind[1] == 'rule' ? 'rule' : 'connection',
			'rule':   join_parts(parts, 0, family_pos),
			'family': family,
			'name':   name,
		};
	}

	return { 'kind': 'other', 'name': name };
}

function ensure_counter_entity(group, key) {
	if (!group[key])
		group[key] = {
			'summary':  counter_summary_empty(),
			'families': {},
		};
	return group[key];
}

function ensure_counter_family(entity, family) {
	if (!entity.families[family])
		entity.families[family] = {
			'summary': counter_summary_empty(),
			'items':   {},
		};
	return entity.families[family];
}

function group_counters(counters) {
	let groups = {
		'interfaces': {},
		'strategies': {},
		'rules':      {},
		'other':      {
			'summary': counter_summary_empty(),
			'items':   {},
		},
	};

	for (let name in keys(counters || {})) {
		let counter = counters[name];
		let parsed = parse_counter_identity(name);
		let entity, family;

		switch (parsed.kind) {
		case 'interface':
			entity = ensure_counter_entity(groups.interfaces, parsed.interface);
			family = ensure_counter_family(entity, parsed.family);
			family.items[name] = { ...counter, 'detail': parsed.detail };
			counter_summary_add(entity.summary, counter);
			counter_summary_add(family.summary, counter);
			break;
		case 'strategy':
			entity = ensure_counter_entity(groups.strategies, parsed.strategy);
			family = ensure_counter_family(entity, parsed.family);
			family.items[name] = { ...counter, 'target': parsed.target, 'target_type': parsed.target_type };
			counter_summary_add(entity.summary, counter);
			counter_summary_add(family.summary, counter);
			break;
		case 'rule':
			entity = ensure_counter_entity(groups.rules, parsed.rule);
			family = ensure_counter_family(entity, parsed.family);
			family.items[name] = counter;
			counter_summary_add(entity.summary, counter);
			counter_summary_add(family.summary, counter);
			break;
		case 'connection':
			entity = ensure_counter_entity(groups.rules, parsed.rule);
			entity.new_connections = connections.family_counts(
				entity.new_connections?.ipv4 + (parsed.family == 'ipv4' ? counter.packets : 0),
				entity.new_connections?.ipv6 + (parsed.family == 'ipv6' ? counter.packets : 0));
			break;
		default:
			groups.other.items[name] = counter;
			counter_summary_add(groups.other.summary, counter);
			break;
		}
	}

	return groups;
}

function get_service_instances() {
	return ubus_call('service', 'list', { 'name': 'mwan4' })?.mwan4?.instances || {};
}

function get_tracker_state(ifname, family, intf, procd) {
	let status_iface = sprintf('%s_%s', ifname, family);
	let uci_track_ips = as_list(intf.track_ip);

	if (!length(uci_track_ips))
		return 'disabled';

	if (procd?.[sprintf('track_%s', status_iface)]?.running) {
		let started = read_str(sprintf('%s/%s/STARTED', TRACK_STATUS_DIR, status_iface)) || '';
		switch (started) {
			case '0': return 'paused';
			case '1': return 'active';
			default:  return 'down';
		}
	}

	return 'down';
}

function get_family_runtime_status(ifname, family, intf, procd, uptime) {
	let status_iface = sprintf('%s_%s', ifname, family);
	let true_iface = get_true_iface(ifname, family);
	let netstatus = ubus_call(sprintf('network.interface.%s', true_iface), 'status') || ubus_call(sprintf('network.interface.%s', ifname), 'status');
	let track_status = get_tracker_state(ifname, family, intf, procd);
	let score_max = int(intf.down || '5') + int(intf.up || '5');
	if (score_max < 1) score_max = 1;

	let score = read_int_nullable(sprintf('%s/%s/SCORE', TRACK_STATUS_DIR, status_iface));
	let failed = read_int_nullable(sprintf('%s/%s/LOST', TRACK_STATUS_DIR, status_iface));
	let turn = read_int_nullable(sprintf('%s/%s/TURN', TRACK_STATUS_DIR, status_iface));
	let targets = [];
	let failed_targets = 0;

	for (let ip in as_list(intf.track_ip)) {
		let latency = read_int_nullable(sprintf('%s/%s/LATENCY_%s', TRACK_STATUS_DIR, status_iface, ip));
		let loss = read_int_nullable(sprintf('%s/%s/LOSS_%s', TRACK_STATUS_DIR, status_iface, ip));
		let target_status = read_str(sprintf('%s/%s/TRACK_%s', TRACK_STATUS_DIR, status_iface, ip)) || 'unknown';
		if (target_status == 'down') failed_targets++;
		push(targets, {
			'ip':         ip,
			'status':     target_status,
			'latency':    latency,
			'packetloss': loss,
			'measured':   latency != null || loss != null,
		});
	}

	let runtime_status = read_str(sprintf('%s/%s/STATUS', TRACK_STATUS_DIR, status_iface)) || 'unknown';
	let health_state = runtime_status;
	if (runtime_status == 'online' && failed_targets > 0)
		health_state = 'degraded';
	else if (track_status == 'paused')
		health_state = 'paused';
	else if (track_status == 'disabled')
		health_state = 'disabled';

	return {
		'family':        family,
		'interface':     true_iface,
		'device':        netstatus?.l3_device || netstatus?.device || null,
		'status':        runtime_status,
		'health_state':  health_state,
		'tracking':      track_status,
		'running':       track_status == 'active',
		'up':            netstatus?.up || false,
		'uptime':        netstatus?.uptime || 0,
		'age':           elapsed_since(sprintf('%s/%s/TIME', TRACK_STATUS_DIR, status_iface), uptime),
		'online':        elapsed_since(sprintf('%s/%s/ONLINE', TRACK_STATUS_DIR, status_iface), uptime),
		'offline':       elapsed_since(sprintf('%s/%s/OFFLINE', TRACK_STATUS_DIR, status_iface), uptime),
		'score':         score,
		'score_current': score,
		'score_max':     score_max,
		'score_percent': score == null ? null : score * 100 / score_max,
		'lost':          failed,
		'failed_checks': failed == null ? failed_targets : failed,
		'failed_targets': failed_targets,
		'turn':          turn,
		'track_ip':      targets,
	};
}

function get_interfaces_status(args, procd) {
	args = args || {};
	procd = procd || get_service_instances();

	let uptime = get_uptime();
	let interfaces = {};

	uci_foreach('interface', function(intf) {
		let ifname = intf['.name'];
		if (args.interface != null && args.interface != ifname)
			return;

		let families = get_families(ifname);
		let family_status = {};
		for (let family in families)
			family_status[family] = get_family_runtime_status(ifname, family, intf, procd, uptime);

		let primary_family = families[0] || 'ipv4';
		let primary = family_status[primary_family] || {};

		let overall_status = 'unknown';
		let saw_online = false;
		let saw_offline = false;
		for (let family in families) {
			let st = family_status[family]?.status || 'unknown';
			if (st == 'online') saw_online = true;
			if (st == 'offline') saw_offline = true;
		}
		if (saw_online && saw_offline) overall_status = 'degraded';
		else if (saw_online) overall_status = 'online';
		else if (saw_offline) overall_status = 'offline';

		let data = {
			'age':             primary.age,
			'online':          primary.online,
			'offline':         primary.offline,
			'uptime':          primary.uptime || 0,
			'score':           primary.score,
			'score_current':   primary.score_current,
			'score_max':       primary.score_max,
			'score_percent':   primary.score_percent,
			'lost':            primary.lost,
			'failed_checks':   primary.failed_checks,
			'failed_targets':  primary.failed_targets,
			'turn':            primary.turn,
			'status':          overall_status,
			'health_state':    saw_online && saw_offline ? 'partial' : (primary.health_state || overall_status),
			'enabled':         uci_bool(intf.enabled),
			'running':         !!primary.running,
			'tracking':        primary.tracking || 'down',
			'up':              !!primary.up,
			'track_ip':        primary.track_ip || [],
			'families':        family_status,
			'quality_enabled': uci_bool(intf.check_quality),
			'quality_supported': (intf.track_method || 'ping') == 'ping' || (intf.track_method || 'ping') == 'httping',
			'track_method':    intf.track_method || 'ping',
			'reliability':     int(intf.reliability || '1'),
			'down':            int(intf.down || '5'),
			'up_threshold':    int(intf.up || '5'),
			'failure_latency': int(intf.failure_latency || '1000'),
			'failure_loss':    int(intf.failure_loss || '50'),
			'recovery_latency': int(intf.recovery_latency || '500'),
			'recovery_loss':   int(intf.recovery_loss || '10'),
			'active_connections': interface_active(ifname),
		};

		let tunnel = get_tunnel_metadata(intf);
		if (tunnel?.configured)
			data.tunnel = tunnel;

		interfaces[ifname] = data;
	});

	return interfaces;
}

function status_warning(code, message, action, check) {
	return {
		'severity': 'warning',
		'code':     code,
		'message':  message,
		'action':   action || STATUS_DIAGNOSTIC_ACTION,
		'check':    check || null,
	};
}

function status_next_step(id, title, detail, command) {
	return {
		'id':      id,
		'title':   title,
		'detail':  detail,
		'command': command || null,
	};
}

function status_next_steps(configured, cfg, service_running, trackers_running, nft_ready) {
	let result = [];

	if (!configured) {
		push(result, status_next_step('configureWan', 'Add and enable a WAN link',
			'Configure at least one mwan4 interface before checking runtime health.', null));
		return result;
	}

	if (!service_running)
		push(result, status_next_step('restartService', 'Restart mwan4 service',
			'The service must be running before trackers, nftables chains, and policy routing can be trusted.',
			'/etc/init.d/mwan4 restart'));

	if (cfg.trackers_expected > 0 && trackers_running == 0)
		push(result, status_next_step('checkTrackers', 'Check health trackers',
			'Enabled interfaces with tracking targets should have track_<iface>_<family> procd instances and /var/run/mwan4track status files.',
			'ubus call service list \'{"name":"mwan4"}\''));

	if (!nft_ready)
		push(result, status_next_step('checkNftables', 'Check nftables chains',
			'mwan4 needs prerouting/output hooks and per-family rule chains in the inet fw4 table.',
			'nft list table inet fw4'));

	if (!length(result))
		push(result, status_next_step('reviewCounters', 'Review rule counters',
			'Counters should increase on matching rules, strategies, and interfaces when traffic uses mwan4 policies.',
			'ubus call mwan4 diagnostics \'{"section":"counters"}\''));

	return result;
}

function count_running_instances(instances, prefix) {
	let count = 0;
	instances = instances || {};

	for (let name in keys(instances)) {
		if (prefix && index(name, prefix) != 0)
			continue;
		if (instances[name]?.running)
			count++;
	}

	return count;
}

function nft_chain_exists(chain) {
	return length(trim(nft_output(sprintf('list chain inet %s %s 2>/dev/null', NFT_TABLE, chain)))) > 0;
}

function detect_status_nft_chains(state) {
	if (state?.nft_chains != null)
		return state.nft_chains;

	return {
		'prerouting': nft_chain_exists(NFT_PREFIX + '_prerouting'),
		'output':     nft_chain_exists(NFT_PREFIX + '_output'),
		'rules_ipv4': nft_chain_exists(NFT_PREFIX + '_rules_ipv4'),
		'rules_ipv6': nft_chain_exists(NFT_PREFIX + '_rules_ipv6'),
	};
}

function nft_chains_ready(chains) {
	if (type(chains) == 'bool')
		return chains;

	chains = chains || {};
	return !!(chains.prerouting && chains.output && (chains.rules_ipv4 || chains.rules_ipv6));
}

function status_config_state() {
	let enabled_interfaces = [];
	let tracking_interfaces = [];
	let expected_trackers = [];
	let trackers_expected = 0;

	uci_foreach('interface', function(intf) {
		if (!uci_bool(intf.enabled))
			return;

		let ifname = intf['.name'];
		let track_ips = as_list(intf.track_ip);
		push(enabled_interfaces, ifname);

		if (!length(track_ips))
			return;

		for (let family in get_families(ifname)) {
			let tracker = sprintf('track_%s_%s', ifname, family);
			push(tracking_interfaces, sprintf('%s_%s', ifname, family));
			push(expected_trackers, tracker);
			trackers_expected++;
		}
	});

	return {
		'enabled_interfaces':  enabled_interfaces,
		'tracking_interfaces': tracking_interfaces,
		'expected_trackers':   expected_trackers,
		'trackers_expected':   trackers_expected,
	};
}

function get_status_diagnostics(state) {
	state = state || {};

	let cfg = status_config_state();
	let procd = state.procd || null;
	if (state.service_instances == null && procd == null)
		procd = ubus_call('service', 'list', { 'name': 'mwan4' });

	let service_instances = state.service_instances ?? procd?.mwan4?.instances ?? procd?.instances ?? {};
	let instances_running = state.instances_running ?? count_running_instances(service_instances);
	let trackers_running = state.trackers_running ?? count_running_instances(service_instances, 'track_');
	let service_running = state.service_running ?? (instances_running > 0);
	let nft_chains = detect_status_nft_chains(state);
	let nft_ready = nft_chains_ready(nft_chains);
	let configured = length(cfg.enabled_interfaces) > 0;
	let running_trackers = [];
	let missing_trackers = [];
	let warnings = [];

	for (let name in keys(service_instances || {}))
		if (index(name, 'track_') == 0 && service_instances[name]?.running)
			push(running_trackers, name);

	for (let name in cfg.expected_trackers)
		if (index(running_trackers, name) < 0)
			push(missing_trackers, name);

	if (configured && !service_running)
		push(warnings, status_warning('serviceInactive', 'mwan4 is configured, but no service instances are running.',
			STATUS_DIAGNOSTIC_ACTION, SERVICE_DIAGNOSTIC_CHECK));

	if (configured && cfg.trackers_expected > 0 && trackers_running == 0)
		push(warnings, status_warning('trackersInactive', 'mwan4 has enabled tracking targets, but no health trackers are running.',
			TRACKER_DIAGNOSTIC_ACTION, TRACKER_DIAGNOSTIC_CHECK));

	if (configured && !nft_ready)
		push(warnings, status_warning('nftInactive', 'mwan4 is configured, but nftables chains are missing.',
			NFT_DIAGNOSTIC_ACTION, NFT_DIAGNOSTIC_CHECK));

	for (let warning in get_tunnel_warnings())
		push(warnings, status_warning(warning.code, warning.message, TUNNEL_DIAGNOSTIC_ACTION, TUNNEL_DIAGNOSTIC_CHECK));

	return {
		'configured':          configured,
		'enabled_interfaces':  cfg.enabled_interfaces,
		'tracking_interfaces': cfg.tracking_interfaces,
		'service_running':     service_running,
		'instances_running':   instances_running,
		'trackers_expected':   cfg.trackers_expected,
		'trackers_running':    trackers_running,
		'tracker_instances':   {
			'expected': cfg.expected_trackers,
			'running':  running_trackers,
			'missing':  missing_trackers,
		},
		'nft_chains':          nft_ready,
		'nft':                 nft_chains,
		'warnings':            warnings,
		'next_steps':          status_next_steps(configured, cfg, service_running, trackers_running, nft_ready),
	};
}

function get_status(args) {
	args = args || {};
	let procd;
	let counters;

	switch (args.section) {
	case 'connected':
		return {
			'connected': {
				'ipv4': report_connected('ipv4'),
				'ipv6': report_connected('ipv6'),
			},
		};
	case 'strategies':
		return {
			'strategies': {
				'ipv4': get_status_strategies('ipv4'),
				'ipv6': get_status_strategies('ipv6'),
			},
			'strategy_status': {
				'ipv4': get_strategy_status('ipv4'),
				'ipv6': get_strategy_status('ipv6'),
			},
		};
	case 'rules':
		return {
			'rules': get_status_rules(),
		};
	case 'interfaces':
		procd = get_service_instances();
		return {
			'interfaces':  get_interfaces_status(args, procd),
			'diagnostics': get_status_diagnostics({ 'service_instances': procd }),
		};
	case 'tunnels':
		return {
			'tunnels': get_tunnel_status(),
		};
	case 'diagnostics':
		return {
			'diagnostics': get_status_diagnostics({ 'service_instances': get_service_instances() }),
		};
	case 'counters':
		counters = report_counters();
		return {
			'counters': counters,
			'counter_summary': summarize_counters(counters),
		};
	default:
		procd = get_service_instances();
		return {
			'interfaces': get_interfaces_status(args, procd),
			'connected': {
				'ipv4': report_connected('ipv4'),
				'ipv6': report_connected('ipv6'),
			},
			'strategies': {
				'ipv4': get_status_strategies('ipv4'),
				'ipv6': get_status_strategies('ipv6'),
			},
			'strategy_status': {
				'ipv4': get_strategy_status('ipv4'),
				'ipv6': get_strategy_status('ipv6'),
			},
			'rules':       get_status_rules(),
			'tunnels':     get_tunnel_status(),
			'diagnostics': get_status_diagnostics({ 'service_instances': procd }),
		};
	}
}

function report_status_diagnostics(state) {
	let diagnostics = get_status_diagnostics(state);
	let result = [];

	if (!length(diagnostics.warnings)) {
		push(result, 'No status warnings.');
	} else {
		for (let warning in diagnostics.warnings) {
			push(result, sprintf('%s: %s', warning.code, warning.message));
			push(result, 'Action: ' + warning.action);
			if (warning.check)
				push(result, 'Check: ' + warning.check);
		}
	}

	if (length(diagnostics.next_steps)) {
		push(result, 'What to check next:');
		for (let step in diagnostics.next_steps) {
			push(result, sprintf(' - %s: %s', step.title, step.detail));
			if (step.command)
				push(result, '   Command: ' + step.command);
		}
	}

	return result;
}

// ── Interface Lifecycle ──────────────────────────────────────────────

function interface_hotplug_shutdown(iface, ifdown) {
	if (!validate_section_name(iface)) {
		warn_invalid('section name', iface, 'interface shutdown');
		return;
	}
	let iface_st = 'offline';
	for (let family in get_families(iface)) {
		let status_iface = sprintf('%s_%s', iface, family);
		let st = read_str(sprintf('%s/%s/STATUS', TRACK_STATUS_DIR, status_iface));
		if (st == 'online') { iface_st = 'online'; break; }
	}

	if (iface_st != 'online' && !ifdown) return;

	if (ifdown) {
		system(sprintf("env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin ACTION=ifdown INTERFACE=%s /bin/sh /etc/hotplug.d/iface/15-mwan4", shell_quote(iface)));
	} else if (iface_st == 'online') {
		system(sprintf("env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin MWAN4_SHUTDOWN=1 ACTION=disconnected INTERFACE=%s /sbin/hotplug-call iface", shell_quote(iface)));
	}
}

// ── Track Cleanup ────────────────────────────────────────────────────

function track_clean(iface) {
	if (!validate_section_name(iface)) {
		warn_invalid('section name', iface, 'track cleanup');
		return;
	}
	for (let family in get_families(iface)) {
		let status_iface = sprintf('%s_%s', iface, family);
		system(sprintf('rm -rf %s', shell_quote(sprintf('%s/%s', TRACK_STATUS_DIR, status_iface))));
	}
	system(sprintf('rm -rf %s', shell_quote(sprintf('%s/%s', STATUS_DIR, iface))));
}

// ── Conntrack ────────────────────────────────────────────────────────

function flush_conntrack(iface, action) {
	if (!validate_section_name(iface)) return;
	let flush_list = uci_get_list(iface, 'flush_conntrack');
	for (let trigger in flush_list) {
		if (trigger == action) {
			let mark = get_iface_mark(iface);
			if (mark) {
				run(sprintf('conntrack -D --mark %s/%s 2>/dev/null', mark, mwan4.mmx_mask));
				LOG('info', sprintf("conntrack flushed for '%s' (mark %s/%s) on '%s'",
					iface, mark, mwan4.mmx_mask, action));
			}
			break;
		}
	}
}

function interface_shutdown(iface) {
	if (!validate_section_name(iface)) return;
	interface_hotplug_shutdown(iface, false);
	track_clean(iface);
}

function ifup(iface, caller) {
	if (!validate_section_name(iface)) {
		warn_invalid('section name', iface, 'ifup');
		return;
	}
	if (caller == 'cmd') {
		if (run('/etc/init.d/mwan4 running') != 0) {
			LOG('warn', 'mwan4 service is not running');
			return;
		}
		uci_ctx = cursor();
		uci_ctx.load('mwan4');
	}

	if (!uci_bool(uci_get(iface, 'enabled'))) return;
	let iface_status = null;
	for (let family in get_families(iface)) {
		let true_iface = get_true_iface(iface, family);
		let candidate = ubus_call(sprintf('network.interface.%s', true_iface), 'status');
		if (candidate?.up && candidate?.l3_device) { iface_status = candidate; break; }
	}
	if (!iface_status) return;

	let l3_device = iface_status.l3_device;
	if (!validate_device_name(l3_device)) {
		warn_invalid('device name', l3_device, sprintf('interface %s ifup', iface));
		return;
	}
	if (caller == 'init') {
		create_iface_rules(iface, l3_device);
		create_iface_route(iface);
		set_iface_hotplug_state(iface, uci_get(iface, 'initial_state') == 'offline' ? 'offline' : 'online');
		return;
	}
	let cmd_str = sprintf("env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin MWAN4_STARTUP=%s ACTION=ifup INTERFACE=%s DEVICE=%s /bin/sh /etc/hotplug.d/iface/15-mwan4",
		shell_quote(caller || ''), shell_quote(iface), shell_quote(l3_device));
	system(cmd_str);
}

// ── Consumer API ─────────────────────────────────────────────────────

function is_interface(iface) {
	_ensure_init();
	if (!validate_section_name(iface)) return false;
	return uci_bool(uci_get(iface, 'enabled'));
}

function get_iface_chain(iface) {
	if (!validate_nft_section_name(iface)) return null;
	return sprintf('%s_iface_in_%s', NFT_PREFIX, iface);
}

function get_strategy_chain(strategy) {
	if (!validate_nft_section_name(strategy)) return null;
	return sprintf('%s_strategy_%s', NFT_PREFIX, strategy);
}

function get_interfaces() {
	_ensure_init();
	let result = [];
	uci_foreach('interface', function(s) {
		if (validate_section_name(s['.name']) && uci_bool(s.enabled))
			push(result, s['.name']);
	});
	return result;
}

function get_configured_interfaces() {
	_ensure_init();
	return uci_section_names('interface');
}

function get_strategies() {
	_ensure_init();
	let result = [];
	uci_foreach('strategy', function(s) {
		if (validate_section_name(s['.name']))
			push(result, s['.name']);
	});
	return result;
}

// ── Backend Contract ─────────────────────────────────────────────────

function get_capabilities() {
	_ensure_init();
	return {
		'version': CONTRACT_VERSION,
		'status': {
			'sections': STATUS_SECTIONS,
		},
		'validate': {
			'sections': ['config'],
		},
		'diagnostics': {
			'sections': DIAGNOSTIC_SECTIONS,
		},
		'probes': {
			'track_methods':   ['ping', 'httping', 'nslookup', 'arping', 'nping-tcp', 'nping-udp', 'nping-icmp', 'nping-arp'],
			'quality_methods': ['ping', 'httping'],
		},
		'control': {
			'actions':           RUNTIME_CONTROL_ACTIONS,
			'interface_actions': ['ifup', 'ifdown'],
			'service_actions':   ['start', 'stop', 'restart', 'reload'],
			'counter_actions':   ['reset_counters'],
		},
		'advanced_control': {
			'actions':           ADVANCED_CONTROL_ACTIONS,
			'feature_actions':   ['install_feature'],
			'key_actions':       ['wireguard_keygen'],
			'integration_actions': ['apply_tunnel_exemptions', 'apply_bfd'],
			'features':          sort(keys(package_ctl.FEATURE_PACKAGES)),
			'action_args':       {
				'ifup':                    ['interface'],
				'ifdown':                  ['interface'],
				'install_feature':         ['feature'],
				'apply_tunnel_exemptions': ['interface'],
			},
		},
		'packages': {
			'features': package_ctl.feature_package_map(),
		},
		'bfd': {
			'schema': BFD_SCHEMA,
		},
		'domains': {
			'dnsmasq_nftset': dnsmasq.nftset_supported(),
		},
		'connections': {
			'rule_mask':     mwan4.rule_mask,
			'rule_capacity': rule_capacity(),
			'limit_default': CONNECTIONS_DEFAULT_LIMIT,
			'limit_max':     CONNECTIONS_MAX_LIMIT,
			'filters':       ['rule', 'interface', 'strategy', 'family', 'proto', 'search'],
		},
	};
}

function contract_problem(code, section, message) {
	return {
		'code':    code,
		'section': section || null,
		'message': message,
	};
}

const RULE_ADDRESS_ERRORS = { src_ip: 'invalidRuleSourceAddress', dest_ip: 'invalidRuleDestinationAddress' };
const RULE_PORT_ERRORS = { src_port: 'invalidRuleSourcePort', dest_port: 'invalidRuleDestinationPort' };

function validate_rule_ports(s, proto, report) {
	let name = s['.name'];
	for (let field in ['src_port', 'dest_port']) {
		if (!s[field]) continue;
		if (proto != 'tcp' && proto != 'udp')
			report.error('invalidRulePortProtocol', name,
				sprintf("Rule '%s' uses %s with non-TCP/UDP protocol '%s'.", name, field, proto || s.proto || ''));
		if (normalize_ports(s[field]) == null)
			report.error(RULE_PORT_ERRORS[field], name, sprintf("Rule '%s' has invalid %s '%s'.", name, field, s[field]));
	}
}

// An address must be valid for at least one family the rule applies to.
function validate_rule_addresses(s, report) {
	let name = s['.name'];
	let families = as_list(s.family);
	let applicable = length(families) ? families : ['ipv4', 'ipv6'];
	for (let field in ['src_ip', 'dest_ip']) {
		for (let addr in as_list(s[field])) {
			if (!length(filter(applicable, f => validate_rule_address(fix_rule_address(addr, f), f))))
				report.error(RULE_ADDRESS_ERRORS[field], name, length(families)
					? sprintf("Rule '%s' %s '%s' does not match family '%s'.", name, field, addr, join(',', families))
					: sprintf("Rule '%s' has invalid %s '%s'.", name, field, addr));
		}
		if (!length(families) && length(as_list(s[field])))
			report.warning('implicitRuleAddressFamily', name, sprintf("Rule '%s' uses %s without an explicit family.", name, field));
	}
}

function validate_rule_matches(s, report) {
	let name = s['.name'];
	for (let mac in as_list(s.src_mac))
		if (!validate_mac(mac))
			report.error('invalidRuleSourceMac', name, sprintf("Rule '%s' has invalid src_mac '%s'.", name, mac));
	for (let domain in as_list(s.domain))
		if (!validate_hostname(domain))
			report.error('invalidRuleDomain', name, sprintf("Rule '%s' has invalid domain '%s'.", name, domain));
	if (s.dscp != null && !validate_dscp(s.dscp))
		report.error('invalidRuleDscp', name, sprintf("Rule '%s' dscp '%s' must be 1-63.", name, s.dscp));
	if (s.ipset && !validate_nft_identifier(s.ipset))
		report.error('invalidRuleIpset', name, sprintf("Rule '%s' ipset '%s' is not a safe nftables identifier.", name, s.ipset));
}

function validate_rule(s, strategies, builtin_strategies, report) {
	let name = s['.name'];
	let proto = normalize_protocol(s.proto || 'all');

	if (length(name) > 15)
		report.error('ruleNameTooLong', name, sprintf("Rule '%s' name exceeds 15 characters.", name));

	if (s.use_strategy && !strategies[s.use_strategy] && !builtin_strategies[s.use_strategy])
		report.error('invalidRuleStrategy', name, sprintf("Rule '%s' references unknown strategy '%s'.", name, s.use_strategy));

	if (!proto)
		report.error('invalidRuleProtocol', name, sprintf("Rule '%s' has unsupported protocol '%s'.", name, s.proto || ''));

	for (let family in as_list(s.family))
		if (family != 'ipv4' && family != 'ipv6')
			report.error('invalidRuleFamily', name, sprintf("Rule '%s' uses unsupported family '%s'.", name, family));

	validate_rule_ports(s, proto, report);
	validate_rule_addresses(s, report);
	validate_rule_matches(s, report);
}

// rule_mask and rule id health, shared by validate and diagnostics.
function external_uci_section(config, section) {
	let c = cursor();
	c.load(config);
	return c.get_all(config, section) ?? {};
}

function external_mark_masks() {
	let masks = {};
	let pbr = external_uci_section('pbr', 'config');
	let tomato = external_uci_section('tomato-qos', 'main');
	if (uci_bool(pbr.enabled))
		masks.pbr = parse_hex_int(pbr.fw_mask || '00ff0000');
	if (uci_bool(tomato.enabled))
		masks['tomato-qos'] = parse_mark_number(tomato.qos_mark_mask || '0xff') | parse_mark_number(tomato.dpi_state_mask || '0xc000')
			| parse_mark_number(tomato.rule_mark_mask || '0xff000000');
	return masks;
}

function validate_rule_mask(report) {
	let mask = parse_mark_number(mwan4.rule_mask);
	if (!(mask > 0 && mask <= 0xffffffff))
		return report.error('invalidRuleMask', 'globals', sprintf("Rule mark mask '%s' is invalid.", mwan4.rule_mask));
	if (mask & +mwan4.mmx_mask)
		return report.error('ruleMaskOverlap', 'globals', sprintf('Rule mark mask %s overlaps mmx_mask %s.', mwan4.rule_mask, mwan4.mmx_mask));
	for (let owner, owned in external_mark_masks())
		if (mask & owned)
			report.warning('ruleMaskSharedMarks', 'globals', sprintf('Rule mark mask %s overlaps %s marks %s; set a rule_mask they do not use.', mwan4.rule_mask, owner, sprintf('0x%08x', owned)));
}

function validate_rule_ids(report) {
	validate_rule_mask(report);
	if (!mwan4.rule_mask_n) return;

	let used = {};
	let sections = user_rule_sections(uci_ctx);
	for (let s in sections) {
		let id = valid_rule_id(s.rule_id);
		if (s.rule_id != null && !id)
			report.warning('invalidRuleId', s['.name'], sprintf("Rule '%s' has invalid rule_id '%s'; a new one is assigned on the next reload.", s['.name'], s.rule_id));
		else if (id && used[id])
			report.warning('duplicateRuleId', s['.name'], sprintf("Rule '%s' duplicates rule_id %d used by '%s'; a new one is assigned on the next reload.", s['.name'], id, used[id]));
		else if (id)
			used[id] = s['.name'];
	}

	if (length(sections) > rule_capacity())
		report.warning('ruleIdCapacity', null, sprintf('%d rules but rule_mask %s holds only %d rule ids; the others are not tracked per rule.', length(sections), mwan4.rule_mask, rule_capacity()));
}

function validate_config() {
	_ensure_init();

	let interfaces = uci_section_map('interface');
	let routes = {};
	let strategies = {};
	let errors = [];
	let warnings = [];
	let counts = {
		'interfaces': length(keys(interfaces)),
		'routes':     0,
		'strategies': 0,
		'rules':      0,
		'tunnels':    0,
	};
	let seen_ids = {};
	let seen_tables = {};
	let seen_marks = {};
	let mmx_mask = parse_mark_number(mwan4.mmx_mask);
	let mmx_default = parse_mark_number(mwan4.mmx_default);
	let mmx_blackhole = parse_mark_number(mwan4.mmx_blackhole);
	let mmx_unreachable = parse_mark_number(mwan4.mmx_unreachable);
	let ordinal = 0;

	function validation_error(code, section, message) {
		push(errors, contract_problem(code, section, message));
	}

	function validation_warning(code, section, message) {
		push(warnings, contract_problem(code, section, message));
	}

	if (mmx_mask == null || mmx_mask <= 0)
		validation_error('invalidMarkMask', 'globals', sprintf("Firewall mark mask '%s' is invalid.", mwan4.mmx_mask || ''));

	uci_foreach('interface', function(s) {
		let name = s['.name'];
		ordinal++;
		let id = parse_uint_number(s.id);
		let table_id = parse_uint_number(s.table_id);
		let mark = parse_mark_number(s.mark);

		if (!validate_section_name(name))
			validation_error('invalidInterfaceName', name,
				sprintf("Interface section '%s' is not a safe mwan4 name.", name || ''));

		for (let family in as_list(s.family || 'ipv4')) {
			if (family != 'ipv4' && family != 'ipv6')
				validation_error('invalidInterfaceFamily', name,
					sprintf("Interface '%s' uses unsupported family '%s'.", name, family));
		}

		if (s.id != null && id == null)
			validation_error('invalidInterfaceId', name,
				sprintf("Interface '%s' has invalid id '%s'.", name, s.id));
		if (s.table_id != null && (table_id == null || table_id < 1 || table_id > 4294967295))
			validation_error('invalidInterfaceTableId', name,
				sprintf("Interface '%s' has invalid table_id '%s'.", name, s.table_id));
		if (s.mark != null && (mark == null || mark <= 0))
			validation_error('invalidInterfaceMark', name,
				sprintf("Interface '%s' has invalid mark '%s'.", name, s.mark));

		id = id || ordinal;
		table_id = table_id || id;
		mark = mark || parse_mark_number(id2mask(id, mwan4.mmx_mask));

		if (mwan4.iface_max > 0 && id > mwan4.iface_max)
			validation_error('interfaceIdOutOfRange', name,
				sprintf("Interface '%s' id %d exceeds max usable id %d for mask %s.", name, id, mwan4.iface_max, mwan4.mmx_mask));
		if (mmx_mask != null && mark != null) {
			if ((mark & ~mmx_mask) != 0)
				validation_error('interfaceMarkOutsideMask', name,
					sprintf("Interface '%s' mark 0x%x is outside mwan4 mask %s.", name, mark, mwan4.mmx_mask));
			if (mark == mmx_default || mark == mmx_blackhole || mark == mmx_unreachable)
				validation_error('interfaceMarkReserved', name,
					sprintf("Interface '%s' mark 0x%x collides with a reserved mwan4 mark.", name, mark));
		}

		if (seen_ids[id])
			validation_error('duplicateInterfaceId', name,
				sprintf("Interface '%s' duplicates id %d used by '%s'.", name, id, seen_ids[id]));
		else
			seen_ids[id] = name;

		if (seen_tables[table_id])
			validation_error('duplicateTableId', name,
				sprintf("Interface '%s' duplicates table_id %d used by '%s'.", name, table_id, seen_tables[table_id]));
		else
			seen_tables[table_id] = name;

		if (mark != null) {
			let mark_key = sprintf('0x%x', mark);
			if (seen_marks[mark_key])
				validation_error('duplicateMark', name,
					sprintf("Interface '%s' duplicates mark %s used by '%s'.", name, mark_key, seen_marks[mark_key]));
			else
				seen_marks[mark_key] = name;
		}

		let has_bfd = s.bfd_peer || s.bfd_vrf || s.bfd_min_rx || s.bfd_min_tx || s.bfd_multiplier;
		if (has_bfd && !s.bfd_peer)
			validation_error('bfdPeerMissing', name,
				sprintf("Interface '%s' has BFD metadata but no bfd_peer.", name));
		if (s.bfd_peer && !endpoint_family(s.bfd_peer))
			validation_error('invalidBfdPeer', name,
				sprintf("Interface '%s' bfd_peer '%s' is not an IP address.", name, s.bfd_peer));
		if (s.bfd_vrf && !validate_device_name(s.bfd_vrf))
			validation_error('invalidBfdVrf', name,
				sprintf("Interface '%s' bfd_vrf '%s' is not a safe VRF name.", name, s.bfd_vrf));
		if (!validate_bfd_interval(s.bfd_min_rx))
			validation_error('invalidBfdMinRx', name,
				sprintf("Interface '%s' bfd_min_rx '%s' is invalid.", name, s.bfd_min_rx));
		if (!validate_bfd_interval(s.bfd_min_tx))
			validation_error('invalidBfdMinTx', name,
				sprintf("Interface '%s' bfd_min_tx '%s' is invalid.", name, s.bfd_min_tx));
		if (!validate_bfd_multiplier(s.bfd_multiplier))
			validation_error('invalidBfdMultiplier', name,
				sprintf("Interface '%s' bfd_multiplier '%s' is invalid.", name, s.bfd_multiplier));
	});

	uci_foreach('route', function(s) {
		let name = s['.name'];
		let iface = s.interface;
		counts.routes++;
		routes[name] = s;

		if (!iface || !interfaces[iface])
			validation_error('invalidRouteInterface', name,
				sprintf("Route '%s' references unknown interface '%s'.", name, iface || ''));

		if (s.metric != null && !validate_uint_range(s.metric, 1, DEFAULT_LOWEST_METRIC))
			validation_error('invalidRouteMetric', name,
				sprintf("Route '%s' metric '%s' must be 1-%d.", name, s.metric, DEFAULT_LOWEST_METRIC));
		if (s.weight != null && !validate_uint_range(s.weight, 1, 4294967295))
			validation_error('invalidRouteWeight', name,
				sprintf("Route '%s' weight '%s' must be positive.", name, s.weight));
	});

	uci_foreach('strategy', function(s) {
		let name = s['.name'];
		counts.strategies++;
		strategies[name] = s;

		for (let route in as_list(s.use_route)) {
			if (!routes[route])
				validation_error('invalidStrategyRoute', name,
					sprintf("Strategy '%s' references unknown route '%s'.", name, route));
		}

		if (s.last_resort && s.last_resort != 'default' && s.last_resort != 'unreachable' && s.last_resort != 'blackhole')
			validation_error('invalidStrategyLastResort', name,
				sprintf("Strategy '%s' has unsupported last_resort '%s'.", name, s.last_resort));
	});

	let builtin_strategies = {
		'default':     true,
		'unreachable': true,
		'blackhole':   true,
	};

	uci_foreach('rule', function(s) {
		validate_rule(s, strategies, builtin_strategies, { error: validation_error, warning: validation_warning });
		counts.rules++;
	});

	validate_rule_ids({ error: validation_error, warning: validation_warning });

	if (!dnsmasq.nftset_supported() && length(filter(ordered_rules(), s => rule_enabled(s) && length(as_list(s.domain)))))
		validation_warning('dnsmasqNftsetMissing', null, 'Domain rules need dnsmasq-full with nftset support.');

	let tunnel_context = get_tunnel_context();
	counts.tunnels = length(keys(tunnel_context.tunnels));
	for (let warning in get_tunnel_warnings(tunnel_context))
		validation_warning(warning.code, warning.interface, warning.message);

	for (let iface in keys(tunnel_context.tunnels)) {
		let meta = tunnel_context.tunnels[iface];
		if (meta.transport_type && !exists(VALID_TUNNEL_TRANSPORTS, meta.transport_type))
			validation_error('invalidTunnelTransport', iface,
				sprintf("Tunnel '%s' has unsupported transport_type '%s'.", iface, meta.transport_type));
		if (meta.underlay_strategy && !strategies[meta.underlay_strategy] && !builtin_strategies[meta.underlay_strategy])
			validation_error('invalidTunnelUnderlayStrategy', iface,
				sprintf("Tunnel '%s' references unknown underlay_strategy '%s'.", iface, meta.underlay_strategy));
		if (meta.endpoint_host && !validate_endpoint_host(meta.endpoint_host))
			validation_error('invalidTunnelEndpoint', iface,
				sprintf("Tunnel '%s' endpoint '%s' is not an IP address or hostname.", iface, meta.endpoint_host));
		if (meta.endpoint_port && !validate_uint_range(meta.endpoint_port, 1, 65535))
			validation_error('invalidTunnelEndpointPort', iface,
				sprintf("Tunnel '%s' endpoint_port '%s' must be 1-65535.", iface, meta.endpoint_port));
		if (meta.local_endpoint && endpoint_family(meta.local_endpoint) == null)
			validation_error('invalidTunnelLocalEndpoint', iface,
				sprintf("Tunnel '%s' local_endpoint '%s' is not an IP address.", iface, meta.local_endpoint));
		if (!validate_fail_mode(meta.endpoint_fail_mode))
			validation_error('invalidTunnelEndpointFailMode', iface,
				sprintf("Tunnel '%s' endpoint_fail_mode '%s' is unsupported.", iface, meta.endpoint_fail_mode));
		if (!validate_fail_mode(meta.data_fail_mode))
			validation_error('invalidTunnelDataFailMode', iface,
				sprintf("Tunnel '%s' data_fail_mode '%s' is unsupported.", iface, meta.data_fail_mode));
	}

	return {
		'valid':    length(errors) == 0,
		'errors':   errors,
		'warnings': warnings,
		'counts':   counts,
	};
}

function diagnostics_summary() {
	_ensure_init();
	let service_instances = get_service_instances();

	return {
		'version':            CONTRACT_VERSION,
		'mmx_mask':           mwan4.mmx_mask,
		'mmx_default':        mwan4.mmx_default,
		'rule_mask':          mwan4.rule_mask,
		'no_ipv6':            mwan4.no_ipv6 == 1,
		'source_routing':     mwan4.source_routing,
		'interfaces':         get_configured_interfaces(),
		'enabled_interfaces': get_interfaces(),
		'strategies':         get_strategies(),
		'tunnels':            get_tunnel_status(),
		'status':             get_status_diagnostics({ 'service_instances': service_instances }),
	};
}

function diagnostics_connections() {
	_ensure_init();
	let report = { errors: [], warnings: [] };
	validate_rule_ids({
		error:   (code, section, message) => push(report.errors, contract_problem(code, section, message)),
		warning: (code, section, message) => push(report.warnings, contract_problem(code, section, message)),
	});

	return {
		'accounting':    conntrack_accounting(),
		'rule_mask':     mwan4.rule_mask,
		'rule_capacity': rule_capacity(),
		'total':         connection_counts().total,
		'rules':         get_status_rules(),
		'interfaces':    interfaces_active(),
		'strategies':    strategies_active(),
		...report,
	};
}

function diagnostics_counters() {
	let counters = report_counters();
	let references = parse_nft_counter_references(nft_output(sprintf('list table inet %s 2>/dev/null', NFT_TABLE)));
	let unreferenced = [];
	let missing_references = [];
	let summary = summarize_counters(counters);

	for (let name in keys(counters || {}))
		if (!references[name]) push(unreferenced, name);

	for (let name in keys(references || {}))
		if (!counters[name]) push(missing_references, name);

	summary.referenced = length(keys(references || {}));
	summary.unreferenced = length(unreferenced);
	summary.missing_references = length(missing_references);

	let groups = group_counters(counters);
	let active = active_by_rule();
	for (let name in filter(keys(active), name => groups.rules[name]))
		groups.rules[name].active_connections = active[name];

	return {
		'summary':            summary,
		'groups':             groups,
		'items':              counters,
		'references':         references,
		'unreferenced':       unreferenced,
		'missing_references': missing_references,
	};
}

function diagnostics_interfaces(selected_iface) {
	let result = {};
	let runtime = get_interfaces_status({ 'interface': selected_iface }, get_service_instances());
	uci_foreach('interface', function(s) {
		let iface = s['.name'];
		if (selected_iface && selected_iface != iface)
			return;

		let families = as_list(s.family || 'ipv4');
		let tracking = {};
		for (let family in families) {
			let status_iface = sprintf('%s_%s', iface, family);
			tracking[family] = {
				'status':   read_str(sprintf('%s/%s/STATUS', TRACK_STATUS_DIR, status_iface)) || 'unknown',
				'tracking': get_mwan4track_status(iface, family),
				'hotplug':  get_iface_hotplug_state(iface),
			};
		}

		let data = {
			'enabled':  uci_bool(s.enabled),
			'families': families,
			'id':       get_iface_id(iface),
			'table_id': get_iface_table_id(iface),
			'mark':     get_iface_mark(iface),
			'track_ip': as_list(s.track_ip),
			'tracking': tracking,
			'runtime':  runtime[iface] || null,
		};

		let tunnel = get_tunnel_metadata(s);
		if (tunnel?.configured)
			data.tunnel = tunnel;

		result[iface] = data;
	});
	return result;
}

function diagnostics_routes() {
	let ipv4 = get_routes('ipv4');
	let ipv6 = mwan4.no_ipv6 == 0 ? get_routes('ipv6') : [];
	let warnings = [];

	for (let item in ipv4)
		if (index(item, 'nexthop') >= 0)
			push(warnings, { 'code': 'ecmpRoute', 'family': 'ipv4', 'route': item, 'message': 'Multipath/ECMP route detected; mwan4 currently treats routes as single-device routes.' });
	for (let item in ipv6) {
		if (index(item, 'nexthop') >= 0)
			push(warnings, { 'code': 'ecmpRoute', 'family': 'ipv6', 'route': item, 'message': 'Multipath/ECMP route detected; mwan4 currently treats routes as single-device routes.' });
		if (index(item, ' from ') >= 0)
			push(warnings, { 'code': 'sourceSpecificRoute', 'family': 'ipv6', 'route': item, 'source_routing': mwan4.source_routing, 'message': mwan4.source_routing ? 'Source-specific route is preserved.' : 'Source-specific route source selector is stripped when copying routes.' });
	}

	return {
		'ipv4': ipv4,
		'ipv6': ipv6,
		'warnings': warnings,
	};
}

function diagnostics_rules() {
	return {
		'ipv4': report_rules('ipv4'),
		'ipv6': mwan4.no_ipv6 == 0 ? report_rules('ipv6') : [],
	};
}

function diagnostics_nftables() {
	let files = {};
	let chains = detect_status_nft_chains({});
	for (let target in keys(NFT_FILES)) {
		files[target] = {
			'path':   NFT_FILES[target],
			'exists': nft_file('exists', target),
		};
	}

	return {
		'table':  NFT_TABLE,
		'chains': chains,
		'ready':  nft_chains_ready(chains),
		'files':  files,
	};
}

function diagnostics_service() {
	let service = ubus_call('service', 'list', { 'name': 'mwan4' })?.mwan4 || {};
	let instances = service.instances || {};
	let cfg = status_config_state();
	let running_trackers = [];
	let missing_trackers = [];

	for (let name in keys(instances))
		if (index(name, 'track_') == 0 && instances[name]?.running)
			push(running_trackers, name);
	for (let name in cfg.expected_trackers)
		if (index(running_trackers, name) < 0)
			push(missing_trackers, name);

	return {
		'running':           count_running_instances(instances) > 0,
		'instances_running': count_running_instances(instances),
		'trackers_running':  count_running_instances(instances, 'track_'),
		'instances':         keys(instances),
		'tracker_instances': {
			'expected': cfg.expected_trackers,
			'running':  running_trackers,
			'missing':  missing_trackers,
		},
	};
}

function diagnostics_tunnels() {
	return get_tunnel_status();
}

function diagnostics_strategies() {
	return {
		'ipv4': get_strategy_status('ipv4'),
		'ipv6': get_strategy_status('ipv6'),
	};
}

function diagnostics_ownership() {
	return get_policy_ownership();
}

function numeric_list_has(values, needle) {
	for (let value in values || [])
		if (int(value) == needle)
			return true;
	return false;
}

function mark_list_has(values, needle) {
	for (let value in values || [])
		if (parse_hex_int(value) == needle)
			return true;
	return false;
}

function pbr_rule_is_mwan4_owned(line, mark, mask, lookup, ownership) {
	if (mask != parse_hex_int(mwan4.mmx_mask))
		return false;

	if (mark_list_has(ownership.marks, mark)) {
		if (lookup != null && numeric_list_has(ownership.tables, lookup))
			return true;
		if (index(line, ' unreachable') >= 0)
			return true;
	}

	if (index(line, ' blackhole') >= 0 && mark == parse_hex_int(mwan4.mmx_blackhole))
		return true;
	if (index(line, ' unreachable') >= 0 && mark == parse_hex_int(mwan4.mmx_unreachable))
		return true;

	return false;
}

function diagnostics_pbr() {
	let ownership = get_policy_ownership();
	let config = {
		'enabled':                uci_bool(external_uci_get('pbr', 'config', 'enabled')),
		'ipv6_enabled':           uci_bool(external_uci_get('pbr', 'config', 'ipv6_enabled')),
		'fw_mask':                format_hex(external_uci_get('pbr', 'config', 'fw_mask') || '00ff0000'),
		'uplink_interface':       external_uci_get('pbr', 'config', 'uplink_interface'),
		'uplink_interface6':      external_uci_get('pbr', 'config', 'uplink_interface6'),
		'supported_interfaces':   as_list(external_uci_get('pbr', 'config', 'supported_interface')),
		'ip_rules_priority':      int(external_uci_get('pbr', 'config', 'uplink_ip_rules_priority') || '30000'),
	};
	let service = ubus_call('service', 'list', { 'name': 'pbr' })?.pbr || null;
	let rules = {
		'ipv4': cmd_lines('ip -4 rule show'),
		'ipv6': mwan4.no_ipv6 == 0 ? cmd_lines('ip -6 rule show') : [],
	};
	let warnings = [];
	let validation = [];
	let mmx = parse_hex_int(mwan4.mmx_mask);
	let pbr_mask = parse_hex_int(config.fw_mask);
	let unsupported = [];
	let manager = package_ctl.package_manager();
	let pbr_installed = manager ? package_ctl.package_installed(manager, 'pbr') : false;

	if (config.enabled && length(config.supported_interfaces)) {
		uci_foreach('interface', function(s) {
			let iface = s['.name'];
			if (!uci_bool(s.enabled)) return;
			if (index(config.supported_interfaces, iface) < 0 && iface != config.uplink_interface && iface != config.uplink_interface6)
				push(unsupported, iface);
		});
	}

	if (pbr_mask && (pbr_mask & mmx) != 0)
		push(warnings, { 'code': 'pbrMwan4MaskOverlap', 'pbr_mask': config.fw_mask, 'mwan4_mask': mwan4.mmx_mask, 'message': 'PBR fw_mask overlaps the mwan4 mark mask.' });

	push(validation, {
		'check':    'PBR package',
		'expected': 'installed',
		'observed': manager ? (pbr_installed ? 'installed' : 'missing') : 'package manager missing',
		'ok':       pbr_installed,
		'action':   'Install the PBR feature bundle before applying PBR workflow changes.',
	});

	push(validation, {
		'check':    'mark mask separation',
		'expected': sprintf('PBR mask separate from mwan4 %s', mwan4.mmx_mask),
		'observed': config.fw_mask,
		'ok':       !pbr_mask || (pbr_mask & mmx) == 0,
		'action':   'Use non-overlapping firewall mark masks for PBR and mwan4.',
	});

	push(validation, {
		'check':    'IPv6 uplink',
		'expected': config.enabled && config.ipv6_enabled ? 'uplink_interface6 set' : 'not required',
		'observed': config.uplink_interface6 || 'missing',
		'ok':       !config.enabled || !config.ipv6_enabled || !!config.uplink_interface6,
		'action':   'Set pbr.config.uplink_interface6 when PBR IPv6 routing is enabled.',
	});

	if (config.enabled && config.ipv6_enabled && !config.uplink_interface6)
		push(warnings, { 'code': 'pbrIpv6UplinkMissing', 'message': 'PBR IPv6 is enabled but uplink_interface6 is not configured.' });

	if (config.enabled && config.ipv6_enabled && length(config.supported_interfaces) && config.uplink_interface6 && index(config.supported_interfaces, config.uplink_interface6) < 0)
		push(warnings, { 'code': 'pbrIpv6UnsupportedUplink', 'interface': config.uplink_interface6, 'message': 'PBR IPv6 uplink is not listed in supported_interface.' });

	for (let iface in unsupported)
		push(warnings, { 'code': 'pbrSupportedInterfaceMissing', 'interface': iface, 'message': sprintf("Enabled mwan4 interface '%s' is not listed in PBR supported_interface.", iface) });

	push(validation, {
		'check':    'supported_interface coverage',
		'expected': 'all enabled mwan4 WAN links listed when PBR is enabled',
		'observed': length(unsupported) ? join(',', unsupported) : 'covered',
		'ok':       !length(unsupported),
		'action':   'Add missing WAN links to pbr.config.supported_interface.',
	});

	for (let family in keys(rules)) {
		for (let line in rules[family]) {
			let fwmark = match(line, /fwmark ([^\/ ]+)\/([^ ]+)/);
			if (fwmark) {
				let mark = parse_hex_int(fwmark[1]);
				let mask = parse_hex_int(fwmark[2]);
				let lookup = match(line, /lookup ([0-9]+)/);
				let table = lookup ? int(lookup[1]) : null;
				let owned = pbr_rule_is_mwan4_owned(line, mark, mask, table, ownership);

				if ((mask & mmx) != 0 && !owned)
					push(warnings, { 'code': 'markMaskOverlap', 'family': family, 'rule': line, 'message': 'A non-mwan4 fwmark rule overlaps the mwan4 mark mask.' });

				if (table != null && numeric_list_has(ownership.tables, table) && !owned)
					push(warnings, { 'code': 'tableOverlap', 'family': family, 'rule': line, 'table': table, 'message': 'A non-mwan4 fwmark rule points at a mwan4-owned table.' });
			}
		}
	}

	return {
		'config':          config,
		'package_manager': manager,
		'package_version': manager ? package_ctl.package_version(manager, 'pbr') : null,
		'validation':      validation,
		'service_running': service ? count_running_instances(service.instances || {}) > 0 : false,
		'service':         service,
		'rules':           rules,
		'warnings':        warnings,
	};
}

function normalize_mptcp_endpoint_flags(value) {
	let flags = [];
	for (let raw in as_list(value)) {
		for (let part in split(replace('' + raw, /,/g, ' '), /[ \t]+/)) {
			let flag = lc(trim(part));
			if (validate_mptcp_flag(flag) && index(flags, flag) < 0)
				push(flags, flag);
		}
	}
	return flags;
}

function mptcp_limit_value(section, option) {
	let value = section ? section[option] : null;
	if (value == null || value == '') return null;
	return validate_mptcp_limit(value) ? int(value) : null;
}

function get_mptcp_section() {
	_ensure_init();
	let section = uci_ctx?.get_all('mwan4', 'mptcp');
	return section?.['.type'] == 'mptcp' ? section : null;
}

function normalize_mptcp_endpoint_config(section, interfaces) {
	let name = section?.['.name'] || '';
	let enabled = section?.enabled == null ? true : uci_bool(section.enabled);
	let iface = trim('' + (section?.interface || ''));
	let family = normalize_family(section?.family || null);
	let address = trim('' + (section?.address || section?.addr || ''));
	let device = trim('' + (section?.device || section?.dev || ''));
	let id = trim('' + (section?.id || ''));
	let port = trim('' + (section?.port || ''));
	let flags = normalize_mptcp_endpoint_flags(section?.flag || section?.flags || section?.role || section?.roles);
	let errors = [];

	if (!validate_section_name(name))
		push(errors, contract_problem('invalidMptcpEndpointName', name,
			sprintf("MPTCP endpoint section '%s' has an unsafe name.", name || '')));

	if (!enabled)
		return {
			'name':      name,
			'enabled':   false,
			'interface': iface || null,
			'family':    family,
			'address':   address || null,
			'device':    device || null,
			'id':        id || null,
			'port':      port || null,
			'flags':     flags,
			'valid':     length(errors) == 0,
			'errors':    errors,
		};

	if (!iface || !interfaces[iface])
		push(errors, contract_problem('invalidMptcpEndpointInterface', name,
			sprintf("MPTCP endpoint '%s' references unknown WAN link '%s'.", name, iface || '')));

	if (!validate_mptcp_endpoint_id(id))
		push(errors, contract_problem('invalidMptcpEndpointId', name,
			sprintf("MPTCP endpoint '%s' must use a stable id from 1 to 255.", name)));

	if (!family && address)
		family = mptcp_address_family(address);

	if (!family && iface && interfaces[iface]) {
		let families = get_families(iface);
		family = families[0] || 'ipv4';
	}

	if (!address && iface && interfaces[iface] && family) {
		let src = get_src_ip(iface, family);
		if (src != '0.0.0.0' && src != '::')
			address = src;
	}

	if (!address || !validate_mptcp_address(address))
		push(errors, contract_problem('invalidMptcpEndpointAddress', name,
			sprintf("MPTCP endpoint '%s' needs a valid IPv4 or IPv6 address, or a WAN link with a live source address.", name)));

	if (!family && address)
		family = mptcp_address_family(address);

	if (!family)
		push(errors, contract_problem('invalidMptcpEndpointFamily', name,
			sprintf("MPTCP endpoint '%s' needs an IPv4 or IPv6 family.", name)));

	if (!length(flags))
		push(errors, contract_problem('invalidMptcpEndpointRole', name,
			sprintf("MPTCP endpoint '%s' needs at least one signal, subflow, backup, or fullmesh role.", name)));

	if (port && !validate_uint_range(port, 1, 65535))
		push(errors, contract_problem('invalidMptcpEndpointPort', name,
			sprintf("MPTCP endpoint '%s' uses an invalid port.", name)));

	if (!device && iface && interfaces[iface]) {
		let true_iface = get_true_iface(iface, family || 'ipv4');
		device = network_get_device(true_iface) || network_get_device(iface) || '';
	}

	if (device && !validate_device_name(device))
		push(errors, contract_problem('invalidMptcpEndpointDevice', name,
			sprintf("MPTCP endpoint '%s' resolves to unsafe device '%s'.", name, device)));

	return {
		'name':      name,
		'enabled':   true,
		'interface': iface || null,
		'family':    family,
		'address':   address || null,
		'device':    device || null,
		'id':        id || null,
		'port':      port || null,
		'flags':     flags,
		'valid':     length(errors) == 0,
		'errors':    errors,
	};
}

function get_mptcp_config() {
	_ensure_init();

	let section = get_mptcp_section();
	let endpoints = [];
	let interfaces = uci_section_map('interface');
	let configured = section != null;
	let limits = {
		'add_addr_accepted': mptcp_limit_value(section, 'add_addr_accepted'),
		'subflows':          mptcp_limit_value(section, 'subflows'),
	};

	uci_foreach('mptcp_endpoint', function(s) {
		configured = true;
		push(endpoints, normalize_mptcp_endpoint_config(s, interfaces));
	});

	return {
		'configured':   configured,
		'enabled':      section?.enabled ?? null,
		'enabled_bool': section?.enabled == null ? null : uci_bool(section.enabled),
		'limits':       limits,
		'endpoints':    endpoints,
	};
}

function mptcp_managed_records() {
	let raw = trim(readfile(MPTCP_STATE_FILE) || '');
	let records = [];
	if (!length(raw)) return records;

	for (let line in split(raw, '\n')) {
		let parts = split(line, '\t');
		let id = parts[0];
		if (!validate_mptcp_endpoint_id(id)) continue;
		push(records, {
			'id':      id,
			'name':    parts[1] || null,
			'address': parts[2] || null,
			'device':  parts[3] || null,
		});
	}
	return records;
}

function parse_mptcp_endpoint_line(line) {
	line = trim(line || '');
	if (!length(line)) return null;

	let parts = split(line, /[ \t]+/);
	let endpoint = {
		'raw':     line,
		'address': parts[0],
		'id':      null,
		'device':  null,
		'flags':   [],
	};

	for (let i = 1; i < length(parts); i++) {
		let token = parts[i];
		switch (token) {
		case 'id':
			if (i + 1 < length(parts)) {
				i++;
				endpoint.id = int(parts[i]);
			}
			break;
		case 'dev':
			if (i + 1 < length(parts)) {
				i++;
				endpoint.device = parts[i];
			}
			break;
		case 'flags':
			if (i + 1 < length(parts)) {
				i++;
				for (let flag in split(parts[i], ','))
					if (validate_mptcp_flag(flag) && index(endpoint.flags, lc(flag)) < 0)
						push(endpoint.flags, lc(flag));
			}
			break;
		default:
			for (let flag in split(token, ','))
				if (validate_mptcp_flag(flag) && index(endpoint.flags, lc(flag)) < 0)
					push(endpoint.flags, lc(flag));
			break;
		}
	}

	return endpoint;
}

function parse_mptcp_endpoints(out) {
	let endpoints = [];
	for (let line in split(trim(out || ''), '\n')) {
		let endpoint = parse_mptcp_endpoint_line(line);
		if (endpoint) push(endpoints, endpoint);
	}
	return endpoints;
}

function find_mptcp_endpoint_by_id(endpoints, id) {
	for (let endpoint in endpoints)
		if ('' + endpoint.id == '' + id)
			return endpoint;
	return null;
}

function remove_mptcp_managed_endpoints() {
	let live = parse_mptcp_endpoints(trim(cmd_output('ip mptcp endpoint show 2>/dev/null')));
	for (let endpoint in mptcp_managed_records()) {
		let current = find_mptcp_endpoint_by_id(live, endpoint.id);
		if (!current)
			continue;
		if (endpoint.address && current.address != endpoint.address)
			continue;
		if (endpoint.device && current.device != endpoint.device)
			continue;
		run(sprintf('ip mptcp endpoint delete id %s', shell_quote(endpoint.id)));
	}
	unlink(MPTCP_STATE_FILE);
}

function mptcp_endpoint_add_command(endpoint) {
	let parts = [ 'ip mptcp endpoint add', shell_quote(endpoint.address) ];
	if (endpoint.device) push(parts, 'dev ' + shell_quote(endpoint.device));
	push(parts, 'id ' + shell_quote(endpoint.id));
	if (endpoint.port) push(parts, 'port ' + shell_quote(endpoint.port));
	push(parts, join(' ', endpoint.flags));
	return join(' ', parts);
}

function parse_mptcp_limits(out) {
	let limits = {};
	let parts = split(trim(out || ''), /[ \t]+/);
	for (let i = 0; i < length(parts); i += 2) {
		if (i + 1 >= length(parts)) break;
		let value = parts[i + 1];
		limits[parts[i]] = match(value, /^[0-9]+$/) ? int(value) : value;
	}
	return limits;
}

function apply_mptcp_config() {
	_ensure_init();

	let config = get_mptcp_config();
	let result = {
		'configured': config.configured,
		'ok':         true,
		'sysctl':     false,
		'limits':     false,
		'endpoints':  [],
		'warnings':   [],
		'errors':     [],
	};

	if (!config.configured)
		return result;

	ensure_dir(STATUS_DIR);
	remove_mptcp_managed_endpoints();

	if (config.enabled != null) {
		writefile('/proc/sys/net/mptcp/enabled', (uci_bool(config.enabled) ? '1' : '0') + '\n');
		result.sysctl = true;
	}

	if (config.enabled_bool != null && !config.enabled_bool) {
		writefile(MPTCP_STATE_FILE, '');
		return result;
	}

	let limit_args = [];
	if (config.limits.add_addr_accepted != null)
		push(limit_args, 'add_addr_accepted ' + config.limits.add_addr_accepted);
	if (config.limits.subflows != null)
		push(limit_args, 'subflows ' + config.limits.subflows);
	if (length(limit_args)) {
		if (run('ip mptcp limits set ' + join(' ', limit_args)) == 0)
			result.limits = true;
		else
			push(result.errors, contract_problem('mptcpLimitsApplyFailed', 'mptcp', 'Unable to apply MPTCP limits with iproute2.'));
	}

	let live = parse_mptcp_endpoints(trim(cmd_output('ip mptcp endpoint show 2>/dev/null')));
	let seen_ids = {};
	let managed = [];

	for (let endpoint in config.endpoints) {
		if (!endpoint.enabled) continue;

		if (seen_ids[endpoint.id]) {
			push(result.errors, contract_problem('duplicateMptcpEndpointId', endpoint.name,
				sprintf("MPTCP endpoint '%s' reuses id '%s'.", endpoint.name, endpoint.id || '')));
			continue;
		}
		seen_ids[endpoint.id] = true;

		for (let error in endpoint.errors)
			push(result.errors, error);
		if (!endpoint.valid)
			continue;

		let conflict = find_mptcp_endpoint_by_id(live, endpoint.id);
		if (conflict) {
			push(result.warnings, contract_problem('mptcpEndpointIdInUse', endpoint.name,
				sprintf("MPTCP endpoint id '%s' is already present in kernel state; mwan4 left it unchanged to avoid taking over external state.", endpoint.id)));
			continue;
		}

		if (run(mptcp_endpoint_add_command(endpoint)) == 0) {
			push(result.endpoints, endpoint);
			push(managed, join('\t', [ endpoint.id, endpoint.name, endpoint.address || '', endpoint.device || '' ]));
		} else {
			push(result.errors, contract_problem('mptcpEndpointApplyFailed', endpoint.name,
				sprintf("Unable to add MPTCP endpoint '%s' with iproute2.", endpoint.name)));
		}
	}

	writefile(MPTCP_STATE_FILE, length(managed) ? join('\n', managed) + '\n' : '');
	result.ok = length(result.errors) == 0;
	return result;
}

function diagnostics_mptcp() {
	let enabled = read_str('/proc/sys/net/mptcp/enabled');
	let endpoints_raw = trim(cmd_output('ip mptcp endpoint show 2>/dev/null'));
	let limits_raw = trim(cmd_output('ip mptcp limits show 2>/dev/null'));
	let endpoint_details = parse_mptcp_endpoints(endpoints_raw);
	let config = get_mptcp_config();
	let warnings = [];

	if (enabled == null && !length(endpoints_raw) && !length(limits_raw))
		push(warnings, { 'code': 'mptcpUnavailable', 'message': 'Kernel or iproute2 MPTCP support is not available.' });
	else if (enabled == '1' && !length(endpoint_details))
		push(warnings, { 'code': 'mptcpNoEndpoints', 'message': 'MPTCP is enabled but no endpoints are configured.' });

	for (let endpoint in endpoint_details) {
		if (endpoint.device && !validate_device_name(endpoint.device))
			push(warnings, { 'code': 'invalidMptcpEndpointDevice', 'device': endpoint.device, 'endpoint': endpoint.raw, 'message': 'MPTCP endpoint reports an invalid device name.' });
		if (!length(endpoint.flags))
			push(warnings, { 'code': 'mptcpEndpointNoFlags', 'endpoint': endpoint.raw, 'message': 'MPTCP endpoint has no signal/subflow/backup/fullmesh flag.' });
	}

	for (let endpoint in config.endpoints) {
		for (let error in endpoint.errors)
			push(warnings, { 'code': error.code, 'endpoint': endpoint.name, 'message': error.message });
	}

	if (config.configured && config.enabled_bool && !mwan4.source_routing)
		push(warnings, { 'code': 'mptcpSourceRoutingDisabled', 'message': 'MPTCP endpoints are configured, but mwan4 source routing is disabled; subflows may leave through the wrong WAN.' });

	return {
		'enabled':          enabled,
		'enabled_bool':     enabled == '1',
		'available':        enabled != null || length(endpoints_raw) > 0 || length(limits_raw) > 0,
		'configured':       config.configured,
		'config':           config,
		'managed':          mptcp_managed_records(),
		'sysctls':          { 'net.mptcp.enabled': enabled },
		'endpoints':        length(endpoints_raw) ? split(endpoints_raw, '\n') : [],
		'endpoint_details': endpoint_details,
		'limits':           length(limits_raw) ? limits_raw : null,
		'limits_detail':    parse_mptcp_limits(limits_raw),
		'warnings':         warnings,
	};
}

function interface_quality_config(intf) {
	let method = normalize_track_method(intf.track_method || 'ping');
	let helper = track_method_helper(method);
	return {
		'interface_enabled': uci_bool(intf.enabled),
		'enabled':          uci_bool(intf.check_quality),
		'supported':        track_method_supports_quality(method),
		'track_method':     method,
		'helper':           helper,
		'helper_available': helper_available(helper),
		'reliability':      int(intf.reliability || '1'),
		'count':            int(intf.count || '1'),
		'timeout':          int(intf.timeout || '4'),
		'failure_latency':  int(intf.failure_latency || '1000'),
		'failure_loss':     int(intf.failure_loss || '40'),
		'recovery_latency': int(intf.recovery_latency || '500'),
		'recovery_loss':    int(intf.recovery_loss || '10'),
	};
}

function diagnostics_quality(selected_iface) {
	let result = {
		'summary': {
			'interfaces':  0,
			'enabled':     0,
			'supported':   0,
			'unsupported': 0,
		},
		'interfaces': {},
		'warnings':   [],
	};

	uci_foreach('interface', function(intf) {
		let iface = intf['.name'];
		if (selected_iface && selected_iface != iface)
			return;

		let cfg = interface_quality_config(intf);
		result.interfaces[iface] = cfg;
		result.summary.interfaces++;
		if (cfg.enabled) result.summary.enabled++;
		if (cfg.supported) result.summary.supported++;
		else result.summary.unsupported++;

		if (cfg.interface_enabled && cfg.enabled && !cfg.supported)
			push(result.warnings, { 'code': 'qualityUnsupportedMethod', 'interface': iface, 'track_method': cfg.track_method, 'message': sprintf("Interface '%s' enables quality checks with unsupported track_method '%s'.", iface, cfg.track_method) });
		if (cfg.interface_enabled && cfg.helper && !cfg.helper_available)
			push(result.warnings, { 'code': 'probeHelperMissing', 'interface': iface, 'helper': cfg.helper, 'track_method': cfg.track_method, 'message': sprintf("Probe helper '%s' for interface '%s' is not installed or not in PATH.", cfg.helper, iface) });
	});

	return result;
}

function probe_state_counts_empty() {
	return {
		'targets':  0,
		'up':       0,
		'down':     0,
		'skipped':  0,
		'unknown':  0,
		'measured': 0,
	};
}

function probe_state_counts_add(counts, probe) {
	counts.targets++;
	if (exists(counts, probe.status))
		counts[probe.status]++;
	else
		counts.unknown++;
	if (probe.measured)
		counts.measured++;
}

function parse_json_safe(text) {
	text = trim(text || '');
	if (!length(text)) return null;

	try {
		return json(text);
	} catch (e) {
		return null;
	}
}

function object_first(object, names) {
	if (type(object) != 'object') return null;
	for (let name in names) {
		let value = object[name];
		if (value != null && value != '') return value;
	}
	return null;
}

function bfd_session_row(value, peer_hint) {
	if (type(value) != 'object') return null;

	let explicit_peer = object_first(value, ['peer', 'peer_addr', 'peerAddress', 'remote', 'remoteAddress', 'address', 'dst']);
	let state = object_first(value, ['status', 'state', 'sessionState', 'local_state', 'remote_state']);
	let device = object_first(value, ['interface', 'ifname', 'iface', 'device', 'dev']);
	let vrf = object_first(value, ['vrf', 'vrfName', 'vrfname']);

	if (!explicit_peer && !state && !device && !vrf)
		return null;

	return {
		'peer':      explicit_peer || peer_hint || null,
		'state':     state || null,
		'interface': device || null,
		'vrf':       vrf || null,
	};
}

function append_bfd_session_rows(rows, value, peer_hint) {
	switch (type(value)) {
	case 'array':
		for (let item in value)
			append_bfd_session_rows(rows, item, peer_hint);
		break;
	case 'object': {
		let row = bfd_session_row(value, peer_hint);
		if (row) {
			push(rows, row);
			break;
		}

		for (let name in keys(value))
			append_bfd_session_rows(rows, value[name], name);
		break;
	}
	}
}

function diagnostics_bfd() {
	let available = helper_available('vtysh');
	let raw_json = available ? trim(cmd_output("vtysh -c 'show bfd peers json' 2>/dev/null")) : '';
	let parsed = parse_json_safe(raw_json);
	let sessions = [];
	let configured = [];
	let warnings = [];

	if (parsed) {
		append_bfd_session_rows(sessions, parsed, null);
	} else if (length(raw_json)) {
		push(warnings, { 'code': 'bfdJsonParseFailed', 'message': 'FRR BFD output was not valid JSON.' });
	}

	uci_foreach('interface', function(intf) {
		let peer = intf.bfd_peer;
		if (!peer) return;
		let iface = intf['.name'];
		let device = network_get_device(iface);
		let found = false;
		for (let session in sessions)
			if (session.peer == peer || (device && session.interface == device))
				found = true;
		push(configured, {
			'interface':   iface,
			'device':      device || null,
			'peer':        peer,
			'vrf':         intf.bfd_vrf || null,
			'min_rx':      intf.bfd_min_rx || null,
			'min_tx':      intf.bfd_min_tx || null,
			'multiplier':  intf.bfd_multiplier || null,
			'live_match':  found,
		});
		if (available && !found)
			push(warnings, { 'code': 'bfdConfiguredSessionMissing', 'interface': iface, 'peer': peer, 'message': sprintf("Interface '%s' has BFD metadata for peer '%s', but no matching live BFD session was reported.", iface, peer) });
	});

	return {
		'available':       available,
		'schema':          BFD_SCHEMA,
		'configured':      configured,
		'sessions':        sessions,
		'session_count':   length(sessions),
		'service':         available ? ubus_call('service', 'list', { 'name': 'frr' })?.frr || null : null,
		'warnings':        warnings,
	};
}

function diagnostics_probes(selected_iface) {
	let result = {
		'summary':    probe_state_counts_empty(),
		'interfaces': {},
		'helpers':    probe_helper_statuses(),
		'bfd':        diagnostics_bfd(),
		'warnings':   [],
	};

	uci_foreach('interface', function(intf) {
		let iface = intf['.name'];
		if (selected_iface && selected_iface != iface)
			return;

		let method = normalize_track_method(intf.track_method || 'ping');
		let helper = method == 'ping' ? 'ping' : track_method_helper(method);
		let helper_ok = track_method_available(method);

		let iface_data = {
			'summary':           probe_state_counts_empty(),
			'families':          {},
			'track_method':      method,
			'helper':            helper,
			'helper_available':  helper_ok,
			'quality_supported': track_method_supports_quality(method),
		};

		if (uci_bool(intf.enabled) && !helper_ok)
			push(result.warnings, { 'code': 'probeHelperMissing', 'interface': iface, 'helper': helper, 'track_method': method, 'message': sprintf("Probe helper '%s' for interface '%s' is not installed or not in PATH.", helper, iface) });

		for (let family in get_families(iface)) {
			let status_iface = sprintf('%s_%s', iface, family);
			let family_data = {
				'summary': probe_state_counts_empty(),
				'targets': [],
			};

			for (let target in as_list(intf.track_ip)) {
				let latency = read_int_nullable(sprintf('%s/%s/LATENCY_%s', TRACK_STATUS_DIR, status_iface, target));
				let loss = read_int_nullable(sprintf('%s/%s/LOSS_%s', TRACK_STATUS_DIR, status_iface, target));
				let probe = {
					'target':     target,
					'status':     read_str(sprintf('%s/%s/TRACK_%s', TRACK_STATUS_DIR, status_iface, target)) || 'unknown',
					'latency':    latency,
					'packetloss': loss,
					'measured':   latency != null || loss != null,
				};
				push(family_data.targets, probe);
				probe_state_counts_add(family_data.summary, probe);
				probe_state_counts_add(iface_data.summary, probe);
				probe_state_counts_add(result.summary, probe);
			}

			iface_data.families[family] = family_data;
		}

		result.interfaces[iface] = iface_data;
	});

	return result;
}

function parse_vrf_devices(out) {
	let devices = [];
	let current = null;

	for (let line in split(out || '', '\n')) {
		let dev = match(line, /^[0-9]+: ([^:@]+)(@[^:]+)?:/);
		if (dev) {
			current = {
				'name':  dev[1],
				'table': null,
				'raw':   trim(line),
			};
			push(devices, current);
		}

		let table = match(line, /\bvrf table ([0-9]+)/);
		if (table && current)
			current.table = int(table[1]);
	}

	return devices;
}

function link_master(out) {
	let m = match(out || '', / master ([^ ]+)/);
	return m ? m[1] : null;
}

function vrf_table_routes(devices) {
	let result = {};

	for (let vrf in devices) {
		if (vrf.table == null) continue;
		result[vrf.name] = {
			'table': vrf.table,
			'ipv4':  cmd_lines(sprintf('ip -4 route show table %d', vrf.table)),
			'ipv6':  mwan4.no_ipv6 == 0 ? cmd_lines(sprintf('ip -6 route show table %d', vrf.table)) : [],
		};
	}

	return result;
}

function diagnostics_vrf(selected_iface) {
	let devices = parse_vrf_devices(cmd_output('ip -d link show type vrf 2>/dev/null'));
	let rules = {
		'ipv4': cmd_lines('ip -4 rule show'),
		'ipv6': mwan4.no_ipv6 == 0 ? cmd_lines('ip -6 rule show') : [],
	};
	let interfaces = {};
	let l3mdev_rules = {
		'ipv4': [],
		'ipv6': [],
	};
	let tables = {};
	let warnings = [];
	let validation = [];
	let ownership = get_policy_ownership();
	let has_l3mdev_rule = false;

	for (let family in keys(rules))
		for (let rule in rules[family])
			if (index(rule, 'l3mdev') >= 0) {
				has_l3mdev_rule = true;
				push(l3mdev_rules[family], rule);
			}

	for (let vrf in devices)
		if (vrf.name != null)
			tables[vrf.name] = vrf.table;

	for (let vrf in devices)
		if (vrf.table != null && index(ownership.tables, vrf.table) >= 0)
			push(warnings, { 'code': 'vrfTableOverlap', 'vrf': vrf.name, 'table': vrf.table, 'message': sprintf("VRF '%s' uses mwan4-owned table %d.", vrf.name, vrf.table) });

	if (length(devices) && !has_l3mdev_rule)
		push(warnings, { 'code': 'vrfL3mdevRuleMissing', 'message': 'VRF devices exist, but no l3mdev ip rule was found.' });

	push(validation, {
		'check':    'l3mdev rule',
		'expected': length(devices) ? 'present' : 'not required',
		'observed': has_l3mdev_rule ? 'present' : 'missing',
		'ok':       !length(devices) || has_l3mdev_rule,
		'action':   'Install/enable VRF support so netifd creates l3mdev rules.',
	});

	uci_foreach('interface', function(intf) {
		let iface = intf['.name'];
		if (selected_iface && selected_iface != iface)
			return;

		let device = network_get_device(iface);
		let detail = device ? cmd_output(sprintf('ip -d link show dev %s 2>/dev/null', shell_quote(device))) : '';
		let master = link_master(detail);
		interfaces[iface] = {
			'device': device || null,
			'master': master,
			'table':  master ? tables[master] || null : null,
		};

		if (intf.table_id && master)
			push(validation, {
				'check':     sprintf('table binding for %s', iface),
				'interface': iface,
				'expected':  int(intf.table_id),
				'observed':  tables[master] || null,
				'ok':        int(intf.table_id) == int(tables[master] || 0),
				'action':    'Align mwan4 table_id with the VRF routing table.',
			});
		else if (intf.table_id && !master)
			push(validation, {
				'check':     sprintf('table metadata for %s', iface),
				'interface': iface,
				'expected':  'ordinary mwan4 table metadata or VRF member',
				'observed':  device ? 'no VRF master' : 'no device',
				'ok':        true,
				'action':    'No action required unless this WAN is intended to be enslaved to a VRF.',
			});
	});

	return {
		'devices':         devices,
		'rules':           rules,
		'l3mdev_rules':    l3mdev_rules,
		'tables':          vrf_table_routes(devices),
		'l3mdev_rule':     has_l3mdev_rule,
		'interfaces':      interfaces,
		'validation':      validation,
		'warnings':        warnings,
	};
}

function diagnostics_tunnels_advanced() {
	let context = get_tunnel_context();
	let exemptions = {};
	for (let iface in keys(context.tunnels || {}))
		exemptions[iface] = tunnel_exemption_command(context.tunnels[iface]);
	return {
		'interfaces': context.tunnels,
		'warnings':   get_tunnel_warnings(context),
		'endpoints':  tunnel_endpoint_diagnostics(context),
		'recursion':  tunnel_recursion_diagnostics(context),
		'exemptions': exemptions,
	};
}

function explain_family(args) {
	let family = normalize_family(args.family);
	if (family) return family;
	let dest = args.dest_ip || args.destination || '';
	return index(dest, ':') >= 0 ? 'ipv6' : 'ipv4';
}

function ipv4_to_number(addr) {
	let parts = split(addr, '.');
	if (length(parts) != 4) return null;
	return int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3]);
}

function ipv4_prefix_match(addr, prefix) {
	let bits = split(prefix, '/');
	if (length(bits) < 1 || length(bits) > 2 || !bits[0]) return false;
	if (length(bits) == 2 && !match(bits[1], /^[0-9]+$/)) return false;
	let width = length(bits) == 1 ? 32 : int(bits[1]);
	if (width == 0) return true;
	let addr_num = ipv4_to_number(addr);
	let net_num = ipv4_to_number(bits[0]);
	if (addr_num == null || net_num == null) return false;
	let block = 1;
	for (let i = 0; i < 32 - width; i++)
		block *= 2;
	return int(addr_num / block) == int(net_num / block);
}

function ipv6_hextets(text) {
	let values = [];
	if (!length(text)) return values;

	for (let part in split(text, ':')) {
		if (!match(part, /^[0-9a-fA-F]{1,4}$/)) return null;
		push(values, parse_hex_int(part));
	}

	return values;
}

function ipv6_to_words(addr) {
	if (!addr || index(addr, ':::') >= 0) return null;

	let pos = index(addr, '::');
	if (pos < 0) {
		let words = ipv6_hextets(addr);
		return words && length(words) == 8 ? words : null;
	}

	if (index(substr(addr, pos + 2), '::') >= 0) return null;

	let left    = ipv6_hextets(substr(addr, 0, pos));
	let right   = ipv6_hextets(substr(addr, pos + 2));
	let words   = [];
	let missing = 8 - length(left || []) - length(right || []);

	if (!left || !right || missing < 1) return null;

	for (let word in left) push(words, word);
	for (let i = 0; i < missing; i++) push(words, 0);
	for (let word in right) push(words, word);

	return length(words) == 8 ? words : null;
}

function ipv6_prefix_match(addr, prefix) {
	let bits = split(prefix, '/');
	if (length(bits) < 1 || length(bits) > 2 || !bits[0]) return false;
	if (length(bits) == 2 && !match(bits[1], /^[0-9]+$/)) return false;
	let width = length(bits) == 1 ? 128 : int(bits[1]);
	if (width < 0 || width > 128) return false;
	if (width == 0) return true;

	let addr_words = ipv6_to_words(addr);
	let net_words  = ipv6_to_words(bits[0]);
	if (!addr_words || !net_words) return false;

	let full_words = int(width / 16);
	let rem_bits   = width - (full_words * 16);
	for (let i = 0; i < full_words; i++) {
		if (addr_words[i] != net_words[i]) return false;
	}

	if (!rem_bits) return true;

	let block = 1;
	for (let i = 0; i < 16 - rem_bits; i++)
		block *= 2;
	return int(addr_words[full_words] / block) == int(net_words[full_words] / block);
}

function address_match(actual, expected, family) {
	if (!expected)
		return true;
	if (!actual)
		return false;
	if (family == 'ipv4')
		return ipv4_prefix_match(actual, expected);
	if (family == 'ipv6')
		return ipv6_prefix_match(actual, expected);
	return lc(actual) == lc(expected);
}

function address_list_match(actual, expected, family) {
	let candidates = as_list(expected);
	return !length(candidates) || length(filter(candidates, e => address_match(actual, e, family))) > 0;
}

function port_match(actual, expected) {
	expected = normalize_ports(expected);
	if (expected == null) return false;
	if (!length(expected)) return true;
	if (actual == null || actual == '') return false;

	let actual_text = '' + actual;
	let actual_num = match(actual_text, /^[0-9]+$/) ? int(actual_text) : null;
	for (let item in split(expected, ',')) {
		let range = match(item, /^([0-9]+)-([0-9]+)$/);
		if (range && actual_num != null && actual_num >= int(range[1]) && actual_num <= int(range[2]))
			return true;
		if (actual_text == item)
			return true;
		if (actual_num != null && match(item, /^[0-9]+$/) && actual_num == int(item))
			return true;
	}

	return false;
}

function rule_family_matches(rule, family) {
	let families = as_list(rule.family);
	if (!length(families)) return true;
	return index(families, family) >= 0;
}

function explain_rule_match(rule, family, input, stats) {
	let matched = true;
	let checks = {};
	let proto = normalize_protocol(rule.proto || 'all') || 'all';
	let input_proto = normalize_protocol(input.proto || 'all') || 'all';

	function add_check(name, ok, expected, actual) {
		checks[name] = {
			'matched':  ok,
			'expected': expected || null,
			'actual':   actual || null,
		};
		if (!ok) matched = false;
	}

	add_check('family', rule_family_matches(rule, family), join(',', as_list(rule.family)), family);
	if (proto != 'all')
		add_check('proto', proto == input_proto, proto, input_proto);
	if (!rule_enabled(rule))
		add_check('enabled', false, 'enabled', 'disabled');
	if (rule.src_ip)
		add_check('src_ip', address_list_match(input.src_ip, rule.src_ip, family), join(',', as_list(rule.src_ip)), input.src_ip);
	if (rule.dest_ip)
		add_check('dest_ip', address_list_match(input.dest_ip, rule.dest_ip, family), join(',', as_list(rule.dest_ip)), input.dest_ip);
	if (rule.src_iface)
		add_check('src_iface', rule.src_iface == input.src_iface, rule.src_iface, input.src_iface);
	if (rule.src_port)
		add_check('src_port', port_match(input.src_port, rule.src_port), rule.src_port, input.src_port);
	if (rule.dest_port)
		add_check('dest_port', port_match(input.dest_port, rule.dest_port), rule.dest_port, input.dest_port);
	if (rule.ipset)
		add_check('ipset', input.ipset == rule.ipset, rule.ipset, input.ipset);
	if (!rule.use_strategy)
		add_check('use_strategy', false, 'configured strategy', null);

	return {
		'rule':               rule['.name'],
		'family':             family,
		'matched':            matched,
		'use_strategy':       rule.use_strategy || null,
		'checks':             checks,
		'rule_id':            stats.id,
		'new_connections':    stats.new_connections,
		'active_connections': stats.active_connections,
	};
}

function builtin_decision(name) {
	switch (name) {
	case 'default':
		return { 'type': 'builtin', 'strategy': name, 'mark': mwan4.mmx_default, 'status': 'default' };
	case 'blackhole':
		return { 'type': 'builtin', 'strategy': name, 'mark': mwan4.mmx_blackhole, 'status': 'blackhole' };
	case 'unreachable':
		return { 'type': 'builtin', 'strategy': name, 'mark': mwan4.mmx_unreachable, 'status': 'unreachable' };
	}
	return null;
}

function explain_strategy_decision(strategy_name, family) {
	let builtin = builtin_decision(strategy_name);
	if (builtin) return builtin;

	let strategies = uci_section_map('strategy');
	let routes = uci_section_map('route');
	let strategy = strategies[strategy_name];
	let candidates = [];
	if (!strategy)
		return { 'type': 'missing_strategy', 'strategy': strategy_name, 'status': 'missing', 'candidates': candidates };

	for (let route_name in as_list(strategy.use_route)) {
		let route = routes[route_name];
		if (!route) continue;
		let iface = route.interface;
		if (!iface || index(get_families(iface), family) < 0)
			continue;
		let state = get_iface_hotplug_state(iface);
		push(candidates, {
			'route':     route_name,
			'interface': iface,
			'family':    family,
			'metric':    int(route.metric || '1'),
			'weight':    int(route.weight || '1'),
			'enabled':   uci_bool(uci_get(iface, 'enabled')),
			'state':     state,
			'online':    state == 'online',
			'mark':      get_iface_mark(iface),
			'table_id':  get_iface_table_id(iface),
			'device':    network_get_device(iface) || null,
		});
	}

	let active = filter(candidates, c => c.online);
	sort(active, (a, b) => a.metric - b.metric);
	if (length(active)) {
		let lowest = active[0].metric;
		let selected = filter(active, c => c.metric == lowest);
		return {
			'type':       'strategy',
			'strategy':   strategy_name,
			'family':     family,
			'status':     'active',
			'selection':  length(selected) > 1 ? 'weighted' : 'single',
			'selected':   selected[0],
			'active':     selected,
			'candidates': candidates,
		};
	}

	let fallback = filter(candidates, c => c.device);
	let last_resort = strategy.last_resort || 'unreachable';
	return {
		'type':        'strategy',
		'strategy':    strategy_name,
		'family':      family,
		'status':      length(fallback) ? 'fallback' : 'last_resort',
		'fallback':    fallback,
		'last_resort': builtin_decision(last_resort) || builtin_decision('unreachable'),
		'candidates':  candidates,
	};
}

function diagnostics_explain(args) {
	args = args || {};
	let family = explain_family(args);
	let input = {
		'family':    family,
		'src_ip':    args.src_ip || null,
		'dest_ip':   args.dest_ip || args.destination || null,
		'proto':     normalize_protocol(args.proto || 'all') || 'all',
		'src_port':  args.src_port || null,
		'dest_port': args.dest_port || null,
		'src_iface': args.src_iface || args.interface || null,
		'ipset':     args.ipset || null,
	};
	let rules = [];
	let matched_rule = null;

	let stats = get_status_rules();
	for (let rule in ordered_rules()) {
		let explanation = explain_rule_match(rule, family, input, stats[rule['.name']]);
		push(rules, explanation);
		if (!matched_rule && explanation.matched)
			matched_rule = explanation;
	}

	let strategy = args.strategy || matched_rule?.use_strategy || null;
	let decision = strategy ? explain_strategy_decision(strategy, family) : {
		'type':   'no_match',
		'status': 'default',
		'mark':   mwan4.mmx_default,
	};

	return {
		'input':        input,
		'matched_rule': matched_rule,
		'decision':     decision,
		'rules':        rules,
	};
}

function get_diagnostics(args) {
	_ensure_init();
	args = args || {};

	let section = args.section || 'all';
	let result = {};
	let errors = [];

	if (section == 'all' || section == 'summary')
		result.summary = diagnostics_summary();
	if (section == 'all' || section == 'interfaces')
		result.interfaces = diagnostics_interfaces(args.interface);
	if (section == 'all' || section == 'routes')
		result.routes = diagnostics_routes();
	if (section == 'all' || section == 'rules')
		result.rules = diagnostics_rules();
	if (section == 'all' || section == 'connections')
		result.connections = diagnostics_connections();
	if (section == 'all' || section == 'strategies')
		result.strategies = diagnostics_strategies();
	if (section == 'all' || section == 'nftables')
		result.nftables = diagnostics_nftables();
	if (section == 'all' || section == 'service')
		result.service = diagnostics_service();
	if (section == 'all' || section == 'tunnels')
		result.tunnels = diagnostics_tunnels_advanced();
	if (section == 'all' || section == 'counters')
		result.counters = diagnostics_counters();
	if (section == 'all' || section == 'ownership')
		result.ownership = diagnostics_ownership();
	if (section == 'all' || section == 'pbr')
		result.pbr = diagnostics_pbr();
	if (section == 'all' || section == 'mptcp')
		result.mptcp = diagnostics_mptcp();
	if (section == 'all' || section == 'quality')
		result.quality = diagnostics_quality(args.interface);
	if (section == 'all' || section == 'probes')
		result.probes = diagnostics_probes(args.interface);
	if (section == 'all' || section == 'vrf')
		result.vrf = diagnostics_vrf(args.interface);
	if (section == 'all' || section == 'explain')
		result.explain = diagnostics_explain(args);
	if (section == 'all' || section == 'packages')
		result.packages = package_ctl.diagnostics_packages();

	if (!length(keys(result)))
		push(errors, contract_problem('invalidSection', section,
			sprintf("Unknown diagnostics section '%s'.", section)));

	return {
		'diagnostics': result,
		'errors':      errors,
	};
}

function configured_interface(iface) {
	if (!validate_section_name(iface))
		return false;
	return !!uci_section_map('interface')[iface];
}

function service_control(action) {
	switch (action) {
	case 'start':
		return system('/etc/init.d/mwan4 enable && /etc/init.d/mwan4 start');
	case 'stop':
		return system('/etc/init.d/mwan4 disable && /etc/init.d/mwan4 stop');
	case 'restart':
		return system('/etc/init.d/mwan4 enable && /etc/init.d/mwan4 restart');
	case 'reload':
		return system('/etc/init.d/mwan4 reload');
	}
	return 1;
}

function reset_counters_control() {
	return system(sprintf('nft reset counters inet %s >/dev/null 2>&1', NFT_TABLE));
}

function apply_bfd_control() {
	let errors = [];
	let commands = [];

	if (!helper_available('vtysh'))
		push(errors, contract_problem('bfdHelperMissing', 'bfd',
			'FRR vtysh is not installed or not in PATH.'));

	let rc = run('/etc/init.d/frr reload');
	push(commands, '/etc/init.d/frr reload');
	if (rc != 0) {
		rc = run('/etc/init.d/frr restart');
		push(commands, '/etc/init.d/frr restart');
	}

	if (rc != 0)
		push(errors, contract_problem('bfdReloadFailed', 'bfd',
			'Unable to reload or restart FRR for BFD.'));

	return {
		'ok':       length(errors) == 0,
		'commands': commands,
		'errors':   errors,
	};
}

function control_dispatch(args, allowed_actions) {
	_ensure_init();
	args = args || {};

	let action = args.action;
	let iface = args.interface;
	let errors = [];

	if (index(allowed_actions, action) < 0) {
		push(errors, contract_problem('invalidAction', action,
			sprintf("Unsupported control action '%s'.", action || '')));
		return {
			'ok':     false,
			'action': action || null,
			'errors': errors,
		};
	}

	if (action == 'ifup' || action == 'ifdown') {
		if (!configured_interface(iface)) {
			push(errors, contract_problem('invalidInterface', iface,
				sprintf("Unknown or unsafe interface '%s'.", iface || '')));
			return {
				'ok':        false,
				'action':    action,
				'interface': iface || null,
				'errors':    errors,
			};
		}

		if (action == 'ifup') {
			ifup(iface, 'rpcd');
		} else {
			interface_hotplug_shutdown(iface, true);
		}

		return {
			'ok':        true,
			'action':    action,
			'interface': iface,
			'errors':    errors,
		};
	}

	if (action == 'reset_counters') {
		let rc = reset_counters_control();
		if (rc != 0)
			push(errors, contract_problem('commandFailed', action,
				sprintf("Control action '%s' failed with exit code %d.", action, rc)));

		return {
			'ok':     length(errors) == 0,
			'action': action,
			'errors': errors,
		};
	}

	if (action == 'install_feature') {
		let result = package_ctl.install_feature_packages(args.feature);
		result.action = action;
		return result;
	}

	if (action == 'wireguard_keygen') {
		let result = generate_wireguard_keypair();
		result.action = action;
		return result;
	}

	if (action == 'apply_tunnel_exemptions') {
		let result = apply_tunnel_exemptions(iface);
		result.action = action;
		return result;
	}

	if (action == 'apply_bfd') {
		let result = apply_bfd_control();
		result.action = action;
		return result;
	}

	let rc = service_control(action);
	if (rc != 0)
		push(errors, contract_problem('commandFailed', action,
			sprintf("Control action '%s' failed with exit code %d.", action, rc)));

	return {
		'ok':     length(errors) == 0,
		'action': action,
		'errors': errors,
	};
}

function control(args) {
	return control_dispatch(args, RUNTIME_CONTROL_ACTIONS);
}

function advanced_control(args) {
	return control_dispatch(args, ADVANCED_CONTROL_ACTIONS);
}

// ── Method Assignment ────────────────────────────────────────────────

mwan4.pkg = pkg;

mwan4.STATUS_DIR = STATUS_DIR;
mwan4.TRACK_STATUS_DIR = TRACK_STATUS_DIR;

// Core
mwan4.init = init;
mwan4.load = load;
mwan4.reload = reload;
mwan4.id2mask = id2mask;
mwan4.LOG = LOG;
mwan4.set_scriptname = set_scriptname;
mwan4.read_str = read_str;
mwan4.read_int = read_int;
mwan4.cmd_lines = cmd_lines;
mwan4.nft_file = nft_file;
mwan4.nft_output = nft_output;
mwan4.ubus_call = ubus_call;

// UCI
mwan4.uci_bool = uci_bool;
mwan4.uci_get = uci_get;
mwan4.uci_get_list = uci_get_list;
mwan4.uci_foreach = uci_foreach;

// Validation
mwan4.shell_quote                 = shell_quote;
mwan4.validate_section_name       = validate_section_name;
mwan4.validate_family             = validate_family;
mwan4.validate_track_method_name  = validate_track_method_name;
mwan4.validate_track_target       = validate_track_target;
mwan4.validate_route_table_lookup = validate_route_table_lookup;
mwan4.validate_protocol           = validate_protocol;
mwan4.validate_ports              = validate_ports;
mwan4.validate_loglevel           = validate_loglevel;
mwan4.validate_mptcp_endpoint_id  = validate_mptcp_endpoint_id;
mwan4.validate_mptcp_address      = validate_mptcp_address;
mwan4.validate_mptcp_flag         = validate_mptcp_flag;
mwan4.validate_nft_identifier     = validate_nft_identifier;
mwan4.validate_device_name        = validate_device_name;
mwan4.validate_mac                = validate_mac;
mwan4.validate_dscp               = validate_dscp;
mwan4.validate_hostname           = validate_hostname;
mwan4.validate_rule_address       = validate_rule_address;
mwan4.uci_section_names           = uci_section_names;

// Getters
mwan4.get_families = get_families;
mwan4.foreach_family = foreach_family;
mwan4.get_true_iface = get_true_iface;
mwan4.get_src_ip = get_src_ip;
mwan4.get_iface_id = get_iface_id;
mwan4.get_iface_table_id = get_iface_table_id;
mwan4.get_iface_hotplug_state = get_iface_hotplug_state;
mwan4.get_mwan4track_status = get_mwan4track_status;
mwan4.get_tunnel_metadata = get_tunnel_metadata;
mwan4.get_tunnel_status = get_tunnel_status;
mwan4.get_tunnel_warnings = get_tunnel_warnings;
mwan4.get_uptime = get_uptime;
mwan4.get_online_time = get_online_time;
mwan4.get_routes = get_routes;

// Table mapping
mwan4.update_iface_to_table = update_iface_to_table;
mwan4.update_dev_to_table = update_dev_to_table;
mwan4.route_line_dev = route_line_dev;

// Hotplug state
mwan4.set_iface_hotplug_state = set_iface_hotplug_state;
mwan4.init_iface_hotplug_states = init_iface_hotplug_states;

// nftables generation
mwan4.set_general_rules = set_general_rules;
mwan4.set_general_nftables = set_general_nftables;
mwan4.set_custom_nftset = set_custom_nftset;
mwan4.set_connected_ipv4 = set_connected_ipv4;
mwan4.set_connected_ipv6 = set_connected_ipv6;
mwan4.set_dynamic_nftset = set_dynamic_nftset;
mwan4.rebuild_iface_nftfile = rebuild_iface_nftfile;
mwan4.set_strategies_nftables = set_strategies_nftables;
mwan4.assign_rule_ids = assign_rule_ids;
mwan4.ensure_rule_ids = ensure_rule_ids;
mwan4.collect_user_rules = collect_user_rules;
mwan4.set_user_rules = set_user_rules;
mwan4.sync_dnsmasq = sync_dnsmasq;
mwan4.prefetch_domains = prefetch_domains;
mwan4.rebuild_dynamic = rebuild_dynamic;

// Interface management
mwan4.create_iface_route = create_iface_route;
mwan4.needs_default_route = needs_default_route;
mwan4.delete_iface_route = delete_iface_route;
mwan4.create_iface_rules = create_iface_rules;
mwan4.delete_iface_rules = delete_iface_rules;

// Reload & utilities
mwan4.fw4_reload = fw4_reload;
mwan4.file_exists = file_exists;

// Consumer API
mwan4.is_interface = is_interface;
mwan4.get_iface_mark = get_iface_mark;
mwan4.get_policy_ownership = get_policy_ownership;
mwan4.persist_policy_ownership = persist_policy_ownership;
mwan4.get_installed_policy_ownership = get_installed_policy_ownership;
mwan4.get_iface_chain = get_iface_chain;
mwan4.get_strategy_chain = get_strategy_chain;
mwan4.get_interfaces = get_interfaces;
mwan4.get_configured_interfaces = get_configured_interfaces;
mwan4.get_strategies = get_strategies;

// Backend contract
mwan4.get_capabilities = get_capabilities;
mwan4.validate_config = validate_config;
mwan4.get_diagnostics = get_diagnostics;
mwan4.control = control;
mwan4.advanced_control = advanced_control;

// Reporting
mwan4.report_iface_status = report_iface_status;
mwan4.get_strategies_data = get_strategies_data;
mwan4.get_strategy_status = get_strategy_status;
mwan4.get_status = get_status;
mwan4.report_strategies = report_strategies;
mwan4.report_connected = report_connected;
mwan4.report_rules = report_rules;
mwan4.report_tunnels = report_tunnels;
mwan4.report_counters = report_counters;
mwan4.get_connections = get_connections;
mwan4.get_status_rules = get_status_rules;
mwan4.summarize_counters = summarize_counters;
mwan4.get_status_diagnostics = get_status_diagnostics;
mwan4.report_status_diagnostics = report_status_diagnostics;

// MPTCP management
mwan4.get_mptcp_config = get_mptcp_config;
mwan4.apply_mptcp_config = apply_mptcp_config;
mwan4.remove_mptcp_managed_endpoints = remove_mptcp_managed_endpoints;

// Lifecycle
mwan4.interface_hotplug_shutdown = interface_hotplug_shutdown;
mwan4.interface_shutdown = interface_shutdown;
mwan4.ifup = ifup;
mwan4.flush_conntrack = flush_conntrack;
mwan4.track_clean = track_clean;

export default mwan4;
