# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# 实验 20（第 30 章）：为本书私有网络生成 Arti 配置。
# 从节点文件中读取三个权威节点的身份与端口，生成 实验室/net/arti/arti.toml。
# 与 Chutney（lib/chutney/arti/config.py）采用相同配置：权威节点与后备缓存，
# 允许本地地址；所有节点均为 127.0.0.1，故关闭子网约束。
import re
from pathlib import Path

LAB = Path(__file__).resolve().parent / "net"
NODES = LAB / "nodes"
ARTI = LAB / "arti"
VOTING_INTERVAL_SECONDS = 20             # 实验网络的 V3AuthVotingInterval


def authorities_from_network():
    for d in sorted(NODES.glob("00?a")):
        rsa = (d / "fingerprint").read_text().split()[1]
        ed = (d / "fingerprint-ed25519").read_text().split()[1]
        v3 = re.search(r"^fingerprint (\w+)", (d / "keys" / "authority_certificate").read_text(), re.M).group(1)
        torrc = (d / "torrc").read_text()
        orport = re.search(r"^OrPort \S*?:?(\d+)$", torrc, re.M).group(1)
        dirport = re.search(r"^DirPort (\d+)$", torrc, re.M).group(1)
        yield rsa, ed, v3, orport, dirport


def main():
    authorities = list(authorities_from_network())
    if len(authorities) != 3:
        raise ValueError(f"预期三个私有目录权威节点，实际找到 {len(authorities)} 个")
    format_list = lambda xs: "[" + ", ".join(xs) + "]"
    lines = [
        "[proxy]", "socks_listen = 9150", "",
        "[storage]", f'cache_dir = "{ARTI}/cache"', f'state_dir = "{ARTI}/state"',
        f'port_info_file = "{ARTI}/state/public/port_info.json"', "",
        "[path_rules]", "ipv4_subnet_family_prefix = 33", "ipv6_subnet_family_prefix = 129", "",
        "[address_filter]", "allow_local_addrs = true", "",
        "[override_net_params]", f"hsdir_interval = {12 * 2 * VOTING_INTERVAL_SECONDS // 60}", "",
        "[tor_network]",
        "fallback_caches = [",
        *[f'  {{ rsa_identity = "{rsa}", ed_identity = "{ed}", orports = ["127.0.0.1:{orp}"] }},'
          for rsa, ed, _, orp, _ in authorities],
        "]", "",
        "[tor_network.authorities]",
        "v3idents = " + format_list(f'"{a[2]}"' for a in authorities),
    ]
    ports = format_list(f'["127.0.0.1:{a[4]}"]' for a in authorities)
    lines += [f"uploads = {ports}", f"downloads = {ports}", f"votes = {ports}", ""]
    ARTI.mkdir(exist_ok=True)
    (ARTI / "arti.toml").write_text("\n".join(lines))
    print(ARTI / "arti.toml")


if __name__ == "__main__":
    main()
