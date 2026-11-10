# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratory 20 (Chapter 30): Arti configuration for the book's private network.
# Read the identities and ports of the three authorities from node files and write lab/net/arti/arti.toml.
# Same choices as Chutney (lib/chutney/arti/config.py): authorities and network fallbacks,
# allow local addresses, and disable subnet restrictions because all nodes use 127.0.0.1.
import re
from pathlib import Path

LAB = Path(__file__).resolve().parent / "net"
NODES = LAB / "nodes"
ARTI = LAB / "arti"
VOTING_INTERVAL_SECONDS = 20             # V3AuthVotingInterval of the laboratory network


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
        raise ValueError(f"Expected exactly three private authorities; found {len(authorities)}")
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
