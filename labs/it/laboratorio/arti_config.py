# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratorio 20 (capitolo 30): configurazione di Arti per la rete privata del libro.
# Legge identità e porte delle tre autorità dai file dei nodi e scrive laboratorio/net/arti/arti.toml.
# Stesse scelte di Chutney (lib/chutney/arti/config.py): autorità e fallback della rete
# privata, indirizzi locali ammessi, nessun vincolo di subnet (tutti i nodi sono su 127.0.0.1).
import re
from pathlib import Path

LAB = Path(__file__).resolve().parent / "net"
NODI = LAB / "nodes"
ARTI = LAB / "arti"
VOTO_SECONDI = 20                       # V3AuthVotingInterval della rete di laboratorio


def autorita():
    for d in sorted(NODI.glob("00?a")):
        rsa = (d / "fingerprint").read_text().split()[1]
        ed = (d / "fingerprint-ed25519").read_text().split()[1]
        v3 = re.search(r"^fingerprint (\w+)", (d / "keys" / "authority_certificate").read_text(), re.M).group(1)
        torrc = (d / "torrc").read_text()
        orport = re.search(r"^OrPort \S*?:?(\d+)$", torrc, re.M).group(1)
        dirport = re.search(r"^DirPort \S*?:?(\d+)$", torrc, re.M).group(1)
        yield rsa, ed, v3, orport, dirport


def main():
    auts = list(autorita())
    if len(auts) != 3:
        raise ValueError(f"Attese tre autorità private, trovate {len(auts)}")
    lista = lambda xs: "[" + ", ".join(xs) + "]"
    righe = [
        "[proxy]", "socks_listen = 9150", "",
        "[storage]", f'cache_dir = "{ARTI}/cache"', f'state_dir = "{ARTI}/state"',
        f'port_info_file = "{ARTI}/state/public/port_info.json"', "",
        "[path_rules]", "ipv4_subnet_family_prefix = 33", "ipv6_subnet_family_prefix = 129", "",
        "[address_filter]", "allow_local_addrs = true", "",
        "[override_net_params]", f"hsdir_interval = {12 * 2 * VOTO_SECONDI // 60}", "",
        "[tor_network]",
        "fallback_caches = [",
        *[f'  {{ rsa_identity = "{rsa}", ed_identity = "{ed}", orports = ["127.0.0.1:{orp}"] }},'
          for rsa, ed, _, orp, _ in auts],
        "]", "",
        "[tor_network.authorities]",
        "v3idents = " + lista(f'"{a[2]}"' for a in auts),
    ]
    porte = lista(f'["127.0.0.1:{a[4]}"]' for a in auts)
    righe += [f"uploads = {porte}", f"downloads = {porte}", f"votes = {porte}", ""]
    ARTI.mkdir(exist_ok=True)
    (ARTI / "arti.toml").write_text("\n".join(righe))
    print(ARTI / "arti.toml")


if __name__ == "__main__":
    main()
