# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Лабораторная работа 11 (глава 18): наблюдение изоляции потоков через Stem.
import re, subprocess, time
from stem import StreamStatus
from stem.control import Controller, EventType

DESTINATION = "127.0.0.1:8080"
SOCKS = "127.0.0.1:9008"

assigned, warnings = [], []


def on_stream(ev):
    # Учитывать только потоки к нашему адресу: Tor также открывает служебные потоки
    # для запросов к каталогам, которые исказили бы подсчёт.
    if ev.status == StreamStatus.SUCCEEDED and ev.target == DESTINATION:
        assigned.append((ev.id, ev.circ_id, ev.target))


def tunnel(c, circ: str) -> str:
    """Цепь может входить в набор Conflux (две связанные ветви; глава 31);
    в этом случае изоляция применяется к набору, а не к отдельной ветви."""
    for row in c.get_info("circuit-status").splitlines():
        if row.split(" ", 1)[0] == circ:
            r = re.search(r"CONFLUX_ID=(\w+)", row)
            return f"conflux {r.group(1)[:8]}" if r else f"цепь {circ}"
    return f"цепь {circ}"


def wait_for_tunnel(c, seconds=30):
    """Ждать, пока Tor не построит хотя бы один полный набор Conflux из двух ветвей."""
    for _ in range(seconds * 2):
        sets = re.findall(r"^\d+ BUILT .*CONFLUX_ID=(\w+)", c.get_info("circuit-status"), re.M)
        if any(sets.count(x) >= 2 for x in sets):
            return
        time.sleep(0.5)


def request(c, credentials=None):
    """Выполнить запрос и вернуть цепь, использованную Tor.
    Использовать последнее событие: после неудачной попытки Tor может повторить поток
    через другую цепь и выдать ещё одно событие SUCCEEDED."""
    assigned.clear()
    cmd = ["curl", "--noproxy", "", "-s", "-o", "/dev/null", "--socks5-hostname", SOCKS, f"http://{DESTINATION}/"]
    if credentials:
        cmd[1:1] = ["--proxy-user", credentials]
    subprocess.run(cmd, check=True)
    for _ in range(20):
        time.sleep(0.5)
        if assigned:
            break
    if not assigned:
        return "?", []
    circ = assigned[-1][1]
    return tunnel(c, circ), [x[1] for x in c.get_circuit(circ).path]


def newnym(c, announce=False):
    """NEWNYM принимается не чаще одного раза в 10 секунд (MAX_SIGNEWNYM_RATE в
    src/core/mainloop/mainloop.c); более ранний запрос задерживается и записывается в журнал.
    Нужно дождаться фактического применения, иначе событие может произойти посреди тестов."""
    warnings.clear()
    c.signal("NEWNYM")
    time.sleep(2)
    for m in list(warnings):
        r = re.search(r"Rate limiting NEWNYM request: delaying by (\d+) second", m)
        if r:
            if announce:
                print(f"(NEWNYM задержан на {r.group(1)} с)")
            time.sleep(int(r.group(1)) + 1)


with Controller.from_port(port=8008) as c:
    c.authenticate()
    c.add_event_listener(on_stream, EventType.STREAM)
    c.add_event_listener(lambda ev: warnings.append(ev.message), EventType.NOTICE)
    newnym(c)                       # начать с новых цепей без отложенного NEWNYM
    wait_for_tunnel(c)             # и дождаться хотя бы одного готового набора цепей
                                     # иначе первые запросы могут попасть в разные новые цепи
    for credentials in ["site-a.example:x1", "site-a.example:x1", "site-b.example:x2", None]:
        circ, path = request(c, credentials)
        name = credentials.split(":")[0] if credentials else "-"
        print(f"учётные данные {name:15s} -> {circ:22s} {path}")
    newnym(c, announce=True)
    circ, _ = request(c, "site-a.example:x1")
    print(f"после NEWNYM, site-a.example -> {circ}")
