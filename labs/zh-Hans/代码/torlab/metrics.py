# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 15：根据公开文档计算网络统计信息。

本模块提供两项功能：共识摘要（中继、标志、带宽、版本、/16 网络）
和 Tor Metrics 用户数估计（目录请求数量 / 10）。
"""
from __future__ import annotations

import math
from collections import Counter

from .directory import Consensus
from .path_selection import network16


def summary(consensus: Consensus) -> dict:
    """汇总单个共识；总带宽权重为零时，占比返回 None。"""
    relay = consensus.relay
    bandwidth = sum(r.bandwidth or 0 for r in relay)
    flag = Counter(f for r in relay for f in r.flag)
    exit_ = [r for r in relay if "Exit" in r.flag and "BadExit" not in r.flag]
    guard = [r for r in relay if "Guard" in r.flag]
    return {
        "relay": len(relay),
        # 使用确定性顺序：计数相同时按名称排序，避免不同 Python 运行
        # 的集合遍历顺序导致结果变化
        "flag": dict(sorted(flag.items(), key=lambda x: (-x[1], x[0]))),
        "total_bandwidth": bandwidth,
        "exit_bandwidth_share": (sum(r.bandwidth or 0 for r in exit_) / bandwidth
                                 if bandwidth > 0 else None),
        "guard_bandwidth_share": (sum(r.bandwidth or 0 for r in guard) / bandwidth
                                  if bandwidth > 0 else None),
        "versions": sorted(Counter(" ".join(r.version.split()[:2]) for r in relay).items(),
                            key=lambda x: (-x[1], x[0]))[:5],
        "networks16": sorted(Counter(network16(r) for r in relay).items(),
                         key=lambda x: (-x[1], x[0]))[:5],
    }


def estimate_users(reported_requests: int, fraction: float) -> int | None:
    """根据每日目录请求估算平均同时在线的 Tor 客户端数量。

    r(N) = floor(r(R) / frac / 10)；覆盖比例须为 10%–110%。
    这是估算，不是独立用户人数的直接计数。
    """
    if isinstance(reported_requests, bool) or not isinstance(reported_requests, int) or reported_requests < 0:
        raise ValueError("目录请求次数必须为非负整数")
    if isinstance(fraction, bool) or not isinstance(fraction, (int, float)):
        return None
    if not math.isfinite(fraction):
        return None
    if not 0.10 <= fraction <= 1.10:
        return None
    return math.floor(reported_requests / fraction / 10)


def remove_rounding(value: int, step: int = 8) -> int | None:
    """对向上取整的计数减去正偶数步长的一半。

    dirreq-v3-reqs 使用步长 8；计数过小时返回 None。
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("计数值必须为非负整数")
    if isinstance(step, bool) or not isinstance(step, int) or step <= 0 or step % 2:
        raise ValueError("舍入步长必须为正偶整数")
    v = value - step // 2
    return v if v > 0 else None


if __name__ == "__main__":
    import sys
    from .directory import parse_consensus
    with open(sys.argv[1], encoding="utf-8") as source:
        c = parse_consensus(source.read())
    labels = {
        "relay": "中继数量",
        "flag": "标志",
        "total_bandwidth": "带宽权重总和",
        "exit_bandwidth_share": "出口中继带宽权重占比",
        "guard_bandwidth_share": "入口守卫带宽权重占比",
        "versions": "版本",
        "networks16": "/16 网络",
    }
    for k, v in summary(c).items():
        print(f"{labels.get(k, k)}: {v}")
