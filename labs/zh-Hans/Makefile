# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# 简体中文实验环境
.PHONY: test data image start verify status stop clean

# `test` 仅执行 torlab 单元测试，不会运行书中的全部实验。
test:
	PYTHONPATH=代码 python3 -m pytest -q 代码/torlab/test

# `data` 按需经 HTTPS 下载 CollecTor 历史数据；仅检查格式头，不验证签名。
data:
	sh fetch-public-data.sh

image:
	$(MAKE) -C 实验室 image

start:
	$(MAKE) -C 实验室 start

# `verify` 运行 torlab 测试及 Chutney 网络验证，并非执行全部 20 个实验。
verify:
	$(MAKE) test
	$(MAKE) -C 实验室 verify

status:
	$(MAKE) -C 实验室 status

stop:
	$(MAKE) -C 实验室 stop

# `clean` 将删除 实验室/net，包括生成的私钥和节点身份。
clean:
	$(MAKE) -C 实验室 clean
