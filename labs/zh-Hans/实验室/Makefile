# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# 通过 Docker 运行本书的私有实验网络 Tor；--network host 与主机共享网络命名空间。
IMAGE   ?= torbook-lab:latest
NAME     = torbook-network
NETWORK ?= book
DOCKER   = docker run --rm --network host -v $(CURDIR):/lab -u $(shell id -u):$(shell id -g) $(IMAGE)

.PHONY: image start verify status stop shell clean

image:
	docker build -t $(IMAGE) .

start:
	docker run -d --name $(NAME) --network host -v $(CURDIR):/lab \
	  -u $(shell id -u):$(shell id -g) $(IMAGE) sleep infinity
	docker exec $(NAME) chutney init --net-from-script-path /lab/chutney/networks/$(NETWORK)
	docker exec $(NAME) chutney bootstrap
	# Chutney 创建的 net/nodes 是只在容器内有效的绝对路径。
	cd net && ln -sfn $$(ls -d nodes.* | tail -1) nodes

verify:
	docker exec $(NAME) chutney verify

status:
	docker exec $(NAME) chutney status

shell:
	docker exec -it $(NAME) bash

stop:
	-docker exec $(NAME) chutney stop
	-docker rm -f $(NAME)

clean: stop
	rm -rf net
