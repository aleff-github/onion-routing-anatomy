# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Лаборатория Tor книги работает через Docker; --network host разделяет сетевое пространство хоста.
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
	# Chutney создаёт net/nodes как абсолютный путь, действительный только внутри контейнера.
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
