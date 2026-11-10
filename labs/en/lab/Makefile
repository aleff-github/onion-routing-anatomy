# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Run the book's private Tor lab via Docker; --network host shares the host network namespace.
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
	# Chutney creates net/nodes as an absolute path valid only inside the container.
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
