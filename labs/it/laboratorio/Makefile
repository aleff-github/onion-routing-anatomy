# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Gestione del laboratorio Tor privato tramite Docker; --network host condivide la rete dell'host.
IMMAGINE ?= torlibro-lab:latest
NOME     = torlibro-rete
RETE     = libro
DOCKER   = docker run --rm --network host -v $(CURDIR):/lab -u $(shell id -u):$(shell id -g) $(IMMAGINE)

.PHONY: immagine avvia verifica stato ferma shell pulisci guardia

# Dietro un proxy HTTPS che re-termina TLS: make immagine PROXY_CA=/percorso/ca.crt
# (rete dell'host per la build, https_proxy passato come argomento, CA come segreto).
PROXY_CA ?=
SEGRETO_CA = id=proxy_ca,src=$(PROXY_CA)
OPZIONI_PROXY = $(if $(PROXY_CA),--network host --build-arg https_proxy=$(or $(https_proxy),$(HTTPS_PROXY)) \
                  --secret $(SEGRETO_CA))

immagine:
	docker build $(OPZIONI_PROXY) -t $(IMMAGINE) .

# Chutney apre i listener anche su [::1]: su un host senza IPv6 (alcuni ambienti cloud)
# tor non parte ("Address family not supported"). In quel caso lo si dice a Chutney con
# CHUTNEY_DISABLE_IPV6, impostata sul container e quindi valida per ogni docker exec.
IPV6 := $(shell python3 -c 'import socket; socket.socket(socket.AF_INET6).bind(("::1", 0))' 2>/dev/null && echo si)
OPZIONI_IPV6 = $(if $(IPV6),,-e CHUTNEY_DISABLE_IPV6=1)

# Gli exit risolvono i nomi solo con il resolver della rete privata (dns_locale.py,
# 127.0.0.1:5300), mai con quello dell'host: CHUTNEY_DNS_CONF diventa il loro
# ServerDNSResolvConfFile.
OPZIONI_DNS = -e CHUTNEY_DNS_CONF=/lab/dns_locale.conf

# --init: il processo 1 del container raccoglie i processi terminati. Senza, ogni tor
# fermato resta zombie figlio di «sleep infinity», chutney stop non riesce a fermarlo e
# lo scambio di verifica-lab-bridge non può confermare l'arresto della rete.
# Configura e avvia la rete, poi attende il bootstrap (container in background).
avvia: guardia
	docker run -d --init --name $(NOME) --network host -v $(CURDIR):/lab $(OPZIONI_IPV6) $(OPZIONI_DNS) \
	  -u $(shell id -u):$(shell id -g) $(IMMAGINE) sleep infinity
	docker exec $(NOME) chutney init --net-from-script-path /lab/chutney/networks/$(RETE)
	docker exec $(NOME) chutney bootstrap
	# Chutney crea net/nodes con un percorso assoluto valido solo nel container.
	cd net && ln -sfn $$(ls -d nodes.* | tail -1) nodes

verifica:
	docker exec $(NOME) chutney verify

stato:
	docker exec $(NOME) chutney status

shell:
	docker exec -it $(NOME) bash

ferma:
	-docker exec $(NOME) chutney stop
	-docker rm -f $(NOME)

pulisci: guardia ferma
	rm -rf net

# Uno scambio di make verifica-lab-bridge interrotto: net/ può contenere la rete bridge e
# net-libro/ la rete libro. Prima si ripristina (docs/it/procedura-laboratori-dal-vivo.md, §8).
guardia:
	@test ! -e verifica-bridge.stato -a ! -e net-libro || { \
	  echo "scambio di verifica-lab-bridge interrotto (verifica-bridge.stato o net-libro presenti):"; \
	  echo "ripristina la rete libro prima di continuare"; exit 1; }
