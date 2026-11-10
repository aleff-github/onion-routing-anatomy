# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Red privada de Tor de la edición española; nombres exclusivos de imagen y contenedor.
# --network host comparte la red del anfitrión: no ofrece aislamiento; no iniciar otros idiomas a la vez.
IMAGE   ?= torbook-es-lab:latest
NAME     = torbook-es-network
NETWORK ?= book

.PHONY: image preflight start verify status shell stop clean puente-pruebas puente-estado puente-http puente-sondeo puente-captura aislamiento-pruebas aislamiento descubrimiento-pruebas descubrimiento politica-salida-pruebas politica-salida correlacion-pruebas correlacion relay-early-pruebas relay-early fuga-dns-pruebas fuga-dns arti-config-pruebas arti-config

image:
	docker build -t $(IMAGE) .

# Preflight limitado: prueba conexiones TCP IPv4 en 127.0.0.1; no inspecciona UDP,
# todos los enlaces ni evita cambios de ocupación entre comprobación y arranque.
# El puerto 4747 se reserva para el servicio onion del laboratorio.
preflight:
	@python3 -c 'import socket,sys; ports=list(range(5100,5112))+list(range(7100,7112))+list(range(8000,8012))+list(range(9000,9012))+[4747,9909,8095]; busy=[]; exec("for p in ports:\n s=socket.socket(); s.settimeout(0.15); occupied=(s.connect_ex((\"127.0.0.1\",p))==0); s.close(); busy.extend([p] if occupied else [])"); print("Puertos ocupados; detén la red en conflicto: "+", ".join(map(str,busy)) if busy else "Puertos de laboratorio libres"); sys.exit(bool(busy))'

start: preflight
	# Si init/bootstrap falla, revisar el contenedor y net/: no hay rollback automático.
	docker run -d --name $(NAME) --network host -v $(CURDIR):/lab \
	  -u $(shell id -u):$(shell id -g) $(IMAGE) sleep infinity
	docker exec $(NAME) chutney init --net-from-script-path /lab/chutney/networks/$(NETWORK)
	docker exec $(NAME) chutney bootstrap
	# Chutney crea el enlace net/nodes con una ruta absoluta interna al contenedor.
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
	# Destruye claves e identidades de laboratorio generadas en net/.
	rm -rf net

# El laboratorio 10 usa la topología book-bridge, ya definida en Chutney.
# Son objetivos independientes: las pruebas pytest son offline; los experimentos
# de red exigen la topología privada activa y dependencias del host cuando corresponda.
puente-pruebas:
	PYTHONPATH=. python3 -m pytest -q test_puente_obfs4.py

puente-estado:
	python3 puente_obfs4.py estado

puente-http:
	python3 puente_obfs4.py http

puente-sondeo:
	python3 puente_obfs4.py sondeo

puente-captura:
	python3 puente_obfs4.py analizar --archivo "$(or $(ARCHIVO),b1.pcap)"

# Laboratorio 11: prueba offline y experimento con Stem dentro del contenedor privado.
aislamiento-pruebas:
	PYTHONPATH=. python3 -m pytest -q test_aislamiento.py

aislamiento:
	docker exec -w /lab $(NAME) python3 /lab/aislamiento.py

# Laboratorio 13: autorización X25519 de un servicio onion efímero.
descubrimiento-pruebas:
	PYTHONPATH=. python3 -m pytest -q test_descubrimiento_restringido.py

descubrimiento:
	python3 descubrimiento_restringido.py

# Laboratorio 14: reglas de salida temporales solo en el repetidor privado 006e.
politica-salida-pruebas:
	PYTHONPATH=../codigo:. python3 -m pytest -q test_politica_salida.py

politica-salida:
	PYTHONPATH=../codigo python3 politica_salida.py

# Laboratorio 16: tráfico sintético por la red privada.
correlacion-pruebas:
	PYTHONPATH=. python3 -m pytest -q test_correlacion.py

correlacion:
	docker exec -w /lab $(NAME) python3 /lab/correlacion.py $(or $(SEMILLA),3)

# Laboratorio 17: 8/9 RELAY_EARLY contra el repetidor privado 004r.
relay-early-pruebas:
	PYTHONPATH=../codigo:. python3 -m pytest -q test_relay_early.py

relay-early:
	PYTHONPATH=../codigo python3 relay_early.py $(or $(CANTIDADES),8 9)

# Laboratorio 18: diagnóstico SOCKS local; los avisos no prueban una fuga DNS real.
fuga-dns-pruebas:
	PYTHONPATH=. python3 -m pytest -q test_fuga_dns.py

fuga-dns:
	docker exec -w /lab $(NAME) python3 /lab/fuga_dns.py

# Laboratorio 20: generación offline de TOML para Arti; no compila Rust.
arti-config-pruebas:
	PYTHONPATH=. python3 -m pytest -q test_arti_config.py

arti-config:
	python3 arti_config.py
