# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Edición española: entrada para las pruebas y la red privada.
# Ejecutar desde un checkout completo; las dependencias deben instalarse aparte.
.PHONY: test data image start verify status stop clean

# Pruebas pytest sin experimentos activos; NO equivalen a validar los 20 laboratorios.
# Los objetivos especializados se ejecutan en laboratorio/ con rutas Python propias.
test:
	PYTHONPATH=codigo python3 -m pytest -q codigo/torlab/test
	$(MAKE) -C laboratorio puente-pruebas
	$(MAKE) -C laboratorio aislamiento-pruebas
	$(MAKE) -C laboratorio descubrimiento-pruebas
	$(MAKE) -C laboratorio politica-salida-pruebas
	$(MAKE) -C laboratorio correlacion-pruebas
	$(MAKE) -C laboratorio relay-early-pruebas
	$(MAKE) -C laboratorio fuga-dns-pruebas
	$(MAKE) -C laboratorio arti-config-pruebas

# Datos históricos públicos para los laboratorios 7, 15 y 19.
# Descarga HTTPS opcional y explícita; la cabecera no autentica las firmas del consenso.
data:
	sh fetch-public-data.sh

# Construye una imagen Docker y puede descargar dependencias del exterior.
image:
	$(MAKE) -C laboratorio image

# Delega en laboratorio/start: preflight TCP limitado, topología privada Chutney y red host.
# --network host NO aísla los puertos: no iniciar a la vez otras ediciones.
start:
	$(MAKE) -C laboratorio start

# Ejecuta pytest + verificación Chutney; NO ejecuta todos los experimentos.
# Es necesario haber iniciado la red privada para que Chutney pueda verificarla.
verify:
	$(MAKE) test
	$(MAKE) -C laboratorio verify

status:
	$(MAKE) -C laboratorio status

stop:
	$(MAKE) -C laboratorio stop

# DESTRUCTIVO: laboratorio/clean detiene la red y borra laboratorio/net/, claves e identidades incluidas.
# No usar como reinicio inocuo; preservar antes los datos que se deban conservar.
clean:
	$(MAKE) -C laboratorio clean
