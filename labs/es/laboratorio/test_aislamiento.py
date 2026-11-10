# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Pruebas offline de las reglas del experimento de aislamiento (sin Stem ni Tor)."""
from types import SimpleNamespace

import aislamiento as lab


def test_solo_se_aceptan_flujos_del_destino_local():
    correcto = SimpleNamespace(status="SUCCEEDED", target=lab.DESTINO)
    otro = SimpleNamespace(status="SUCCEEDED", target="127.0.0.1:9999")
    intento = SimpleNamespace(status="NEW", target=lab.DESTINO)
    assert lab.es_flujo_de_prueba(correcto)
    assert not lab.es_flujo_de_prueba(otro)
    assert not lab.es_flujo_de_prueba(intento)
    assert not lab.es_flujo_de_prueba(SimpleNamespace(status="FAILED", target=lab.DESTINO))
    assert not lab.es_flujo_de_prueba(SimpleNamespace(target=lab.DESTINO))
    assert not lab.es_flujo_de_prueba(SimpleNamespace(status="SUCCEEDED"))


def test_conflux_identifica_tunel_logico():
    estado = ("4 BUILT PURPOSE=GENERAL CONFLUX_ID=ABCDEF123456\n"
              "5 BUILT PURPOSE=GENERAL CONFLUX_ID=ABCDEF123456\n"
              "6 BUILT PURPOSE=GENERAL\n")
    assert lab.nombre_tunel(estado, "4") == "conflux ABCDEF12"
    assert lab.nombre_tunel(estado, "5") == "conflux ABCDEF12"
    assert lab.nombre_tunel(estado, "6") == "circuito 6"
    assert lab.nombre_tunel(estado, "7") == "circuito 7"
    assert lab.hay_conflux_completo(estado)


def test_un_solo_circuito_con_conflux_no_es_par_completo():
    assert not lab.hay_conflux_completo("4 BUILT CONFLUX_ID=ABCDEF\n")
    assert not lab.hay_conflux_completo("4 BUILT\n5 BUILT\n")
    assert not lab.hay_conflux_completo("4 BUILT CONFLUX_ID=ABCDEF\n5 LAUNCHED CONFLUX_ID=ABCDEF\n")
    assert not lab.hay_conflux_completo("4 BUILT CONFLUX_ID=ABCDEF\n5 BUILT CONFLUX_ID=123456\n")


def test_retraso_de_newnym():
    assert lab.segundos_retraso_newnym("Rate limiting NEWNYM request: delaying by 6 seconds") == 6
    assert lab.segundos_retraso_newnym("Rate limiting NEWNYM request: delaying by 1 second") == 1
    assert lab.segundos_retraso_newnym("Bootstrapped 100%") == 0


def test_aislamiento_cumple_invariantes():
    resultado = lab.validar_resultados(
        ["conflux AAAAAAAA", "conflux AAAAAAAA", "conflux BBBBBBBB", "conflux CCCCCCCC"],
        "conflux DDDDDDDD",
    )
    assert all(resultado.values())


def test_aislamiento_detecta_reutilizacion_incorrecta():
    resultado = lab.validar_resultados(
        ["conflux AAAAAAAA", "conflux AAAAAAAA", "conflux AAAAAAAA", "conflux CCCCCCCC"],
        "conflux DDDDDDDD",
    )
    assert not resultado["aislamiento"]
    assert resultado["reutilización"]


def test_aislamiento_detecta_newnym_sin_cambio():
    resultado = lab.validar_resultados(
        ["circuito 4", "circuito 4", "circuito 5", "circuito 6"], "circuito 4"
    )
    assert not resultado["NEWNYM"]


def test_sin_eventos_no_se_afirma_exito():
    resultado = lab.validar_resultados(["?", "?", "?", "?"], "?")
    assert not any(resultado.values())


def test_aislamiento_detecta_falta_de_aislamiento_sin_credenciales():
    resultado = lab.validar_resultados(
        ["conflux AAAAAAAA", "conflux AAAAAAAA", "conflux BBBBBBBB", "conflux AAAAAAAA"],
        "conflux CCCCCCCC",
    )
    assert resultado["reutilización"]
    assert resultado["aislamiento"]
    assert not resultado["sin credenciales"]
    assert resultado["NEWNYM"]


def test_resultados_incompletos_nunca_son_validos():
    for etiquetas, despues in (
        (["circuito 1", "circuito 1", "circuito 2"], "circuito 3"),
        (["circuito 1", "circuito 1", "circuito 2", "circuito 3"], "?"),
    ):
        assert not any(lab.validar_resultados(etiquetas, despues).values())


def test_solicitud_usa_socks_privado_y_ultimo_evento(monkeypatch):
    asignaciones = [("anterior", "99", lab.DESTINO)]
    comandos = []
    controlador = SimpleNamespace(
        get_info=lambda clave: "4 BUILT PURPOSE=GENERAL\n5 BUILT PURPOSE=GENERAL\n",
        get_circuit=lambda circuito: SimpleNamespace(path=[("a", "003r"), ("b", "004r")]),
    )

    def simular_curl(comando, **opciones):
        comandos.append((comando, opciones))
        # Simula un flujo reintentado: seleccionar el último evento SUCCEEDED.
        asignaciones.extend([("intento", "4", lab.DESTINO), ("final", "5", lab.DESTINO)])

    monkeypatch.setattr(lab.subprocess, "run", simular_curl)
    tunel, ruta = lab.solicitar(controlador, asignaciones, "site-a.example:x1")
    assert (tunel, ruta) == ("circuito 5", ["003r", "004r"])
    comando, opciones = comandos[0]
    assert comando[comando.index("--noproxy") + 1] == ""
    assert comando[comando.index("--socks5-hostname") + 1] == lab.SOCKS
    assert comando[comando.index("--proxy-user") + 1] == "site-a.example:x1"
    assert comando[-1] == "http://127.0.0.1:8080/"
    assert opciones["check"] and opciones["timeout"] == 20


def test_solicitud_sin_eventos_no_inventa_circuito(monkeypatch):
    llamadas = []
    asignaciones = []
    controlador = SimpleNamespace()
    monkeypatch.setattr(lab.subprocess, "run", lambda *a, **k: llamadas.append(a))
    monkeypatch.setattr(lab.time, "sleep", lambda segundos: None)
    assert lab.solicitar(controlador, asignaciones) == ("?", [])
    assert len(llamadas) == 1


def test_newnym_respeta_aviso_de_aplazamiento(monkeypatch):
    avisos = ["aviso obsoleto"]
    esperas = []

    def enviar_senal(nombre):
        assert nombre == "NEWNYM"
        avisos.append("Rate limiting NEWNYM request: delaying by 6 seconds")

    monkeypatch.setattr(lab.time, "sleep", esperas.append)
    lab.nueva_identidad(SimpleNamespace(signal=enviar_senal), avisos)
    assert esperas == [2, 7]
    assert len(avisos) == 1
