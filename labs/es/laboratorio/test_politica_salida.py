# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Pruebas offline del orden de políticas y la interpretación de mensajes END."""
from pathlib import Path
from types import SimpleNamespace

import pytest

import politica_salida as lab
from torlab.cells import RelayCommand
from politica_salida import (
    PUERTO_BLOQUEADO, PUERTO_CERRADO, PUERTO_PERMITIDO,
    comprobar_destino, evaluar_resultados, insertar_regla_rechazo, resultado_relay,
)


def test_rechazo_se_inserta_antes_de_reglas_existentes():
    original = "ORPort 5106\nExitPolicy accept 127.0.0.0/8:*\nExitPolicy reject *:*\n"
    modificado = insertar_regla_rechazo(original)
    assert modificado.startswith("ORPort 5106\nExitPolicy reject 127.0.0.1:8080\nExitPolicy accept")
    assert modificado.endswith("ExitPolicy reject *:*\n")


def test_no_modifica_configuracion_sin_exitpolicy():
    with pytest.raises(ValueError, match="ExitPolicy"):
        insertar_regla_rechazo("ORPort 5106\n")


def test_rechaza_una_segunda_regla_identica():
    with pytest.raises(ValueError, match="Ya existe"):
        insertar_regla_rechazo("ExitPolicy reject 127.0.0.1:8080\n")


def test_mensaje_connected():
    assert resultado_relay(RelayCommand.CONNECTED, b"") == "CONNECTED"


def test_end_exitpolicy_incluye_direccion_y_ttl():
    datos = bytes([4, 127, 0, 0, 1]) + (1800).to_bytes(4, "big")
    assert resultado_relay(RelayCommand.END, datos) == (
        "END motivo=EXITPOLICY dirección=127.0.0.1 TTL=1800"
    )


def test_end_sin_servidor():
    assert resultado_relay(RelayCommand.END, b"\x01") == "END motivo=MISC"
    assert resultado_relay(RelayCommand.END, b"\x03") == "END motivo=CONNECTREFUSED"


def test_tres_invariantes_y_cambio_de_version_tor():
    resultados = {
        PUERTO_BLOQUEADO: "END motivo=EXITPOLICY dirección=127.0.0.1 TTL=1800",
        PUERTO_PERMITIDO: "CONNECTED",
        PUERTO_CERRADO: "END motivo=MISC",
    }
    assert all(evaluar_resultados(resultados).values())
    resultados[PUERTO_CERRADO] = "END motivo=CONNECTREFUSED"
    assert all(evaluar_resultados(resultados).values())
    resultados[PUERTO_PERMITIDO] = "END motivo=EXITPOLICY"
    assert not evaluar_resultados(resultados)["permitido"]


def test_no_permite_destinos_fuera_del_laboratorio():
    with pytest.raises(ValueError):
        comprobar_destino(443)


@pytest.mark.parametrize("puerto", [-1, 0, 65536])
def test_insercion_rechaza_puertos_fuera_de_rango(puerto):
    with pytest.raises(ValueError, match="rango TCP"):
        insertar_regla_rechazo("ExitPolicy accept 127.0.0.0/8:*\n", puerto)


def test_inserta_una_regla_alternativa_antes_del_primer_exitpolicy():
    original = "# Regla de prueba\nExitPolicy accept 127.0.0.0/8:*\n"
    modificado = insertar_regla_rechazo(original, 8082)
    assert modificado == (
        "# Regla de prueba\nExitPolicy reject 127.0.0.1:8082\n"
        "ExitPolicy accept 127.0.0.0/8:*\n"
    )


def test_comentario_sobre_regla_no_equivale_a_regla_existente():
    original = (
        "# Ejemplo: ExitPolicy reject 127.0.0.1:8080\n"
        "ExitPolicy accept 127.0.0.0/8:*\n"
    )
    assert insertar_regla_rechazo(original).count(
        "ExitPolicy reject 127.0.0.1:8080"
    ) == 2


def test_end_exitpolicy_con_cuerpo_corto_no_inventa_ttl():
    assert resultado_relay(RelayCommand.END, b"\x04\x7f") == "END motivo=EXITPOLICY"


def test_end_vacio_no_inventa_exito():
    assert resultado_relay(RelayCommand.END, b"") == "END motivo=0"


def test_resultados_incompletos_no_se_aprueban():
    assert not any(evaluar_resultados({}).values())
    assert not evaluar_resultados({PUERTO_PERMITIDO: "CONNECTED"})["rechazo"]
    assert not evaluar_resultados({
        PUERTO_BLOQUEADO: "END motivo=MISC",
        PUERTO_PERMITIDO: "CONNECTED",
        PUERTO_CERRADO: "END motivo=CONNECTREFUSED",
    })["rechazo"]


def test_rechazo_exige_categoria_exacta_y_no_prefijo_falso():
    datos = {
        PUERTO_BLOQUEADO: "END motivo=EXITPOLICY_FALSO",
        PUERTO_PERMITIDO: "CONNECTED",
        PUERTO_CERRADO: "END motivo=MISC",
    }
    assert not evaluar_resultados(datos)["rechazo"]


def test_destino_invalido_no_construye_circuito(monkeypatch):
    def prohibir_construccion(*args, **kwargs):
        pytest.fail("No debe construirse un circuito para destinos no permitidos")

    monkeypatch.setattr(lab, "build", prohibir_construccion)
    with pytest.raises(ValueError):
        comprobar_destino(443)


def test_destino_permitido_cierra_siempre_circuito_simulado(monkeypatch):
    class SocketSimulado:
        cerrado = False

        def close(self):
            self.cerrado = True

    sock = SocketSimulado()
    enviado = []
    pasos = []

    class CircuitoSimulado:
        channel = SimpleNamespace(sock=sock)

        def send(self, mensaje):
            enviado.append(mensaje)

        def receive(self):
            return None, SimpleNamespace(command=RelayCommand.CONNECTED, data=b"")

    monkeypatch.setattr(lab, "relay", pasos.append)
    # El circuito nunca conecta: build se sustituye por completo.
    def construir(nodos):
        assert nodos == [None, None, None]
        return CircuitoSimulado()

    monkeypatch.setattr(lab, "build", construir)
    assert comprobar_destino(PUERTO_PERMITIDO) == "CONNECTED"
    assert pasos == ["003r", "005r", "006e"]
    assert len(enviado) == 1
    assert sock.cerrado


def test_recarga_verifica_pid_de_006e_sin_lanzar_docker(monkeypatch):
    llamadas = []

    def ejecutar(comando, **opciones):
        llamadas.append((comando, opciones))

    monkeypatch.setattr(lab.subprocess, "run", ejecutar)
    lab.recargar()
    comando, opciones = llamadas[0]
    assert len(llamadas) == 1
    assert comando[:5] == ["docker", "exec", lab.CONTENEDOR, "sh", "-c"]
    assert "/lab/net/nodes/006e/pid" in comando[-1]
    assert "ps -p" in comando[-1]
    assert "006e/torrc" in comando[-1]
    assert 'kill -HUP "$pid"' in comando[-1]
    assert opciones["check"] is True
    assert opciones["timeout"] == 15


def test_servidor_obligatorio_rechaza_puerto_ocupado(monkeypatch):
    def error_al_abrir(*args, **kwargs):
        raise OSError("ocupado")

    monkeypatch.setattr(lab.http.server, "ThreadingHTTPServer", error_al_abrir)
    with pytest.raises(RuntimeError, match="No se puede iniciar"):
        lab.iniciar_servidor(PUERTO_PERMITIDO, obligatorio=True)
    assert lab.iniciar_servidor(PUERTO_BLOQUEADO, obligatorio=False) is None


def test_respuesta_http_no_expone_archivos_locales():
    escrituras, codigos, errores, cabeceras = [], [], [], []
    respuesta = SimpleNamespace(
        path="/",
        wfile=SimpleNamespace(write=escrituras.append),
        send_response=codigos.append,
        send_error=errores.append,
        send_header=lambda clave, valor: cabeceras.append((clave, valor)),
        end_headers=lambda: None,
    )
    lab.RespuestaDePrueba.do_GET(respuesta)
    assert codigos == [200]
    assert escrituras == [b"Prueba de salida privada de Tor\n"]
    assert ("Content-Length", str(len(escrituras[0]))) in cabeceras
    respuesta.path = "/lab/"
    lab.RespuestaDePrueba.do_GET(respuesta)
    assert errores == [404]
    assert len(escrituras) == 1


def preparar_experimento(tmp_path: Path, monkeypatch):
    nodo = tmp_path / "006e"
    nodo.mkdir()
    torrc = nodo / "torrc"
    original = "ORPort 5106\nExitPolicy accept 127.0.0.0/8:*\n"
    torrc.write_text(original, encoding="utf-8")
    monkeypatch.setattr(lab, "REPETIDOR_SALIDA", nodo)
    monkeypatch.setattr(lab, "puerto_cerrado_libre", lambda: True)
    monkeypatch.setattr(lab.time, "sleep", lambda segundos: None)
    creados = []

    class ServidorSimulado:
        def __init__(self, puerto):
            self.puerto = puerto
            self.eventos = []

        def shutdown(self):
            self.eventos.append("shutdown")

        def server_close(self):
            self.eventos.append("server_close")

    def iniciar(puerto, obligatorio):
        servidor = ServidorSimulado(puerto)
        creados.append(servidor)
        return servidor

    monkeypatch.setattr(lab, "iniciar_servidor", iniciar)
    return torrc, original, creados


def test_experimento_offline_restaura_torrc_y_cierra_servidores(
    tmp_path, monkeypatch
):
    torrc, original, servidores = preparar_experimento(tmp_path, monkeypatch)
    recargas, pruebas = [], []

    def recargar():
        recargas.append(torrc.read_text(encoding="utf-8"))

    def comprobar(puerto):
        pruebas.append(puerto)
        return {
            PUERTO_BLOQUEADO: "END motivo=EXITPOLICY",
            PUERTO_PERMITIDO: "CONNECTED",
            PUERTO_CERRADO: "END motivo=CONNECTREFUSED",
        }[puerto]

    monkeypatch.setattr(lab, "recargar", recargar)
    monkeypatch.setattr(lab, "comprobar_destino", comprobar)
    assert lab.experimentar() is True
    assert pruebas == [PUERTO_BLOQUEADO, PUERTO_PERMITIDO, PUERTO_CERRADO]
    assert len(recargas) == 2
    assert "ExitPolicy reject 127.0.0.1:8080" in recargas[0]
    assert recargas[1] == original
    assert torrc.read_text(encoding="utf-8") == original
    assert [s.eventos for s in servidores] == [
        ["shutdown", "server_close"], ["shutdown", "server_close"]
    ]


def test_error_durante_prueba_restaura_torrc_y_cierra_servidores(
    tmp_path, monkeypatch
):
    torrc, original, servidores = preparar_experimento(tmp_path, monkeypatch)
    recargas = []
    monkeypatch.setattr(lab, "recargar", lambda: recargas.append(True))

    def fallar_prueba(puerto):
        raise RuntimeError("fallo simulado de circuito")

    monkeypatch.setattr(lab, "comprobar_destino", fallar_prueba)
    with pytest.raises(RuntimeError, match="fallo simulado"):
        lab.experimentar()
    assert len(recargas) == 2
    assert torrc.read_text(encoding="utf-8") == original
    assert len(servidores) == 2
    assert all(s.eventos == ["shutdown", "server_close"] for s in servidores)


def test_puerto_negativo_ocupado_impide_iniciar_experimento(monkeypatch):
    monkeypatch.setattr(lab, "puerto_cerrado_libre", lambda: False)
    monkeypatch.setattr(
        lab, "iniciar_servidor",
        lambda *args, **kwargs: pytest.fail("No debe iniciarse un servidor"),
    )
    with pytest.raises(RuntimeError, match="9999"):
        lab.experimentar()
