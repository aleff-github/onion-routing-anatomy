# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Pruebas offline para el laboratorio 18: no requieren red ni Stem."""
import subprocess
from types import SimpleNamespace

import pytest

import fuga_dns as lab


class ControlSimulado:
    def __init__(self):
        self.conf = {"TestSocks": "0", "SafeSocks": "0"}
        self.escucha = None

    def get_conf(self, clave, default=None):
        return self.conf.get(clave, default)

    def add_event_listener(self, callback, *eventos):
        assert eventos == ("NOTICE", "WARN")
        self.escucha = callback

    def remove_event_listener(self, callback):
        assert callback == self.escucha
        self.escucha = None

    def set_options(self, opciones):
        self.conf.update(opciones)

    def set_conf(self, clave, valor):
        self.conf[clave] = valor

    def reset_conf(self, clave):
        self.conf.pop(clave, None)

    def registrar(self, mensaje):
        if self.escucha:
            self.escucha(SimpleNamespace(message=mensaje))


def solicitud_simulada(control, *, omitir_aviso=False, fallo_bloqueo=False):
    def solicitar(opcion):
        assert opcion in lab.OPCIONES
        if control.conf.get("SafeSocks") == "1":
            return ("200", 0) if fallo_bloqueo else ("000", 97)
        if not omitir_aviso:
            if opcion == "--socks5":
                control.registrar("Tor only received an IP address")
            else:
                control.registrar("Tor handles the DNS resolution itself")
        return "200", 0
    return solicitar


def test_solo_admite_proxy_y_destino_local(monkeypatch):
    llamadas = []

    def falso_run(orden, **kwargs):
        llamadas.append((orden, kwargs))
        return SimpleNamespace(stdout="200", returncode=0)

    monkeypatch.setattr(lab.subprocess, "run", falso_run)
    for opcion in lab.OPCIONES:
        assert lab.solicitar(opcion) == ("200", 0)
    assert len(llamadas) == 2
    for orden, kwargs in llamadas:
        assert orden[-3:] in [
            ["--socks5", "127.0.0.1:9008", "http://localhost:8080/"],
            ["--socks5-hostname", "127.0.0.1:9008", "http://localhost:8080/"],
        ]
        # NO_PROXY del anfitrión no debe anular el proxy SOCKS.
        assert orden[orden.index("--noproxy") + 1] == ""
        assert kwargs["check"] is False
        assert kwargs["timeout"] == 25


@pytest.mark.parametrize("opcion", ["--proxy", "--socks4", "https://ejemplo.org", ""])
def test_prohibe_opciones_no_previstas(monkeypatch, opcion):
    def no_llamar_curl(*args, **kwargs):
        pytest.fail("Una opción prohibida no debe invocar curl")

    monkeypatch.setattr(lab.subprocess, "run", no_llamar_curl)
    with pytest.raises(ValueError):
        lab.solicitar(opcion)


def test_rechaza_codigos_http_malformados():
    assert lab.codigo_http("200") == "200"
    assert lab.codigo_http("000\n") == "000"
    assert lab.codigo_http("error") == "000"
    assert lab.codigo_http("200 404") == "000"


def test_distingue_diagnosticos_del_controlport():
    mensajes = ["Tor started", "Your application gives Tor only an IP address",
                "Tor takes care of DNS resolution itself"]
    assert "IP address" in lab.aviso_socks(mensajes, "IP address")
    assert "DNS" in lab.aviso_socks(mensajes, "DNS")
    assert lab.aviso_socks(mensajes, "NO EXISTE") == ""


def test_evaluacion_positiva_y_controles_negativos():
    datos = {
        "--socks5": ("200", 0),
        "--socks5-hostname": ("200", 0),
        "--socks5 SafeSocks": ("000", 97),
    }
    avisos = {
        "--socks5": "IP address: riesgo de filtración",
        "--socks5-hostname": "DNS resolution by Tor",
    }
    resultado = lab.evaluar_resultados(datos, avisos)
    assert set(resultado) == {
        "aviso sobre dirección IP local",
        "aviso sobre resolución DNS delegada a Tor",
        "rechazo por SafeSocks",
    }
    assert all(resultado.values())
    assert not lab.evaluar_resultados(datos, {})["aviso sobre dirección IP local"]
    assert not lab.evaluar_resultados(datos, {})["aviso sobre resolución DNS delegada a Tor"]
    datos["--socks5 SafeSocks"] = ("000", 0)
    assert not lab.evaluar_resultados(datos, avisos)["rechazo por SafeSocks"]
    datos["--socks5 SafeSocks"] = ("200", 0)
    assert not lab.evaluar_resultados(datos, avisos)["rechazo por SafeSocks"]
    datos["--socks5"] = ("200", 7)
    assert not lab.evaluar_resultados(datos, avisos)["aviso sobre dirección IP local"]


def test_exito_restauracion_y_desuscripcion():
    control = ControlSimulado()
    salida = []
    assert lab.comparar_socks(
        control, "NOTICE", "WARN", solicitud=solicitud_simulada(control),
        esperar=lambda _: None, mostrar=salida.append
    )
    assert control.conf == {"TestSocks": "0", "SafeSocks": "0"}
    assert control.escucha is None
    assert sum("CORRECTA" in mensaje for mensaje in salida) == 3


@pytest.mark.parametrize("fallo", ["sin_aviso", "sin_bloqueo"])
def test_no_afirma_exito_con_control_incompleto(fallo):
    control = ControlSimulado()
    assert not lab.comparar_socks(
        control, "NOTICE", "WARN",
        solicitud=solicitud_simulada(
            control, omitir_aviso=(fallo == "sin_aviso"),
            fallo_bloqueo=(fallo == "sin_bloqueo")
        ),
        esperar=lambda _: None, mostrar=lambda _: None
    )
    assert control.conf == {"TestSocks": "0", "SafeSocks": "0"}
    assert control.escucha is None


def test_error_tambien_restaura_configuracion():
    control = ControlSimulado()

    def error(_):
        raise subprocess.TimeoutExpired("curl", 25)

    with pytest.raises(subprocess.TimeoutExpired):
        lab.comparar_socks(
            control, "NOTICE", "WARN", solicitud=error, esperar=lambda _: None
        )
    assert control.conf == {"TestSocks": "0", "SafeSocks": "0"}
    assert control.escucha is None


def test_restauracion_de_valores_ausentes():
    control = ControlSimulado()
    control.conf.clear()
    assert lab.comparar_socks(
        control, "NOTICE", "WARN", solicitud=solicitud_simulada(control),
        esperar=lambda _: None, mostrar=lambda _: None
    )
    assert control.conf == {}


def test_restringe_infraestructura_y_no_sirve_archivos(monkeypatch, tmp_path):
    assert lab.URL == "http://localhost:8080/"
    assert lab.SOCKS == "127.0.0.1:9008"
    assert lab.PUERTO_CONTROL == 8008
    assert issubclass(lab.RespuestaLocal, __import__("http.server", fromlist=["BaseHTTPRequestHandler"]).BaseHTTPRequestHandler)
    monkeypatch.setattr(lab, "CLIENTE_PRIVADO", tmp_path / "sin-nodo")
    with pytest.raises(RuntimeError, match="Chutney privado"):
        lab.validar_entorno()


def test_solicitud_distingue_codigo_curl_y_codigo_http(monkeypatch):
    respuestas = [
        SimpleNamespace(stdout="200\n", returncode=0),
        SimpleNamespace(stdout="200", returncode=7),
        SimpleNamespace(stdout="error", returncode=0),
    ]
    def falso_run(*args, **kwargs):
        return respuestas.pop(0)

    monkeypatch.setattr(lab.subprocess, "run", falso_run)
    assert lab.solicitar("--socks5") == ("200", 0)
    # HTTP y estado del proceso son señales distintas y deben evaluarse juntas.
    assert lab.solicitar("--socks5") == ("200", 7)
    assert lab.solicitar("--socks5-hostname") == ("000", 0)


def test_no_confunde_aviso_ip_con_aviso_dns():
    control = ControlSimulado()
    mensajes = []

    def emitir_solo_aviso_ip(opcion):
        if opcion == "--socks5":
            control.registrar("Tor only received an IP address")
        return "200", 0

    assert not lab.comparar_socks(
        control, "NOTICE", "WARN", solicitud=emitir_solo_aviso_ip,
        esperar=lambda _: None, mostrar=mensajes.append,
    )
    assert any("NO VERIFICADA" in mensaje for mensaje in mensajes)
    assert control.escucha is None
    assert control.conf == {"TestSocks": "0", "SafeSocks": "0"}


def test_ignora_avisos_emitidos_antes_de_cada_solicitud():
    class ControlConAvisosPrevios(ControlSimulado):
        def add_event_listener(self, callback, *eventos):
            super().add_event_listener(callback, *eventos)
            self.registrar("Tor only received an IP address")
            self.registrar("Tor handles the DNS resolution itself")

    control = ControlConAvisosPrevios()

    def solicitud_sin_avisos(opcion):
        if control.conf.get("SafeSocks") == "1":
            return "000", 97
        return "200", 0

    assert not lab.comparar_socks(
        control, "NOTICE", "WARN", solicitud=solicitud_sin_avisos,
        esperar=lambda _: None, mostrar=lambda _: None,
    )
    assert control.conf == {"TestSocks": "0", "SafeSocks": "0"}
    assert control.escucha is None


def test_error_al_configurar_socks_desuscribe_y_restaura():
    control = ControlSimulado()
    def fallo_configuracion(opciones):
        control.conf.update(opciones)
        raise RuntimeError("fallo simulado de configuración")

    control.set_options = fallo_configuracion
    with pytest.raises(RuntimeError, match="fallo simulado"):
        lab.comparar_socks(
            control, "NOTICE", "WARN", solicitud=lambda _: pytest.fail(
                "No debe solicitarse una URL después de un fallo de configuración"
            ),
            esperar=lambda _: None, mostrar=lambda _: None,
        )
    assert control.escucha is None
    assert control.conf == {"TestSocks": "0", "SafeSocks": "0"}


def test_respuesta_http_local_no_sirve_archivos():
    class SalidaSimulada:
        def __init__(self):
            self.escrituras = []
        def write(self, datos):
            self.escrituras.append(datos)

    salida = SalidaSimulada()
    codigos = []
    cabeceras = []
    errores = []
    solicitud = SimpleNamespace(
        path="/",
        wfile=salida,
        send_response=codigos.append,
        send_error=errores.append,
        send_header=lambda clave, valor: cabeceras.append((clave, valor)),
        end_headers=lambda: None,
    )
    lab.RespuestaLocal.do_GET(solicitud)
    assert codigos == [200]
    assert errores == []
    assert salida.escrituras == [b"Laboratorio privado de Tor\n"]
    assert ("Content-Length", str(len(salida.escrituras[0]))) in cabeceras

    solicitud.path = "/lab/"
    lab.RespuestaLocal.do_GET(solicitud)
    assert errores == [404]
    assert len(salida.escrituras) == 1


def test_restauracion_independiente_para_valores_presentes_y_ausentes():
    control = ControlSimulado()
    control.conf = {"TestSocks": "1", "SafeSocks": "1", "OtraOpcion": "valor"}
    lab.restaurar_configuracion(control, {"TestSocks": None, "SafeSocks": "0"})
    assert control.conf == {"SafeSocks": "0", "OtraOpcion": "valor"}
