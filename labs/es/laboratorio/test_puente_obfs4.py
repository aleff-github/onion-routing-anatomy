# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Pruebas offline de los analizadores del laboratorio de puentes."""
from pathlib import Path
from types import SimpleNamespace
import subprocess
import ssl

import pytest

import puente_obfs4 as puente


def test_bootstrap_completo():
    assert puente.arranque_completo("[notice] Bootstrapped 100% (done): Done")
    assert not puente.arranque_completo("[notice] Bootstrapped 90% (ap_conn_done)")
    # No interpretar un 100% antiguo como el estado del intento más reciente.
    assert not puente.arranque_completo("Bootstrapped 100% (done)\nBootstrapped 90% (ap_conn_done)")
    assert puente.arranque_completo("Bootstrapped 90% (ap_conn_done)\nBootstrapped 100% (done)")


def test_prefijo_tls():
    assert puente.prefijo_tls("16030105f8")
    assert puente.prefijo_tls("16:03:03:00:10")
    assert not puente.prefijo_tls("f23abb4e8c")
    assert not puente.prefijo_tls("cadena_no_hexadecimal")
    assert not puente.prefijo_tls("")


def test_resumen_captura():
    total, tls, muestra = puente.resumir_payloads("16030105f8\nf23abb4e8c\n")
    assert (total, tls, muestra) == (2, 1, "16030105f8")
    assert puente.resumir_payloads("") == (0, 0, "")


def test_nombre_captura_restringido():
    assert puente.nombre_captura_valido("b1.pcap")
    assert puente.nombre_captura_valido("captura-01.pcapng")
    for invalido in ("../b1.pcap", "/tmp/b1.pcap", "b1.txt", "../../etc/passwd", ""):
        assert not puente.nombre_captura_valido(invalido)


def test_estado_sin_datos_no_inventa_resultados(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.setattr(puente, "REGISTRO_CLIENTE", tmp_path / "ausente.log")
    assert puente.estado() == 1
    assert "No existe" in capsys.readouterr().out


def test_estado_usa_registro_existente(monkeypatch, tmp_path: Path, capsys):
    registro = tmp_path / "notice.log"
    registro.write_text("Bootstrapped 100% (done)\n")
    monkeypatch.setattr(puente, "REGISTRO_CLIENTE", registro)
    assert puente.estado() == 0
    assert "arranque completo" in capsys.readouterr().out


def test_http_local_no_utiliza_hosts_externos(monkeypatch):
    comandos = []
    def falso_ejecutar(comando, timeout=30):
        comandos.append(comando)
        return "200"
    monkeypatch.setattr(puente, "ejecutar", falso_ejecutar)
    assert puente.http_local() == 0
    linea = " ".join(comandos[0])
    assert "127.0.0.1:9011" in linea and "http://127.0.0.1:8080/" in linea
    assert "torbook-es-network" in linea
    # curl respeta NO_PROXY para localhost salvo que se anule explícitamente.
    assert comandos[0][comandos[0].index("--noproxy") + 1] == ""

def test_analizador_rechaza_enlace_simbolico(monkeypatch, tmp_path: Path, capsys):
    net = tmp_path / "net"
    net.mkdir()
    destino = tmp_path / "privado.pcap"
    destino.write_bytes(b"not a capture")
    enlace = net / "enlace.pcap"
    try:
        enlace.symlink_to(destino)
    except (OSError, NotImplementedError):
        pytest.skip("No se pueden crear enlaces simbólicos en este entorno")
    monkeypatch.setattr(puente, "LAB", tmp_path)
    assert puente.analizar_captura("enlace.pcap") == 1
    assert "enlace simbólico" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("registro", "esperado"),
    [
        ("", False),
        ("Bootstrapped 100% (done)", True),
        ("Bootstrapped 100% (done)\nBootstrapped 0% (starting)", False),
        ("Bootstrapped 80%\nBootstrapped 100%", True),
        ("Bootstrapped 100%\nBootstrapped 99%", False),
        ("Bootstrapped 900% (error)", False),
    ],
)
def test_arranque_segun_ultimo_porcentaje_de_registro(registro, esperado):
    assert puente.arranque_completo(registro) is esperado


@pytest.mark.parametrize(
    ("prefijo", "parece_tls"),
    [
        ("160300", True),
        ("160304", True),
        ("160305", False),
        ("170303", False),
        ("1604ff", False),
        ("16:03:01", True),
        ("16:03", False),
        ("16:03:ZZ", False),
    ],
)
def test_prefijo_tls_es_solo_heuristica(prefijo, parece_tls):
    assert puente.prefijo_tls(prefijo) is parece_tls


def test_resumen_captura_cuenta_segmentos_y_limita_muestra():
    payloads = "160303" + "aa" * 40
    total, prefijos, muestra = puente.resumir_payloads(
        "\n" + payloads + "\n  f23abb  \n16030500\n"
    )
    assert total == 3
    assert prefijos == 1
    assert muestra == payloads[:48]


@pytest.mark.parametrize(
    "nombre",
    ["", ".pcap", "../net/captura.pcap", "dir/captura.pcap", "archivo.PCAP",
     "archivo.pcap.txt", "puente pcap.pcap", "a;rm -rf.pcap",
     "archivo\\\\prueba.pcap", "área.pcap", "captura.pcap\n"],
)
def test_nombre_captura_rechaza_rutas_y_caracteres_no_admitidos(nombre):
    assert not puente.nombre_captura_valido(nombre)


def test_ejecutar_aplica_timeout_y_verificacion_sin_red(monkeypatch):
    llamadas = []

    def ejecutar_simulado(comando, **opciones):
        llamadas.append((comando, opciones))
        return SimpleNamespace(stdout="salida offline")

    monkeypatch.setattr(puente.subprocess, "run", ejecutar_simulado)
    assert puente.ejecutar(["echo", "simulado"], timeout=7) == "salida offline"
    assert llamadas == [(
        ["echo", "simulado"],
        {"capture_output": True, "text": True, "check": True, "timeout": 7},
    )]


def test_http_local_rechaza_estado_no_200(monkeypatch, capsys):
    llamadas = []
    def ejecutar_simulado(comando, timeout=30):
        llamadas.append((comando, timeout))
        return "404\n"

    monkeypatch.setattr(puente, "ejecutar", ejecutar_simulado)
    assert puente.http_local() == 1
    assert len(llamadas) == 1
    assert llamadas[0][1] == 25
    assert "No se ha obtenido HTTP 200" in capsys.readouterr().out


def test_estado_con_bootstrap_incompleto(monkeypatch, tmp_path: Path, capsys):
    registro = tmp_path / "notice.log"
    registro.write_text("Bootstrapped 100% (done)\nBootstrapped 90% (ap_conn_done)\n")
    monkeypatch.setattr(puente, "REGISTRO_CLIENTE", registro)
    assert puente.estado() == 1
    assert "todavía no registra" in capsys.readouterr().out


def test_captura_ausente_no_invoca_tshark(monkeypatch, tmp_path: Path, capsys):
    (tmp_path / "net").mkdir()
    monkeypatch.setattr(puente, "LAB", tmp_path)
    monkeypatch.setattr(
        puente, "ejecutar",
        lambda *args, **kwargs: pytest.fail("No debe ejecutarse tshark"),
    )
    assert puente.analizar_captura("inexistente.pcap") == 1
    assert "Captura ausente" in capsys.readouterr().out


def test_captura_invalida_no_invoca_tshark(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(puente, "LAB", tmp_path)
    monkeypatch.setattr(
        puente, "ejecutar",
        lambda *args, **kwargs: pytest.fail("No debe ejecutarse tshark"),
    )
    assert puente.analizar_captura("../fuera.pcap") == 1


def test_analisis_captura_solo_lee_archivo_permitido(monkeypatch, tmp_path: Path, capsys):
    red = tmp_path / "net"
    red.mkdir()
    (red / "muestra.pcap").write_bytes(b"datos artificiales")
    monkeypatch.setattr(puente, "LAB", tmp_path)
    llamadas = []

    def ejecutar_simulado(comando, timeout=30):
        llamadas.append((comando, timeout))
        return "1603030010\nf23abb4e8c\n" if len(llamadas) == 1 else "f23abb4e8c\n"

    monkeypatch.setattr(puente, "ejecutar", ejecutar_simulado)
    assert puente.analizar_captura("muestra.pcap") == 0
    assert len(llamadas) == 2
    for indice, puerto in enumerate((puente.PUERTO_OR, puente.PUERTO_OBFS4)):
        comando, timeout = llamadas[indice]
        assert comando[:6] == ["docker", "exec", "-u", "0", puente.CONTENEDOR, "tshark"]
        assert comando[comando.index("-r") + 1] == "/lab/net/muestra.pcap"
        assert comando[comando.index("-Y") + 1] == (
            f"tcp.dstport=={puerto} && tcp.len>0"
        )
        assert timeout == 60
    salida = capsys.readouterr().out
    assert "segmentos con datos=2" in salida
    assert "segmentos con datos=1" in salida
    assert "prefijos compatibles" in salida


def test_sondeo_tls_no_prueba_resistencia_activa(monkeypatch, capsys):
    conexiones = []
    class SocketSimulado:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def settimeout(self, valor):
            conexiones.append(("timeout", valor))

    class ContextoSimulado:
        def __init__(self):
            self.check_hostname = True
            self.verify_mode = None
        def wrap_socket(self, sock):
            raise ssl.SSLError("handshake deliberadamente rechazado")

    monkeypatch.setattr(
        puente.socket, "create_connection",
        lambda destino, timeout: (
            conexiones.append((destino, timeout)) or SocketSimulado()
        ),
    )
    monkeypatch.setattr(puente.ssl, "SSLContext", lambda protocolo: ContextoSimulado())
    assert puente.sondeo_tls() == 0
    assert conexiones == [(("127.0.0.1", 9909), 5), ("timeout", 5)]
    assert "no demuestra resistencia" in capsys.readouterr().out


def test_main_captura_fallo_del_comando_sin_red(monkeypatch, capsys):
    monkeypatch.setattr(puente.sys, "argv", ["puente_obfs4.py", "http"])
    monkeypatch.setattr(
        puente, "http_local",
        lambda: (_ for _ in ()).throw(
            subprocess.CalledProcessError(1, ["docker", "exec"])
        ),
    )
    assert puente.main() == 1
    assert "Comprobación no completada" in capsys.readouterr().err


def test_analizador_no_debe_seguir_directorio_net_simbolico(
    monkeypatch, tmp_path: Path
):
    exterior = tmp_path / "exterior"
    exterior.mkdir()
    (exterior / "captura.pcap").write_bytes("datos sintéticos".encode())
    enlace = tmp_path / "net"
    try:
        enlace.symlink_to(exterior, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("No se pueden crear enlaces simbólicos en este entorno")
    monkeypatch.setattr(puente, "LAB", tmp_path)
    monkeypatch.setattr(
        puente, "ejecutar",
        lambda *args, **kwargs: pytest.fail(
            "No debe accederse a capturas a través de net enlazado"
        ),
    )
    assert puente.analizar_captura("captura.pcap") == 1
