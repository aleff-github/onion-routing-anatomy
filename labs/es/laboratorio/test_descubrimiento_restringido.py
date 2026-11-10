# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Pruebas sin red para la autorización y los límites de seguridad del laboratorio."""
from pathlib import Path
from types import SimpleNamespace

import pytest

import descubrimiento_restringido as lab


DIRECCION = "a" * 56 + ".onion"


def test_autorizacion_publica_x25519():
    clave = bytes(range(32))
    resultado = lab.autorizacion_publica(clave)
    assert resultado.startswith("descriptor:x25519:")
    assert resultado.endswith("\n")
    assert "=" not in resultado
    assert len(resultado.split(":")[2].strip()) == 52


def test_autorizacion_privada_x25519():
    resultado = lab.autorizacion_privada(DIRECCION, bytes(range(32)))
    assert resultado.startswith("a" * 56 + ":descriptor:x25519:")
    assert resultado.endswith("\n")
    assert "=" not in resultado


def test_claves_y_direcciones_invalidas():
    with pytest.raises(ValueError):
        lab.autorizacion_publica(b"demasiado corta")
    with pytest.raises(ValueError):
        lab.autorizacion_privada(DIRECCION, b"\x00")
    with pytest.raises(ValueError):
        lab.autorizacion_privada("ejemplo.com", bytes(32))


def test_directorio_interno_usa_torrc(tmp_path: Path):
    nodo = tmp_path / "008c"
    nodo.mkdir()
    (nodo / "torrc").write_text("SocksPort 9008\nDataDirectory /lab/net/nodes/008c\n")
    assert lab.directorio_interno(nodo) == "/lab/net/nodes/008c"


def test_directorio_interno_sin_configuracion(tmp_path: Path):
    nodo = tmp_path / "008c"
    nodo.mkdir()
    (nodo / "torrc").write_text("SocksPort 9008\n")
    with pytest.raises(RuntimeError, match="DataDirectory"):
        lab.directorio_interno(nodo)


def test_estado_inicial_protege_directorios_anteriores(tmp_path: Path, monkeypatch):
    servicio, cliente = tmp_path / "009h", tmp_path / "008c"
    servicio.mkdir()
    cliente.mkdir()
    (servicio / "torrc").write_text("DataDirectory /lab/net/nodes/009h\n")
    (cliente / "torrc").write_text("DataDirectory /lab/net/nodes/008c\n")
    monkeypatch.setattr(lab, "SERVICIO", servicio)
    monkeypatch.setattr(lab, "CLIENTE", cliente)
    monkeypatch.setattr(lab, "DIR_SERVICIO", servicio / "restricted_service")
    monkeypatch.setattr(lab, "DIR_CLIENTE", cliente / "onion_auth")
    assert lab.validar_estado_inicial()[0].startswith("DataDirectory")
    (servicio / "restricted_service").mkdir()
    with pytest.raises(RuntimeError, match="directorios de autorización previos"):
        lab.validar_estado_inicial()


def test_configuracion_cliente_ya_existe(tmp_path: Path, monkeypatch):
    servicio, cliente = tmp_path / "009h", tmp_path / "008c"
    servicio.mkdir()
    cliente.mkdir()
    (servicio / "torrc").write_text("DataDirectory /lab/net/nodes/009h\n")
    (cliente / "torrc").write_text("ClientOnionAuthDir /otro\n")
    monkeypatch.setattr(lab, "SERVICIO", servicio)
    monkeypatch.setattr(lab, "CLIENTE", cliente)
    monkeypatch.setattr(lab, "DIR_SERVICIO", servicio / "restricted_service")
    monkeypatch.setattr(lab, "DIR_CLIENTE", cliente / "onion_auth")
    with pytest.raises(RuntimeError, match="ClientOnionAuthDir"):
        lab.validar_estado_inicial()


def test_consulta_impide_destinos_fuera_del_onion(monkeypatch):
    def no_invocar(*args, **kwargs):
        raise AssertionError("No debe invocarse docker")
    monkeypatch.setattr(lab.subprocess, "run", no_invocar)
    with pytest.raises(ValueError):
        lab.consultar("https://example.com")


def test_consulta_fuerza_socks_y_comprueba_el_estado_de_curl(monkeypatch):
    llamadas = []
    codigo_salida = [0]

    def falso_run(comando, **opciones):
        llamadas.append((comando, opciones))
        return SimpleNamespace(stdout="200", returncode=codigo_salida[0])

    monkeypatch.setattr(lab.subprocess, "run", falso_run)
    assert lab.consultar(DIRECCION) == "200"
    comando, opciones = llamadas[-1]
    assert comando[comando.index("--noproxy") + 1] == ""
    assert comando[comando.index("--socks5-hostname") + 1] == lab.SOCKS
    assert comando[-1] == "http://" + DIRECCION + "/"
    assert opciones["timeout"] == 75

    codigo_salida[0] = 7  # Una solicitud fallida no debe parecer HTTP 200.
    assert lab.consultar(DIRECCION) == "000"

def preparar_nodos_temporales(tmp_path: Path, monkeypatch):
    """Crea solo configuraciones temporales; no utiliza la topología de Chutney."""
    servicio, cliente = tmp_path / "009h", tmp_path / "008c"
    servicio.mkdir()
    cliente.mkdir()
    original_s = "SocksPort 9009\nDataDirectory /lab/net/nodes/009h\n"
    original_c = "SocksPort 9008\nDataDirectory /lab/net/nodes/008c\n"
    (servicio / "torrc").write_text(original_s, encoding="utf-8")
    (cliente / "torrc").write_text(original_c, encoding="utf-8")
    monkeypatch.setattr(lab, "SERVICIO", servicio)
    monkeypatch.setattr(lab, "CLIENTE", cliente)
    monkeypatch.setattr(lab, "DIR_SERVICIO", servicio / "restricted_service")
    monkeypatch.setattr(lab, "DIR_CLIENTE", cliente / "onion_auth")
    return servicio, cliente, original_s, original_c


def test_autorizaciones_x25519_recuperan_los_32_bytes_originales():
    import base64

    clave = bytes(range(32))
    publica = lab.autorizacion_publica(clave).strip().split(":")[-1]
    privada = lab.autorizacion_privada(DIRECCION, clave).strip().split(":")[-1]
    for valor in (publica, privada):
        assert len(valor) == 52
        assert base64.b32decode(valor + "=" * (-len(valor) % 8)) == clave


@pytest.mark.parametrize(
    "direccion",
    [
        "https://example.com",
        "http://" + DIRECCION,
        DIRECCION.upper(),
        "a" * 55 + ".onion",
        "0" * 56 + ".onion",
        DIRECCION + ".example",
        DIRECCION + "/",
        DIRECCION + "\n",
    ],
)
def test_consulta_rechaza_direcciones_no_admitidas_sin_abrir_red(monkeypatch, direccion):
    def prohibir_subproceso(*args, **kwargs):
        pytest.fail("No debe ejecutarse docker para una dirección no admitida")

    monkeypatch.setattr(lab.subprocess, "run", prohibir_subproceso)
    with pytest.raises(ValueError, match="Dirección onion"):
        lab.consultar(direccion)


def test_estado_inicial_rechaza_directorio_previo_del_cliente(tmp_path, monkeypatch):
    servicio, cliente, original_s, original_c = preparar_nodos_temporales(
        tmp_path, monkeypatch
    )
    (cliente / "onion_auth").mkdir()
    with pytest.raises(RuntimeError, match="directorios de autorización previos"):
        lab.validar_estado_inicial()
    assert (servicio / "torrc").read_text() == original_s
    assert (cliente / "torrc").read_text() == original_c


def test_estado_inicial_rechaza_servicio_onion_ya_configurado(tmp_path, monkeypatch):
    servicio, _, _, _ = preparar_nodos_temporales(tmp_path, monkeypatch)
    with (servicio / "torrc").open("a", encoding="utf-8") as archivo:
        archivo.write("HiddenServiceDir /lab/net/nodes/009h/restricted_service\n")
    with pytest.raises(RuntimeError, match="restricted_service"):
        lab.validar_estado_inicial()


def test_recarga_solo_nodos_esperados_y_comprueba_pid(monkeypatch, tmp_path):
    llamadas = []

    def simular_run(comando, **opciones):
        llamadas.append((comando, opciones))

    monkeypatch.setattr(lab.subprocess, "run", simular_run)
    with pytest.raises(ValueError, match="Nodo inesperado"):
        lab.recargar(tmp_path / "007r")
    assert not llamadas
    lab.recargar(tmp_path / "009h")
    assert len(llamadas) == 1
    comando, opciones = llamadas[0]
    assert comando[:5] == ["docker", "exec", lab.CONTENEDOR, "sh", "-c"]
    assert "/lab/net/nodes/009h/pid" in comando[5]
    assert "ps -p" in comando[5]
    assert "009h/torrc" in comando[5]
    assert 'kill -HUP "$pid"' in comando[5]
    assert opciones["check"] is True
    assert opciones["timeout"] == 15


def test_espera_direccion_rechaza_host_invalido_y_acepta_el_posterior(
    tmp_path, monkeypatch
):
    carpeta = tmp_path / "restricted_service"
    carpeta.mkdir()
    hostname = carpeta / "hostname"
    hostname.write_text("example.com\n", encoding="utf-8")
    monkeypatch.setattr(lab, "DIR_SERVICIO", carpeta)
    esperas = []

    def dormir(segundos):
        esperas.append(segundos)
        hostname.write_text(DIRECCION + "\n", encoding="utf-8")

    monkeypatch.setattr(lab.time, "sleep", dormir)
    assert lab.esperar_direccion(intentos=2) == DIRECCION
    assert esperas == [1]


def test_espera_direccion_agota_intentos_sin_direccion(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "DIR_SERVICIO", tmp_path / "sin-servicio")
    esperas = []
    monkeypatch.setattr(lab.time, "sleep", esperas.append)
    with pytest.raises(RuntimeError, match="No apareció"):
        lab.esperar_direccion(intentos=3)
    assert esperas == [1, 1, 1]


@pytest.mark.parametrize(
    ("salida", "codigo_proceso", "esperado"),
    [
        ("200\n", 0, "200"),
        ("404", 0, "404"),
        ("200", 7, "000"),
        ("HTTP 200", 0, "000"),
        ("20X", 0, "000"),
        ("", 0, "000"),
    ],
)
def test_consulta_interpreta_codigo_http_sin_confundir_error(
    monkeypatch, salida, codigo_proceso, esperado
):
    def simular_run(comando, **opciones):
        assert comando[-1] == "http://" + DIRECCION + "/"
        assert opciones["capture_output"] is True
        assert opciones["text"] is True
        return SimpleNamespace(stdout=salida, returncode=codigo_proceso)

    monkeypatch.setattr(lab.subprocess, "run", simular_run)
    assert lab.consultar(DIRECCION) == esperado


def test_experimento_simulado_restaura_torrc_y_borra_solo_claves_temporales(
    tmp_path, monkeypatch
):
    servicio, cliente, original_s, original_c = preparar_nodos_temporales(
        tmp_path, monkeypatch
    )
    recargas, consultas, esperas = [], [], []
    monkeypatch.setattr(lab, "recargar", lambda nodo: recargas.append(nodo))
    monkeypatch.setattr(lab, "esperar_direccion", lambda: DIRECCION)
    monkeypatch.setattr(lab.time, "sleep", esperas.append)

    def consulta_simulada(direccion):
        assert direccion == DIRECCION
        publica = lab.DIR_SERVICIO / "authorized_clients" / "alice.auth"
        privada = lab.DIR_CLIENTE / "alice.auth_private"
        assert publica.is_file() and publica.stat().st_size > 0
        consultas.append(privada.is_file())
        return "200" if privada.is_file() else "000"

    monkeypatch.setattr(lab, "consultar", consulta_simulada)
    assert lab.experimentar() is True
    assert consultas == [False, True]
    assert esperas == [20, 3]
    assert recargas == [servicio, cliente, cliente, cliente, servicio]
    assert (servicio / "torrc").read_text() == original_s
    assert (cliente / "torrc").read_text() == original_c
    assert not lab.DIR_SERVICIO.exists()
    assert not lab.DIR_CLIENTE.exists()


def test_fallo_al_restaurar_recarga_conserva_claves_para_inspeccion(
    tmp_path, monkeypatch
):
    servicio, cliente, original_s, original_c = preparar_nodos_temporales(
        tmp_path, monkeypatch
    )
    llamadas = []

    def recargar_simulado(nodo):
        llamadas.append(nodo)
        if len(llamadas) == 4:
            raise lab.subprocess.CalledProcessError(1, ["docker", "exec"])

    monkeypatch.setattr(lab, "recargar", recargar_simulado)
    monkeypatch.setattr(lab, "esperar_direccion", lambda: DIRECCION)
    monkeypatch.setattr(lab, "consultar", lambda direccion: "000")
    monkeypatch.setattr(lab.time, "sleep", lambda segundos: None)
    with pytest.raises(RuntimeError, match="Fallo al recargar Tor"):
        lab.experimentar()
    assert llamadas == [servicio, cliente, cliente, cliente, servicio]
    assert (servicio / "torrc").read_text() == original_s
    assert (cliente / "torrc").read_text() == original_c
    assert lab.DIR_SERVICIO.exists()
    assert lab.DIR_CLIENTE.exists()
