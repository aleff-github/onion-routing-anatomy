# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Pruebas offline con series sintéticas y comprobaciones negativas de correlación."""
import pytest

import correlacion as lab


class SocketSimulado:
    """Transporte local en memoria: ninguna conexión de red real."""

    def __init__(self, respuesta: bytes):
        self.respuesta = bytearray(respuesta)
        self.envios = []
        self.esperas = []
        self.cerrado = False

    def recv(self, cantidad: int) -> bytes:
        if not self.respuesta:
            return b""
        # Entrega un byte por llamada para ejercitar la lectura fragmentada.
        fragmento = bytes(self.respuesta[:min(cantidad, 1)])
        del self.respuesta[:len(fragmento)]
        return fragmento

    def sendall(self, contenido: bytes) -> None:
        self.envios.append(contenido)

    def settimeout(self, segundos: int) -> None:
        self.esperas.append(segundos)

    def close(self) -> None:
        self.cerrado = True


def test_series_temporales():
    datos = lab.series([(10.1, 5), (10.2, 3), (10.35, 9)], 10.0)
    assert datos[0] == 8
    assert datos[1] == 9
    assert sum(datos) == 17
    assert len(datos) == int(lab.DURATION / lab.BIN + 20)


def test_series_vacias_y_eventos_posteriores_al_limite():
    inicio = 10.0
    assert not any(lab.series([], inicio))
    limite = inicio + (int(lab.DURATION / lab.BIN + 20) * lab.BIN)
    datos = lab.series([(inicio + lab.BIN, 3), (limite, 99), (limite + 1, 20)], inicio)
    assert datos[0] == 0
    assert datos[1] == 3
    assert sum(datos) == 3


def test_series_no_debe_incluir_eventos_anteriores_al_inicio():
    datos = lab.series([(9.99, 17)], 10.0)
    assert datos[0] == 0


def test_correlacion_y_anticorrelacion():
    x = [0, 1, 4, 2, 0]
    assert lab.safe_correlation(x, [v * 2 for v in x]) == pytest.approx(1.0)
    assert lab.safe_correlation(x, [-v for v in x]) == pytest.approx(-1.0)


@pytest.mark.parametrize(
    ("entrada", "salida"),
    [
        ([0, 0, 0], [1, 2, 3]),
        ([1, 2, 3], [7, 7, 7]),
        ([1, 2], [0]),
        ([], []),
        ([1], [2]),
    ],
)
def test_rechazo_series_no_comparables(entrada, salida):
    assert lab.safe_correlation(entrada, salida) == float("-inf")


def test_flujos_sinteticos_aislados():
    assert lab.SOCKS == ("127.0.0.1", 9008)
    assert lab.SERVER_PORT == 8095
    assert lab.N == 6


def test_correspondencias_no_utilizan_verdad_en_calculo():
    # Verifica solo el cálculo puro, no una captura ni una atribución real de flujos.
    a = [0, 1, 0, 2, 0, 4]
    b = [4, 0, 0, 0, 1, 0]
    scores = [lab.safe_correlation(a, a), lab.safe_correlation(a, b)]
    assert scores[0] > scores[1]


def test_recv_exact_reconstruye_respuestas_fragmentadas():
    transporte = SocketSimulado(b"ABCDE")
    assert lab.recv_exact(transporte, 5) == b"ABCDE"
    assert transporte.respuesta == bytearray()


def test_recv_exact_rechaza_respuestas_incompletas():
    transporte = SocketSimulado(b"AB")
    with pytest.raises(ConnectionError, match="incompleta"):
        lab.recv_exact(transporte, 3)


def test_socks5_usa_autenticacion_y_destino_local(monkeypatch):
    # Método de usuario/contraseña, autenticación correcta y respuesta CONNECT IPv4.
    respuestas = (
        b"\x05\x02"
        + b"\x01\x00"
        + b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1f\x9f"
    )
    transporte = SocketSimulado(respuestas)
    conexiones = []

    def abrir(direccion, timeout):
        conexiones.append((direccion, timeout))
        return transporte

    monkeypatch.setattr(lab.socket, "create_connection", abrir)
    assert lab.socks5("flujo-1") is transporte
    assert conexiones == [(("127.0.0.1", 9008), 15)]
    assert transporte.envios == [
        b"\x05\x01\x02",
        b"\x01\x07flujo-1\x01x",
        b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x9f",
    ]
    assert transporte.esperas == [15, 45]
    assert not transporte.cerrado


@pytest.mark.parametrize("credenciales", ["", "x" * 256])
def test_socks5_rechaza_usuario_invalido_antes_de_conectar(monkeypatch, credenciales):
    def prohibir_conexion(*args, **kwargs):
        pytest.fail("No debe abrirse una conexión con credenciales inválidas")

    monkeypatch.setattr(lab.socket, "create_connection", prohibir_conexion)
    with pytest.raises(ValueError, match="1 a 255 bytes"):
        lab.socks5(credenciales)


@pytest.mark.parametrize(
    "respuesta",
    [
        b"\x05\x00",  # Método sin contraseña rechazado.
        b"\x05\x02\x01\x01",  # Usuario y contraseña rechazados.
        b"\x05\x02\x01\x00\x05\x00\x00\x09",  # ATYP no permitido.
    ],
)
def test_socks5_cierra_socket_en_respuestas_invalidas(monkeypatch, respuesta):
    transporte = SocketSimulado(respuesta)
    monkeypatch.setattr(lab.socket, "create_connection", lambda *a, **k: transporte)
    with pytest.raises(ConnectionError):
        lab.socks5("flujo-1")
    assert transporte.cerrado
