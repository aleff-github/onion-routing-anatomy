# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Pruebas offline de las celdas y del límite de RELAY_EARLY."""
from types import SimpleNamespace
import pytest

from torlab.cells import CellCommand, RelayCommand
from torlab.circuit import CircuitError, MAX_RELAY_EARLY
import relay_early as laboratorio


class CanalSimulado:
    def __init__(self):
        self.celdas = []
    def send(self, celda):
        self.celdas.append(celda)


class CifradoSimulado:
    def encrypt(self, mensaje, salto):
        assert mensaje.command == RelayCommand.DROP
        assert mensaje.stream_id == 0 and salto is None
        return b"\x00" * 509


def circuito_simulado():
    return SimpleNamespace(circ_id=0x80000001,
                           crypto=CifradoSimulado(), channel=CanalSimulado())


def test_constante_del_protocolo():
    assert MAX_RELAY_EARLY == 8


@pytest.mark.parametrize("cantidad", [8, 9])
def test_envio_directo_de_celdas_tempranas(cantidad):
    circuito = circuito_simulado()
    laboratorio.enviar_tempranas(circuito, cantidad)
    assert len(circuito.channel.celdas) == cantidad
    assert all(c.command == CellCommand.RELAY_EARLY for c in circuito.channel.celdas)
    assert all(c.circ_id == circuito.circ_id for c in circuito.channel.celdas)
    assert circuito.channel.celdas[0].body == b"\x00" * 509


@pytest.mark.parametrize("cantidad", [-1, 0, 1, 7, 10, 100])
def test_rechazo_de_cantidades_ajenas_al_experimento(cantidad):
    with pytest.raises(ValueError):
        laboratorio.validar_cantidad(cantidad)


def test_ocho_requiere_connected():
    assert laboratorio.evaluar_respuesta(8, "CONNECTED")
    assert not laboratorio.evaluar_respuesta(8, "circuito destruido, motivo 1")


def test_nueve_requiere_destroy_con_motivo_protocolo():
    assert laboratorio.evaluar_respuesta(9, "circuito destruido, motivo 1")
    assert not laboratorio.evaluar_respuesta(9, "CONNECTED")
    assert not laboratorio.evaluar_respuesta(9, "circuito destruido, motivo 2")
    # Exigir un resultado exacto, no subcadenas de un mensaje ambiguo.
    assert not laboratorio.evaluar_respuesta(9, "otro error: circuito destruido, motivo 1")
    assert not laboratorio.evaluar_respuesta(9, "circuito destruido, motivo 10")


def test_ocho_y_nueve_generan_celdas_completas_con_id_del_circuito():
    for cantidad in (8, 9):
        circuito = circuito_simulado()
        laboratorio.enviar_tempranas(circuito, cantidad)
        assert len(circuito.channel.celdas) == cantidad
        assert all(
            celda.command == CellCommand.RELAY_EARLY
            and celda.circ_id == circuito.circ_id
            and celda.body == b"\x00" * 509
            for celda in circuito.channel.celdas
        )


def test_cantidad_invalida_no_envia_celdas_ni_cifra():
    class CifradoProhibido:
        def encrypt(self, *args):
            pytest.fail("No debe cifrar antes de validar la cantidad")

    circuito = circuito_simulado()
    circuito.crypto = CifradoProhibido()
    for cantidad in (0, 7, 10, -1):
        with pytest.raises(ValueError, match="8 o 9"):
            laboratorio.enviar_tempranas(circuito, cantidad)
    assert circuito.channel.celdas == []


def test_validar_cantidad_debe_rechazar_flotantes():
    with pytest.raises(ValueError):
        laboratorio.validar_cantidad(8.0)


def preparar_circuito_con_cierre():
    canal = CanalSimulado()
    cierre = []
    canal.sock = SimpleNamespace(close=lambda: cierre.append(True))
    mensajes = []
    circuito = SimpleNamespace(
        circ_id=0x80000001,
        crypto=CifradoSimulado(),
        channel=canal,
        send=mensajes.append,
    )
    return circuito, mensajes, cierre


@pytest.mark.parametrize(
    ("cantidad", "respuesta_esperada"),
    [(8, "CONNECTED"), (9, "CONNECTED")],
)
def test_prueba_simulada_usa_004r_sin_red_y_cierra_canal(
    monkeypatch, cantidad, respuesta_esperada
):
    circuito, mensajes, cierre = preparar_circuito_con_cierre()
    relay_solicitados = []
    construcciones = []

    def relay_falso(nombre):
        relay_solicitados.append(nombre)
        return "repetidor simulado"

    def build_falso(ruta, cc=True):
        construcciones.append((ruta, cc))
        return circuito

    circuito.receive = lambda: (
        0, SimpleNamespace(command=RelayCommand.CONNECTED, data=b"")
    )
    monkeypatch.setattr(laboratorio, "relay", relay_falso)
    monkeypatch.setattr(laboratorio, "build", build_falso)

    assert laboratorio.probar_cantidad(cantidad) == respuesta_esperada
    assert relay_solicitados == ["004r"]
    assert construcciones == [(["repetidor simulado"], False)]
    assert len(circuito.channel.celdas) == cantidad
    assert len(mensajes) == 1
    assert mensajes[0].command == RelayCommand.BEGIN_DIR
    assert mensajes[0].stream_id == 1
    assert cierre == [True]


def test_destroy_simulado_devuelve_el_motivo_localizado_y_cierra(monkeypatch):
    circuito, mensajes, cierre = preparar_circuito_con_cierre()
    def receive_falso():
        raise CircuitError("circuito destruido, motivo 1")

    circuito.receive = receive_falso
    monkeypatch.setattr(laboratorio, "relay", lambda nombre: nombre)
    monkeypatch.setattr(laboratorio, "build", lambda ruta, cc: circuito)
    assert laboratorio.probar_cantidad(9) == "circuito destruido, motivo 1"
    assert len(circuito.channel.celdas) == 9
    assert mensajes[0].command == RelayCommand.BEGIN_DIR
    assert cierre == [True]


def test_error_inesperado_tambien_cierra_canal(monkeypatch):
    circuito, _, cierre = preparar_circuito_con_cierre()
    circuito.receive = lambda: (_ for _ in ()).throw(RuntimeError("simulado"))
    monkeypatch.setattr(laboratorio, "relay", lambda nombre: nombre)
    monkeypatch.setattr(laboratorio, "build", lambda ruta, cc: circuito)
    with pytest.raises(RuntimeError, match="simulado"):
        laboratorio.probar_cantidad(8)
    assert cierre == [True]


def test_cantidad_invalida_no_construye_circuito(monkeypatch):
    monkeypatch.setattr(
        laboratorio, "build",
        lambda *args, **kwargs: pytest.fail("No debe construirse un circuito"),
    )
    with pytest.raises(ValueError, match="8 o 9"):
        laboratorio.probar_cantidad(7)


@pytest.mark.parametrize(
    ("argumentos", "respuestas", "codigo"),
    [
        ([], {8: "CONNECTED", 9: "circuito destruido, motivo 1"}, 0),
        (["8"], {8: "CONNECTED"}, 0),
        (["9"], {9: "CONNECTED"}, 1),
        (["8", "9"], {8: "CONNECTED", 9: "circuito destruido, motivo 2"}, 1),
    ],
)
def test_main_solo_usa_las_cantidades_autorizadas(
    monkeypatch, capsys, argumentos, respuestas, codigo
):
    llamadas = []
    monkeypatch.setattr(
        laboratorio.argparse.ArgumentParser, "parse_args",
        lambda self: SimpleNamespace(
            cantidades=[int(valor) for valor in argumentos] if argumentos else [8, 9]
        ),
    )

    def probar_falso(cantidad):
        llamadas.append(cantidad)
        return respuestas[cantidad]

    monkeypatch.setattr(laboratorio, "probar_cantidad", probar_falso)
    assert laboratorio.main() == codigo
    assert llamadas == ([int(v) for v in argumentos] if argumentos else [8, 9])
    salida = capsys.readouterr().out
    assert "celdas RELAY_EARLY" in salida
    assert ("NO VERIFICADA" in salida) is (codigo == 1)


@pytest.mark.parametrize("argumentos", [[8, 8], [9, 9], [7], [10]])
def test_main_rechaza_argumentos_invalidos_antes_del_circuito(
    monkeypatch, argumentos
):
    monkeypatch.setattr(
        laboratorio.argparse.ArgumentParser, "parse_args",
        lambda self: SimpleNamespace(cantidades=argumentos),
    )
    monkeypatch.setattr(
        laboratorio, "probar_cantidad",
        lambda cantidad: pytest.fail("No debe ejecutarse la prueba de red"),
    )
    with pytest.raises(SystemExit) as error:
        laboratorio.main()
    assert error.value.code == 2
