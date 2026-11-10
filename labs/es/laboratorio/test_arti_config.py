# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Pruebas offline del generador de TOML de Arti (sin Cargo ni Chutney)."""
from pathlib import Path, PureWindowsPath
import tomllib

import pytest

import arti_config as lab


def crear_autoridades_en_directorios(tmp_path: Path):
    for n in range(3):
        nodo = tmp_path / f"00{n + 1}a"
        (nodo / "keys").mkdir(parents=True)
        (nodo / "fingerprint").write_text(f"test{n} " + ("A" * 40) + "\n")
        (nodo / "fingerprint-ed25519").write_text(f"test{n} " + ("B" * 43) + "\n")
        (nodo / "keys" / "authority_certificate").write_text("fingerprint " + ("C" * 40) + "\n")
        (nodo / "torrc").write_text(
            f"OrPort 127.0.0.1:{5101 + n}\nDirPort {7101 + n}\n"
        )


def test_lee_exactamente_tres_autoridades(tmp_path: Path):
    crear_autoridades_en_directorios(tmp_path)
    autoridades = list(lab.authorities_from_network(tmp_path))
    assert len(autoridades) == 3
    assert autoridades[0][3:] == ("5101", "7101")
    assert autoridades[2][3:] == ("5103", "7103")


def test_toml_valido_con_parametros_de_red_privada(tmp_path: Path):
    crear_autoridades_en_directorios(tmp_path)
    autoridades = list(lab.authorities_from_network(tmp_path))
    toml = tomllib.loads(lab.generar_configuracion(autoridades, tmp_path / "arti"))
    assert toml["proxy"]["socks_listen"] == 9150
    assert toml["address_filter"]["allow_local_addrs"] is True
    assert toml["path_rules"]["ipv4_subnet_family_prefix"] == 33
    assert toml["path_rules"]["ipv6_subnet_family_prefix"] == 129
    assert toml["override_net_params"]["hsdir_interval"] == 8
    assert len(toml["tor_network"]["fallback_caches"]) == 3
    assert toml["tor_network"]["fallback_caches"][0]["orports"] == ["127.0.0.1:5101"]
    assert len(toml["tor_network"]["authorities"]["v3idents"]) == 3
    assert toml["tor_network"]["authorities"]["v3idents"] == ["C" * 40] * 3
    puertos_directorio = [
        ["127.0.0.1:7101"], ["127.0.0.1:7102"], ["127.0.0.1:7103"]
    ]
    assert toml["tor_network"]["authorities"]["uploads"] == puertos_directorio
    assert toml["tor_network"]["authorities"]["downloads"] == puertos_directorio
    assert toml["tor_network"]["authorities"]["votes"] == puertos_directorio
    assert [cache["orports"] for cache in toml["tor_network"]["fallback_caches"]] == [
        ["127.0.0.1:5101"], ["127.0.0.1:5102"], ["127.0.0.1:5103"]
    ]


@pytest.mark.parametrize("cantidad", [0, 2, 4])
def test_rechaza_un_numero_de_autoridades_distinto_de_tres(tmp_path: Path, cantidad: int):
    crear_autoridades_en_directorios(tmp_path)
    autoridades = list(lab.authorities_from_network(tmp_path))
    autoridades.append(("D" * 40, "E" * 43, "F" * 40, "5104", "7104"))
    with pytest.raises(ValueError, match="tres autoridades"):
        lab.generar_configuracion(autoridades[:cantidad], tmp_path / "arti")


def test_no_inventa_campos_de_configuracion_faltantes():
    with pytest.raises(ValueError, match="DirPort"):
        lab.campo("OrPort 127.0.0.1:5101", r"^DirPort (\d+)$", "DirPort")


def test_genera_configuracion_sin_crear_archivos_ni_ejecutar_arti(tmp_path: Path):
    crear_autoridades_en_directorios(tmp_path)
    carpeta = tmp_path / "sin-crear" / "arti"
    configuracion = lab.generar_configuracion(
        list(lab.authorities_from_network(tmp_path)), carpeta
    )
    assert "127.0.0.1:7103" in configuracion
    assert not carpeta.exists()


def test_toml_con_rutas_windows_y_escapes_internos(tmp_path: Path):
    """Las barras invertidas de Windows no deben convertirse en escapes TOML."""
    crear_autoridades_en_directorios(tmp_path)
    autoridades = list(lab.authorities_from_network(tmp_path))
    ruta_windows = PureWindowsPath(r"C:\Users\test\Tor\arti")
    generado = lab.generar_configuracion(autoridades, ruta_windows)
    toml = tomllib.loads(generado)
    assert toml["storage"]["cache_dir"] == str(ruta_windows / "cache")
    assert toml["storage"]["state_dir"] == str(ruta_windows / "state")
    assert toml["storage"]["port_info_file"] == str(
        ruta_windows / "state" / "public" / "port_info.json"
    )
    assert len(toml["tor_network"]["fallback_caches"]) == 3


def test_toml_escapa_comillas_en_ruta_abstracta(tmp_path: Path):
    """Un nombre de ruta con comillas debe generar una cadena TOML válida."""
    crear_autoridades_en_directorios(tmp_path)
    autoridades = list(lab.authorities_from_network(tmp_path))
    ruta = tmp_path / 'directorio "prueba"' / "arti"
    toml = tomllib.loads(lab.generar_configuracion(autoridades, ruta))
    assert toml["storage"]["cache_dir"] == str(ruta / "cache")


def test_main_rechaza_topologia_ausente_sin_crear_archivos(tmp_path: Path, monkeypatch):
    carpeta_inexistente = tmp_path / "sin-nodos"
    carpeta_arti = tmp_path / "arti"
    monkeypatch.setattr(lab, "NODES", carpeta_inexistente)
    monkeypatch.setattr(lab, "ARTI", carpeta_arti)
    with pytest.raises(FileNotFoundError, match="laboratorio/net/nodes"):
        lab.main()
    assert not carpeta_arti.exists()


def test_main_escribe_toml_en_directorio_temporal(tmp_path: Path, monkeypatch, capsys):
    crear_autoridades_en_directorios(tmp_path)
    carpeta_arti = tmp_path / "arti"
    monkeypatch.setattr(lab, "NODES", tmp_path)
    monkeypatch.setattr(lab, "ARTI", carpeta_arti)
    lab.main()
    archivo = carpeta_arti / "arti.toml"
    assert [ruta.name for ruta in carpeta_arti.iterdir()] == ["arti.toml"]
    datos = tomllib.loads(archivo.read_text(encoding="utf-8"))
    assert datos["proxy"]["socks_listen"] == 9150
    assert len(datos["tor_network"]["authorities"]["v3idents"]) == 3
    assert str(archivo) in capsys.readouterr().out
