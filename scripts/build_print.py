#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Isolated local/Docker print build; never writes digital auxiliaries or assets."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
EDITIONS = {
    'it': ('stampa', 'anatomia-di-tor_it'),
    'en': ('print', 'anatomy-of-tor_en'),
    'es': ('impresion', 'anatomía-de-tor_es'),
    'ru': ('печать', 'анатомия-tor_ru'),
    'zh-Hans': ('印刷', 'tor-解剖_zh-Hans'),
}
WORK = ROOT / 'build/print-work'
AUDIT = ROOT / 'build/print-audit'
# Stable PDF timestamps and trailer IDs; scientific text is unaffected.
EPOCH = '1794300000'


def prepare(language):
    # Each language gets its own full, small source tree, so concurrent builds
    # cannot race on shared files, chapter auxiliaries, biber or makeindex.
    stage = WORK / language
    for f in (ROOT / 'source').rglob('*'):
        if f.is_file() and f.suffix in {'.tex', '.lua', '.bib', '.sty', '.cls', '.ist'} and f.name != 'solo.tex':
            dst = stage / f.relative_to(ROOT)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if not dst.exists() or dst.read_bytes() != f.read_bytes():
                shutil.copyfile(f, dst)
    return stage


def input_hashes(language):
    """Hash project inputs actually opened by TeX plus its bibliography/Lua bridge."""
    stage = WORK / language
    cwd = stage / 'source' / language
    entry = EDITIONS[language][0]
    inputs = {}
    paths = [line[6:] for line in (cwd / f'{entry}.fls').read_text().splitlines()
             if line.startswith('INPUT ')]
    paths += ['../shared/bibliography/tor.bib', '../shared/lst-unicode.lua']
    for name in paths:
        path = Path(name)
        if name.startswith('/w/'):
            path = ROOT / name[3:]
        elif not path.is_absolute():
            path = cwd / path
        path = path.resolve()
        if not path.is_relative_to(stage) or path.suffix not in {'.tex', '.lua', '.bib', '.sty', '.cls', '.ist'}:
            continue
        inputs[str(path.relative_to(stage))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(sorted(inputs.items()))


def build(language, image):
    stage = prepare(language)
    entry, name = EDITIONS[language]
    cwd = stage / 'source' / language
    args = ['latexmk', '-lualatex', '-interaction=nonstopmode', '-halt-on-error',
            '-file-line-error', '-recorder', entry + '.tex']
    env = os.environ.copy()
    env.update(SOURCE_DATE_EPOCH=EPOCH, FORCE_SOURCE_DATE='1')
    engine = 'local'
    if not shutil.which('latexmk'):
        subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], check=True, capture_output=True, timeout=60)
        engine = subprocess.check_output(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], text=True).strip()
        cache = ROOT / 'build/print-tex-cache' / language
        (cache / 'xdg').mkdir(parents=True, exist_ok=True)
        (cache / 'texmf-var').mkdir(exist_ok=True)
        rel = cwd.relative_to(ROOT)
        args = ['docker', 'run', '--rm', '--network=none', '--cpus=2', '--memory=6g',
                '-u', f'{os.getuid()}:{os.getgid()}',
                '-e', f'SOURCE_DATE_EPOCH={EPOCH}', '-e', 'FORCE_SOURCE_DATE=1',
                '-e', f'HOME=/w/build/print-tex-cache/{language}',
                '-e', f'XDG_CACHE_HOME=/w/build/print-tex-cache/{language}/xdg',
                '-e', f'TEXMFVAR=/w/build/print-tex-cache/{language}/texmf-var',
                '-v', f'{ROOT}:/w', '-w', f'/w/{rel}', image] + args
    AUDIT.mkdir(parents=True, exist_ok=True)
    with (AUDIT / f'{language}-build.log').open('w') as log:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    record = {'language': language, 'command': args, 'engine': engine,
              'source_date_epoch': EPOCH, 'exit_code': result.returncode}
    if result.returncode == 0:
        pdf = cwd / f'{entry}.pdf'
        dest = ROOT / 'book' / language / f'{name}_7x10.pdf'
        # Publish only a completed latexmk result, atomically.
        tmp = dest.with_suffix('.pdf.tmp')
        shutil.copyfile(pdf, tmp)
        tmp.replace(dest)
        record.update(input_sha256=input_hashes(language), path=str(dest.relative_to(ROOT)), bytes=dest.stat().st_size,
                      sha256=hashlib.sha256(dest.read_bytes()).hexdigest())
    (AUDIT / f'{language}-build.json').write_text(json.dumps(record, ensure_ascii=False, indent=2)+'\n')
    print(f'{language}: latexmk exit {result.returncode}; log: {AUDIT / (language+"-build.log")}', flush=True)
    return result.returncode


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('language', choices=[*EDITIONS, 'all'])
    p.add_argument('--image', default=os.environ.get('IMMAGINE', 'texlive/texlive:latest'))
    p.add_argument('--clean', action='store_true', help='Remove only isolated print intermediates, preserving PDFs/audit/cache')
    a = p.parse_args()
    languages = list(EDITIONS) if a.language == 'all' else [a.language]
    if a.clean:
        for lang in languages:
            if (WORK / lang).exists():
                shutil.rmtree(WORK / lang)
        return
    sys.exit(max(build(lang, a.image) for lang in languages))

if __name__ == '__main__':
    main()
