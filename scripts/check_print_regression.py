#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Check byte preservation of digital assets, shared content and existing recipes."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent.parent
BASE='0f1361a87e7dfc7db1e52331024cbde3547b1420'
OUT=ROOT/'build/print-audit'
# The book edition index is documentation, not a pre-existing digital artifact.
# PDF A4, EPUB, covers and scientific inputs remain byte-checked below.
ALLOWED={'book/README.md', 'source/it/stampa.tex',*(f'source/{l}/Makefile' for l in ['en','es','ru','zh-Hans'])}
# These seven figure sources deliberately add print-only typography. They are not
# byte-identical to the A4 sources; independently verify that removing the print
# branch reconstructs exactly the original digital figure (ignoring indentation).
PRINT_FIG23={
    'source/it/figure/fig23-architetture.tex',
    'source/en/figures/fig23-architectures.tex',
    'source/es/figuras/fig23-arquitecturas.tex',
    'source/ru/рисунки/рис23-архитектуры.tex',
    'source/zh-Hans/图/图23-架构.tex',
}
PRINT_FIG10={'source/es/figuras/fig10-cebolla.tex',
             'source/ru/рисунки/рис10-луковица.tex'}
PRINT_ONLY_FIGURES=PRINT_FIG23 | PRINT_FIG10

def normalized_lines(s):
    return '\n'.join(line.strip() for line in s.splitlines() if line.strip())

def print_figure_preserves_digital(original, current, name):
    """Prove only print-conditional code changed, preserving the A4 fallback."""
    import re
    old=original.decode('utf-8')
    new=current.decode('utf-8')
    if name in PRINT_FIG23:
        # Two separate TikZ nodes use the original node/arrow verbatim on A4.
        rx=r'\\ifdefined\\PrintEdition\s*\n[\s\S]*?\\else\s*\n([\s\S]*?)\n\s*\\fi'
        matches=list(re.finditer(rx,new))
        if len(matches)!=2 or new.count(r'\ifdefined\PrintEdition')!=2:
            return False
        restored=re.sub(rx, lambda m:m.group(1), new)
    elif name in PRINT_FIG10:
        # The legend keeps its original scriptsize font on A4.
        marker='% Print-only smaller relay circles and a legible, separated legend.'
        if (new.count(marker)!=1 or new.count(r'\ifdefined\PrintEdition')!=1
                or r'\def\OnionLegendFont{\scriptsize}' not in new
                or r'\def\OnionLegendFont{\tiny}' not in new
                or new.count(r'\OnionLegendFont')!=5):
            # Two definitions plus three labels must remain.
            return False
        restored=re.sub(r'\\ifdefined\\PrintEdition[\s\S]*?\\else[\s\S]*?\\fi',
                        '',new,count=1)
        restored=restored.replace(r'\OnionLegendFont',r'\scriptsize')
        if name == 'source/ru/рисунки/рис10-луковица.tex':
            # A4 uses exactly the original coordinates; only the 7x10 legend
            # shifts the third item away from the longer Russian middle label.
            if (new.count(r'\OnionLegendThirdX') != 3
                    or new.count(r'\OnionLegendThirdLabelX') != 3):
                return False
            restored=restored.replace(r'\OnionLegendThirdX','6.0')
            restored=restored.replace(r'\OnionLegendThirdLabelX','6.35')
        restored=re.sub(r'^[ \t]*% Print-only smaller relay circles and a legible, separated legend.\r?\n',
                        '',restored,flags=re.M)
    else:
        return False
    return (r'\ifdefined\PrintEdition' not in restored
            and normalized_lines(old)==normalized_lines(restored))


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    files=subprocess.check_output(['git','ls-tree','-r','--name-only','-z',BASE],cwd=ROOT).decode().split('\0')
    records=[]
    for name in files:
        if not name or name in ALLOWED or name.endswith('_7x10.pdf'): continue
        if not name.startswith(('source/','book/','assets/','website/static/')): continue
        before=subprocess.check_output(['git','show',f'{BASE}:{name}'],cwd=ROOT)
        f=ROOT/name
        old=hashlib.sha256(before).hexdigest()
        new=hashlib.sha256(f.read_bytes()).hexdigest() if f.exists() else None
        unchanged=(old==new)
        a4_figure_equivalent=False
        if name in PRINT_ONLY_FIGURES and not unchanged and f.is_file():
            a4_figure_equivalent=print_figure_preserves_digital(before,f.read_bytes(),name)
        records.append({'path':name,'base_sha256':old,'current_sha256':new,
                        'unchanged':unchanged,'print_only_a4_equivalent':a4_figure_equivalent})
    # Compare expanded recipes, without running any digital compilation or publisher.
    original=OUT/'baseline.Makefile'
    original.write_bytes(subprocess.check_output(['git','show',f'{BASE}:Makefile'],cwd=ROOT))
    recipes=[]
    for target in ['book-pdf','book-epub','cover','book-traduzioni','composizione','epub-check','pulisci']:
        commands=[]
        for makefile in [str(original),'Makefile']:
            r=subprocess.run(['make','--no-print-directory','-n','-f',makefile,target],cwd=ROOT,capture_output=True,text=True)
            commands.append((r.returncode,r.stdout,r.stderr))
        recipes.append({'target':target,'identical':commands[0]==commands[1],'exit_code':commands[1][0]})
    report={'base':BASE,'files':records,'digital_recipes':recipes,
            'limitation':'Existing published binaries and source inputs are compared byte for byte. This does not assert bit-reproducibility of a new digital build with a newer TeX distribution.'}
    valid_figures={x['path'] for x in records if x['print_only_a4_equivalent']}
    ok=(valid_figures==PRINT_ONLY_FIGURES
        and all(x['unchanged'] or x['print_only_a4_equivalent'] for x in records)
        and all(x['identical'] and x['exit_code']==0 for x in recipes))
    report['status']='PASS' if ok else 'FAIL'
    (OUT/'regression.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(report['status'],len(records),'source/asset checks;',
          len(valid_figures),'verified print-only figure exceptions;',
          len(recipes),'existing recipes')
    for r in recipes:
        if not r['identical']: print(r)
    sys.exit(0 if ok else 1)

if __name__=='__main__':main()
