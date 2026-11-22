#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Compare all 31 chapters, 4 appendices and bibliography against shipped A4.

Character multiplicities are independent of float order and line wrapping.
They are a diagnostic (not a mathematical or translation proof). Code is
checked separately without discarding punctuation by check_print.py.
"""
from collections import Counter
import difflib
import hashlib
import json
from pathlib import Path
import re
import sys
import unicodedata
import pymupdf as fitz
from build_print import ROOT, WORK, AUDIT, EDITIONS


def norm(s):
    # Discretionary hyphens and whitespace disappear, but all letters and digits
    # remain. Order can change when figures/tables move; counters preserve counts.
    return ''.join(c for c in unicodedata.normalize('NFKC',s) if c.isalnum())


def extract(doc, first, last, top, bottom):
    return '\n'.join(doc[i].get_text(clip=fitz.Rect(0,top,doc[i].rect.width,bottom)) for i in range(first-1,last-1))


def compare(lang):
    entry,name=EDITIONS[lang]
    old=fitz.open(ROOT/'book'/lang/f'{name}_A4.pdf')
    new=fitz.open(ROOT/'book'/lang/f'{name}_7x10.pdf')
    old_toc=[x for x in old.get_toc() if x[0]==2]
    toc=(WORK/lang/'source'/lang/f'{entry}.toc').read_text()
    pages=[]
    for line in toc.splitlines():
        if line.startswith(r'\contentsline {chapter}'):
            m=re.search(r'\}\{(\d+)\}\{[^{}]*\}%?$',line)
            if m:pages.append(int(m.group(1)))
    assert len(old_toc)==len(pages)==37, (lang,len(old_toc),len(pages))
    offset=next(i for i,p in enumerate(new) if p.get_label()=='1')
    print_pages=[p+offset for p in pages]
    report=[]
    for i in range(36):
        a=extract(old,old_toc[i][2],old_toc[i+1][2],68,760)
        b=extract(new,print_pages[i],print_pages[i+1],50,670)
        aa,bb=norm(a),norm(b)
        ca,cb=Counter(aa),Counter(bb)
        missing=ca-cb;added=cb-ca
        item={'title':old_toc[i][1],'a4_page_range':[old_toc[i][2],old_toc[i+1][2]-1],
              'print_page_range':[print_pages[i],print_pages[i+1]-1],
              'a4_alphanumeric':len(aa),'print_alphanumeric':len(bb),
              'same_character_multiset':ca==cb,'missing':dict(missing),'added':dict(added)}
        item['equivalent_after_repeated_header_removal']=ca==cb
        if i==31 and lang in {'it','zh-Hans'}:
            header={'it':'TermineIngleseSignificatoCap','zh-Hans':'术语含义章'}[lang]
            item['glossary_header']={'text':header,'a4_count':aa.count(header),'print_count':bb.count(header)}
            item['equivalent_after_repeated_header_removal']=Counter(aa.replace(header,''))==Counter(bb.replace(header,''))
        if missing or added:
            # Segment differences in normalized reading order for manual diagnosis.
            matcher=difflib.SequenceMatcher(None,aa,bb,autojunk=False)
            item['differences']=[{'kind':op,'a4':aa[max(0,x-45):min(len(aa),y+45)],
                                  'print':bb[max(0,u-45):min(len(bb),v+45)]}
                                for op,x,y,u,v in matcher.get_opcodes() if op!='equal']
        report.append(item)
    result={'language':lang,'sections':report,'identical_character_multisets':sum(x['same_character_multiset'] for x in report),
            'a4_sha256':hashlib.sha256((ROOT/'book'/lang/f'{name}_A4.pdf').read_bytes()).hexdigest(),
            'print_sha256':hashlib.sha256((ROOT/'book'/lang/f'{name}_7x10.pdf').read_bytes()).hexdigest(),
            'status':'PASS' if all(x['equivalent_after_repeated_header_removal'] for x in report) else 'REVIEW',
            'limitations':'Ignores punctuation, whitespace and ordering. Does not independently certify mathematical symbols, images or indentation; combine with code/font/source/visual checks.'}
    (AUDIT/f'{lang}-content-comparison.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(lang,result['status'],result['identical_character_multisets'],'/36 raw sections identical; repeated glossary headers accounted separately',flush=True)
    return result

if __name__=='__main__':
    results=[compare(lang) for lang in sys.argv[1:] or EDITIONS]
    sys.exit(1 if any(r['status']!='PASS' for r in results) else 0)
