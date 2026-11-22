#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Audit every print page; optional complete raster and contact-sheet generation.

Requires PyMuPDF, Pillow, pdffonts. Machine checks are NOT visual approval.
Reports retain suspicious pages, not silently waive them.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import unicodedata
import pymupdf as fitz
from PIL import Image, ImageDraw
from build_print import EDITIONS, ROOT, WORK, AUDIT
from check_pdf_code import frammenti_inline, righe_listato


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def compact(s):
    return re.sub(r'\s+', '', unicodedata.normalize('NFKC', s)).replace('\u00ad','')


def body_text(doc, top, bottom):
    # Exclude running heads and page numbers, preserve content across page breaks.
    return '\n'.join(p.get_text(clip=fitz.Rect(0,top,p.rect.width,bottom)) for p in doc)


def audit(lang, render=False):
    entry, name = EDITIONS[lang]
    pdf = ROOT / 'book' / lang / f'{name}_7x10.pdf'
    if not pdf.exists():
        return {'language':lang,'errors':['PDF missing'],'status':'FAIL'}
    doc = fitz.open(pdf)
    report = dict(language=lang,path=str(pdf.relative_to(ROOT)),bytes=pdf.stat().st_size,
                  sha256=sha(pdf),pages=len(doc),metadata=doc.metadata,
                  errors=[],warnings=[],page_checks=[],visual_review='NOT performed by this script')
    titles={'it':'Anatomia di Tor','en':'Anatomy of Tor','es':'Anatomía de Tor','ru':'Анатомия Tor','zh-Hans':'Tor 解剖'}
    report['pdf_language']=doc.xref_get_key(doc.pdf_catalog(),'Lang')[1]
    report['page_label_rules']=doc.get_page_labels()
    report['colophon_version_present']='1.0.0' in doc[3].get_text()
    if (doc.metadata.get('title')!=titles[lang] or doc.metadata.get('author')!='Alessandro Greco'
        or not report['pdf_language'].startswith(lang) or not report['colophon_version_present']):
        report['errors'].append('Incorrect title/author/language/version')
    labels=[p.get_label() for p in doc]
    offset=next((i for i,label in enumerate(labels) if label=='1'),None)
    if offset is None or offset%2 or labels[offset:]!=[str(n) for n in range(1,len(doc)-offset+1)]:
        report['errors'].append('Main-matter page labels not sequential or start on verso')
    if len(doc)%2: report['errors'].append('Odd page count')
    build_record = AUDIT / f'{lang}-build.json'
    if not build_record.exists():
        report['errors'].append('Missing successful build record')
    else:
        build = json.loads(build_record.read_text())
        if build.get('exit_code') != 0 or build.get('sha256') != report['sha256']:
            report['errors'].append('PDF does not match the latest successful build')
        inputs = build.get('input_sha256', {})
        if not inputs or any(not (ROOT / f).exists() or sha(ROOT / f) != digest
                             for f, digest in inputs.items()):
            report['errors'].append('Source inputs changed since recorded build; rebuild required')
    stage = WORK / lang / 'source' / lang
    tocpath=stage/f'{entry}.toc'
    chapter_pages=[]
    if tocpath.exists():
        for line in tocpath.read_text().splitlines():
            if line.startswith(r'\contentsline {chapter}'):
                match=re.search(r'\}\{(\d+)\}\{[^{}]*\}%?$',line)
                if match: chapter_pages.append(int(match.group(1)))
    report['toc_chapter_appendix_bibliography_index_pages']=chapter_pages
    if (len(chapter_pages)!=37 or chapter_pages!=sorted(set(chapter_pages)) or
        any(n%2!=1 or n>len(doc)-(offset or 0) for n in chapter_pages)):
        report['errors'].append('Missing/nonsequential chapter TOC entries or non-recto start')
    logpath = stage / f'{entry}.log'
    if not logpath.exists():
        report['errors'].append('Missing build log')
        log = ''
    else:
        log=logpath.read_text(errors='replace')
    fatal_patterns=[r'Missing character:.*',r'^!.*',r'^.*LaTeX Error:.*',r'^.*undefined references.*',r'^.*Citation .+ undefined.*',r'^.*Reference .+ undefined.*',r'^.*Empty bibliography.*']
    report['latex_errors']=[x for pat in fatal_patterns for x in re.findall(pat,log,re.M)]
    if report['latex_errors']: report['errors'].append('LaTeX errors, missing glyphs or unresolved references')
    report['overfull_boxes']=re.findall(r'Overfull \\[hv]box[^\n]*',log)
    report['font_warnings']=re.findall(r'.*(?:Font Warning|[Ff]ont shape.*undefined).*',log)
    if report['font_warnings']: report['errors'].append('Unresolved font warnings')
    report['underfull_count']=len(re.findall('Underfull',log))
    if report['overfull_boxes']: report['errors'].append(f"{len(report['overfull_boxes'])} overfull boxes require correction/review")
    fonts=subprocess.check_output(['pdffonts',str(pdf)],text=True)
    (AUDIT / f'{lang}-fonts.txt').write_text(fonts)
    report['fonts']=fonts.splitlines()[2:]
    if not report['fonts'] or any(not re.search(r'\byes\s+(?:yes|no)\s+(?:yes|no)\s+\d+\s+\d+\s*$',f) for f in report['fonts']):
        report['errors'].append('Unembedded font or unexpected pdffonts result')
    if doc.is_encrypted: report['errors'].append('Encrypted PDF')
    # FLS proves all A4 chapter/appendix/figure inputs were actually opened.
    fls=(stage / f'{entry}.fls').read_text(errors='replace') if (stage/f'{entry}.fls').exists() else ''
    structure={'it':'struttura','en':'structure','es':'estructura','ru':'структура','zh-Hans':'结构'}[lang]
    expected=re.findall(r'\\include\{([^}]+)\}',(ROOT/'source'/lang/f'{structure}.tex').read_text())
    figure_dir={'it':'figure','en':'figures','es':'figuras','ru':'рисунки','zh-Hans':'图'}[lang]
    figures=sorted((ROOT/'source'/lang/figure_dir).glob('*.tex'))
    report['included_figures']={str(f.relative_to(ROOT/'source'/lang)): str(f.relative_to(ROOT/'source'/lang)) in fls for f in figures}
    if not all(report['included_figures'].values()): report['errors'].append('Missing figure input')
    report['included_chapters_appendices']={x: f'{x}.tex' in fls for x in expected}
    if len(expected)!=35 or not all(report['included_chapters_appendices'].values()): report['errors'].append('Missing chapter/appendix input')
    bbl=stage/f'{entry}.bbl';ind=stage/f'{entry}.ind'
    report['bibliography_entries']=len(re.findall(r'\\entry\{',bbl.read_text())) if bbl.exists() else 0
    report['index_items']=len(re.findall(r'\\(?:sub)?item\b',ind.read_text())) if ind.exists() else 0
    if not report['bibliography_entries'] or not report['index_items']: report['errors'].append('Missing bibliography/index')
    text=body_text(doc,50,670)
    c=compact(text)
    report['code_missing']=[]
    for s,f in frammenti_inline(lang).items():
        if compact(s) not in c and compact(s).replace('…','...') not in c: report['code_missing'].append({'source':f,'text':s,'kind':'inline'})
    for f,s in righe_listato(lang):
        if compact(s) not in c and compact(s).replace('…','...') not in c: report['code_missing'].append({'source':f,'text':s,'kind':'listing'})
    if report['code_missing']: report['errors'].append(f"{len(report['code_missing'])} extracted code fragments differ; inspect ordering/wrapping")
    a4=ROOT/'book'/lang/f'{name}_A4.pdf'
    old=fitz.open(a4)
    # Counter is a diagnostic only: line breaks, headers, TOC page references,
    # ligatures, math, reading order and index pagination legitimately differ.
    def words(t):
        t=re.sub(r'(?<=\w)[-\u00ad]\s*\n\s*(?=\w)','',t)
        return Counter(re.findall(r'[^\W\d_]+',unicodedata.normalize('NFKC',t).casefold()))
    wc_old,wc_new=words(body_text(old,68,760)),words(text)
    missing=wc_old-wc_new
    report['a4_comparison']={'a4_sha256':sha(a4),'a4_pages':len(old),
        'token_count_a4':sum(wc_old.values()),'token_count_print':sum(wc_new.values()),
        'missing_token_count':sum(missing.values()),'missing_tokens':missing.most_common(),
        'limitation':'Diagnostic, not semantic proof: front matter, headers, hyphenation, reading order and index page references differ.'}
    out=AUDIT/'render'/lang
    if render: out.mkdir(parents=True,exist_ok=True)
    blank=[]
    for i,page in enumerate(doc):
        n=i+1
        info={'page':n,'label':page.get_label(),'size_pt':[page.rect.width,page.rect.height],
              'text_outside_page':[],'text_outside_safe_area':[],'body_outside_margins':[], 'missing_glyphs':0,
              'punctuation_ink_measurements':[]}
        punctuation_raster = None
        if abs(page.rect.width-504)>.02 or abs(page.rect.height-720)>.02 or page.rotation:
            report['errors'].append(f'Wrong size/rotation page {n}')
        for span in page.get_texttrace():
            for u,g,origin,b in span['chars']:
                if chr(u).isspace():continue
                x0,y0,x1,y1=b
                if g==0: info['missing_glyphs']+=1
                left,right=(72,465.84) if n%2 else (38.16,432)
                # CJK punctuation has a full-em advance box although LuaTeX-ja
                # compresses its blank side bearing. Measure visible ink for
                # margin candidates, retaining both boxes as audit evidence.
                if (unicodedata.category(chr(u)).startswith('P') and
                    (x0<left-.8 or x1>right+.8)):
                    if punctuation_raster is None:
                        pp=page.get_pixmap(matrix=fitz.Matrix(4,4),colorspace=fitz.csGRAY,alpha=False)
                        punctuation_raster=Image.frombytes('L',(pp.width,pp.height),pp.samples)
                    crop=(max(0,math.floor(x0*4)),max(0,math.floor(y0*4)),
                          min(2016,math.ceil(x1*4)),min(2880,math.ceil(y1*4)))
                    ink=punctuation_raster.crop(crop).point(lambda v:255 if v<235 else 0).getbbox()
                    if ink:
                        actual=[(ink[0]+crop[0])/4,(ink[1]+crop[1])/4,
                                (ink[2]+crop[0])/4,(ink[3]+crop[1])/4]
                        info['punctuation_ink_measurements'].append({'character':chr(u),'advance_box':list(b),'ink_box':actual,'dpi':288})
                        x0,y0,x1,y1=actual
                if x0<-.5 or y0<-.5 or x1>504.5 or y1>720.5: info['text_outside_page'].append(chr(u))
                if x0<35.3 or y0<35.3 or x1>468.7 or y1>684.7: info['text_outside_safe_area'].append(chr(u))
                if y0>=54 and y1<=668 and (x0<left-.8 or x1>right+.8): info['body_outside_margins'].append(chr(u))
        info['links']=len(page.get_links())
        for key in ['text_outside_page','text_outside_safe_area','body_outside_margins']:
            info[key]=''.join(info[key])
        pix=page.get_pixmap(matrix=fitz.Matrix(100/72,100/72),colorspace=fitz.csRGB,alpha=False)
        im=Image.frombytes('RGB',(pix.width,pix.height),pix.samples)
        mask=im.convert('L').point(lambda x:255 if x<235 else 0)
        bbox=mask.getbbox()
        info['ink_bbox_pt']=[round(v*72/100,2) for v in bbox] if bbox else None
        if bbox is None: blank.append(n)
        elif min(info['ink_bbox_pt'][:2]) < 35 or info['ink_bbox_pt'][2] > 469 or info['ink_bbox_pt'][3] > 685:
            report['warnings'].append(f'Raster ink outside 0.5in safety area page {n}')
        if info['text_outside_page'] or info['missing_glyphs']: report['errors'].append(f'Clipped text/missing glyph page {n}')
        if info['text_outside_safe_area'] or info['body_outside_margins']:
            report['warnings'].append(f'Text margin candidate page {n}')
        if render: im.save(out/f'page-{n:04}.png')
        report['page_checks'].append(info)
    report['blank_pages']=blank
    if any(n % 2 for n in blank): report['warnings'].append('Unexpected blank recto page')
    report['page_size_pt']=[doc[0].rect.width,doc[0].rect.height]
    if len(doc)>400: report['errors'].append('Page count >400: increase inner margin to at least 1.125in')
    if any(x['links'] for x in report['page_checks']): report['warnings'].append('PDF contains clickable links')
    if render:
        sheets=out/'sheets';sheets.mkdir(exist_ok=True)
        for first in range(0,len(doc),16):
            sheet=Image.new('RGB',(1400,2080),'#dddddd');draw=ImageDraw.Draw(sheet)
            for k in range(first,min(first+16,len(doc))):
                im=Image.open(out/f'page-{k+1:04}.png');im.thumbnail((336,480))
                x=(k-first)%4*350+7;y=(k-first)//4*520+25
                sheet.paste(im,(x,y));draw.text((x,y-19),f'{lang}  PDF {k+1}',fill='black')
            sheet.save(sheets/f'{first+1:04}-{min(first+16,len(doc)):04}.jpg',quality=92)
        report['render']={'dpi':100,'pages':len(doc),'folder':str(out.relative_to(ROOT)), 'contact_sheet_pages':16}
        # Remove obsolete generated previews after a page-count change only.
        expected_pages={f'page-{n:04}.png' for n in range(1,len(doc)+1)}
        expected_sheets={f'{n+1:04}-{min(n+16,len(doc)):04}.jpg' for n in range(0,len(doc),16)}
        for path in out.glob('page-*.png'):
            if path.name not in expected_pages: path.unlink()
        for path in sheets.glob('*.jpg'):
            if path.name not in expected_sheets: path.unlink()
    report['status']='FAIL' if report['errors'] else ('REVIEW' if report['warnings'] else 'AUTOMATED_PASS')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('languages',nargs='*',default=list(EDITIONS))
    p.add_argument('--render',action='store_true')
    args=p.parse_args()
    AUDIT.mkdir(parents=True,exist_ok=True)
    results=[]
    for lang in args.languages:
        if lang not in EDITIONS: p.error('Unknown language '+lang)
        r=audit(lang,args.render)
        (AUDIT/f'{lang}-audit.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n')
        print(lang,r['status'],r.get('pages'),r['errors'],len(r.get('warnings',[])),flush=True)
        results.append(r)
    sys.exit(1 if any(r['status'] in {'FAIL','REVIEW'} for r in results) else 0)

if __name__=='__main__': main()
