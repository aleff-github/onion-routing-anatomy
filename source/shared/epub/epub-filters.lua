-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (C) 2026 Alessandro Greco
--
-- make4ht filters shared by the EPUB editions.
--
-- 1. Alternative text for the display formulas.
--
-- tex4ht turns each display formula into an SVG image and writes its alt text by
-- linearising the formula: fractions are split over several lines, subscripts and
-- underscores are lost, italic identifiers are broken into letters ("PU B K EY").
-- The image is right; the alt text is not usable with a screen reader. Here each
-- display formula of the book gets a curated alt text in linear notation.
--
-- Formulas are recognised by a distinctive token of the generated alt text, with
-- whitespace removed. A display formula that matches no rule is reported on the
-- terminal and keeps its generated alt text; scripts/check_epub.py fails on it.
--
-- 2. No build date as publication date. tex4ebook writes the build time both in
-- dcterms:modified (required by EPUB 3: when the file was last modified) and in
-- dc:date, which EPUB defines as the publication date. The first one is kept; the
-- second one is removed until the edition has a real publication date.
--
-- Usage in source/<language>/epub.mk4:
--   local filters = dofile("../shared/epub/epub-filters.lua")
--   Make:match("html$", filters.display_math_alt("en"))
--   Make:match("opf$", filters.without_build_date)

local M = {}

-- Identifiers and sentences that differ between editions. The translations keep the
-- English protocol identifiers; the Italian edition translates some of them.
local words = {
  it = {
    address = "indirizzo", relay_index = "indice_relay", service_index = "indice_servizio",
    identity = "identità Ed25519", period = "periodo", period_length = "durata", seed = "seme",
    secret_input = "secret_input, ottenuto concatenando i sette valori EXP(X, y), EXP(X, b), ID, B, X, Y e PROTOID.",
  },
  en = {
    secret_input = "secret_input, formed by concatenating the seven values EXP(X, y), EXP(X, b), ID, B, X, Y, and PROTOID.",
  },
  es = {
    secret_input = "secret_input se obtiene concatenando, en este orden, los siete valores: EXP(X, y), EXP(X, b), ID, B, X, Y y PROTOID.",
  },
  ru = {
    secret_input = "secret_input — результат последовательного соединения семи значений: EXP(X, y), EXP(X, b), ID, B, X, Y и PROTOID.",
  },
  ["zh-Hans"] = {
    secret_input = "secret_input 由七项依次拼接组成：EXP(X, y)、EXP(X, b)、ID、B、X、Y 和 PROTOID。",
  },
}

local english = {
  address = "address", relay_index = "relay_index", service_index = "service_index",
  identity = "Ed25519 identity", period = "period", period_length = "period_length", seed = "seed",
}

local function rules(lang)
  local w = setmetatable(words[lang] or {}, { __index = english })
  assert(words[lang], "epub-filters: unknown language " .. tostring(lang))
  return {
    { token = "Trunc",
      alt = "C = P ⊕ Trunc_|P|(AES_K(IV) ∥ AES_K(IV + 1) ∥ …)" },
    { token = "xy⋅G",
      alt = "x · Y = y · X = xy · G" },
    { token = "PROTOID",
      alt = w.secret_input },
    { token = "16384",
      alt = "TLS_RECORD_MAX_CELLS = floor(16384 / 514) = 31" },
    { token = "base32",
      alt = w.address .. ' = base32(PUBKEY ∥ CHECKSUM ∥ VERSION) ∥ ".onion"' },
    { token = "key-blind",
      alt = 'h = SHA3-256("Derive temporary signing key\\0" ∥ A ∥ B ∥ N), N = "key-blind" ∥ '
            .. w.period .. " ∥ " .. w.period_length },
    { token = "=h⋅A",
      alt = "A′ = h · A" },
    { token = "node-idx",
      alt = w.relay_index .. ' = SHA3-256("node-idx" ∥ ' .. w.identity .. " ∥ SRV ∥ "
            .. w.period .. " ∥ " .. w.period_length .. ")" },
    { token = "-idx",
      alt = w.service_index .. '(r) = SHA3-256("store-at-idx" ∥ A′ ∥ r ∥ '
            .. w.period_length .. " ∥ " .. w.period .. ")" },
    { token = "hsintro",
      alt = '"Tor hs intro v1\\0" ∥ A′ ∥ ' .. w.seed .. " ∥ nonce ∥ E" },
    { token = "r(R)",
      alt = "r(N) = floor(r(R) / (frac · 10))" },
    { token = "∑",
      alt = "H(X) = − sum for i = 1 to N of p_i · log2(p_i)" },
    { token = "0≤d≤1",
      alt = "d = H(X) / H_M, 0 ≤ d ≤ 1" },
    { token = "modp",
      alt = "y = (u − 1) / (u + 1) mod p" },
  }
end

-- Rules are tried in order: "node-idx" comes before the generic "-idx" of
-- "store-at-idx", which tex4ht may split as "store -at-idx".
local function curated_alt(list, generated)
  local compact = generated:gsub("%s+", "")
  for _, rule in ipairs(list) do
    if compact:find(rule.token, 1, true) then
      return rule.alt
    end
  end
end

function M.display_math_alt(lang)
  local domfilter = require "make4ht-domfilter"
  local list = rules(lang)
  return domfilter {
    function(dom)
      local images = dom:query_selector("img.math-display, div.gather-star img")
      for _, img in ipairs(images) do
        local generated = img:get_attribute("alt") or ""
        local alt = curated_alt(list, generated)
        if alt then
          img:set_attribute("alt", alt)
        else
          io.stderr:write("epub-filters: no curated alt text for: " .. generated .. "\n")
        end
      end
      return dom
    end,
  }
end

function M.without_build_date(filename)
  local f = assert(io.open(filename, "r"))
  local opf = f:read("*a")
  f:close()
  opf = opf:gsub("<dc:date>[^<]*</dc:date>%s*", "")
  f = assert(io.open(filename, "w"))
  f:write(opf)
  f:close()
end

M.rules = rules
return M
