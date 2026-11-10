-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (C) 2026 Alessandro Greco
--
-- listings and characters above U+00FF under LuaTeX.
--
-- listings reads a listing character by character and keeps letters in a buffer
-- before typesetting them. It only knows characters up to U+00FF: Cyrillic or
-- Chinese characters skip the buffer and are typeset at once, so they move with
-- respect to the ASCII around them and the spaces between them get lost
-- ("TLS-сертификат не совпадает" became "TLSсертификат- несовпадает", "流 1：209 字节"
-- became "流：1209 字节"). Both the PDF and the EPUB were affected.
--
-- While a lstlisting environment is being read, this callback wraps each run of
-- such characters (with the spaces inside the run) in the listings escape
-- character ` (escapechar, set in macro.tex): the run is typeset as ordinary text,
-- in its place. The backtick appears in no listing of the book; if one is ever
-- needed, the escape character has to change.

local lstunicode = {}
local ESCAPE = "`"

-- Byte that starts a UTF-8 character at or above U+0100: 0xC4-0xF4.
local function is_high_lead(byte)
  return byte >= 0xC4 and byte <= 0xF4
end

local function char_len(byte)
  if byte >= 0xF0 then return 4 elseif byte >= 0xE0 then return 3 elseif byte >= 0xC0 then return 2 end
  return 1
end

function lstunicode.wrap(line)
  local out, i, n = {}, 1, #line
  while i <= n do
    local b = line:byte(i)
    if is_high_lead(b) then
      -- run of high characters, spaces allowed inside the run
      local j, last = i, i
      while j <= n do
        local c = line:byte(j)
        if is_high_lead(c) then
          j = j + char_len(c)
          last = j
        elseif c == 32 then
          j = j + 1
        else
          break
        end
      end
      out[#out + 1] = ESCAPE .. line:sub(i, last - 1) .. ESCAPE
      i = last
    else
      local len = char_len(b)
      out[#out + 1] = line:sub(i, i + len - 1)
      i = i + len
    end
  end
  return table.concat(out)
end

function lstunicode.enable()
  luatexbase.add_to_callback("process_input_buffer", lstunicode.wrap, "lstunicode")
end

function lstunicode.disable()
  if luatexbase.in_callback("process_input_buffer", "lstunicode") then
    luatexbase.remove_from_callback("process_input_buffer", "lstunicode")
  end
end

return lstunicode
