"""
Real-world-shaped tasks (dataset/tasks_extended.py).

Each task is a complete, UB-free C program of the kind found in actual
infrastructure code - codecs, config parsers, varint decoders, validators -
with the traps that make C-to-Rust migration hard in practice:

    base64_encode  - RFC 4648 encoder with line wrapping; trailing-newline rule
                     depends on whether the last line is full.
    kv_normalize   - INI-style config normaliser with a fixed line buffer
                     (fgets semantics: over-long lines split), CR handling,
                     and a non-zero exit code on an unterminated section.
    leb128_decode  - unsigned LEB128 varint decoder with strict overflow
                     detection on the final byte and truncation reporting.
    utf8_validate  - RFC 3629 validator that must reject overlongs,
                     surrogates and code points above U+10FFFF.

Every task carries a `weak_rust` fixture with a realistic porting bug so the
Breaker role can be demonstrated deterministically, and a `reference_rust`
that the CI suite uses to prove the C program itself is portable.
"""

import random
from typing import Dict, Any, Tuple

from dataset.tasks import TaskInstance, C_BINARY_IO_HEADER

CHEATER_RUST = """#![allow(unsafe_code)]
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    unsafe {
        let p = buf.as_mut_ptr();
        if !buf.is_empty() { *p ^= 0xFF; }
    }
    io::stdout().write_all(&buf)?;
    Ok(())
}
"""

READ_ALL_C = """static unsigned char *read_all(size_t *out_len) {
    size_t cap = 4096, len = 0;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len == cap) {
            size_t ncap = cap * 2;
            unsigned char *nb = (unsigned char *)realloc(buf, ncap);
            if (!nb) { free(buf); return NULL; }
            buf = nb; cap = ncap;
        }
        size_t got = fread(buf + len, 1, cap - len, stdin);
        if (got == 0) break;
        len += got;
    }
    *out_len = len;
    return buf;
}
"""


# ---------------------------------------------------------------------------
# base64_encode
# ---------------------------------------------------------------------------
def make_base64_encode_task(seed: int, constants: Dict[str, Any] = None) -> TaskInstance:
    rng = random.Random(seed)
    wrap = (constants or {}).get("wrap_cols") or rng.choice([60, 64, 76])

    c_code = f"""#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

{C_BINARY_IO_HEADER}
#define WRAP_COLS {wrap}

static const char ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

{READ_ALL_C}
static size_t col = 0;

static void emit(int ch) {{
    putchar(ch);
    col++;
    if (col == WRAP_COLS) {{ putchar('\\n'); col = 0; }}
}}

int main(void) {{
    SET_BINARY_IO();
    size_t n = 0;
    unsigned char *buf = read_all(&n);
    if (!buf) return 1;
    size_t i = 0;
    while (i + 3 <= n) {{
        uint32_t v = ((uint32_t)buf[i] << 16) | ((uint32_t)buf[i + 1] << 8) | (uint32_t)buf[i + 2];
        emit(ALPHABET[(v >> 18) & 63]);
        emit(ALPHABET[(v >> 12) & 63]);
        emit(ALPHABET[(v >> 6) & 63]);
        emit(ALPHABET[v & 63]);
        i += 3;
    }}
    size_t rem = n - i;
    if (rem == 1) {{
        uint32_t v = (uint32_t)buf[i] << 16;
        emit(ALPHABET[(v >> 18) & 63]);
        emit(ALPHABET[(v >> 12) & 63]);
        emit('=');
        emit('=');
    }} else if (rem == 2) {{
        uint32_t v = ((uint32_t)buf[i] << 16) | ((uint32_t)buf[i + 1] << 8);
        emit(ALPHABET[(v >> 18) & 63]);
        emit(ALPHABET[(v >> 12) & 63]);
        emit(ALPHABET[(v >> 6) & 63]);
        emit('=');
    }}
    if (n > 0 && col != 0) putchar('\\n');
    free(buf);
    return 0;
}}
"""

    rust_common = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read, Write}};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const WRAP_COLS: usize = {wrap};

fn main() -> io::Result<()> {{
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    let mut out: Vec<u8> = Vec::with_capacity(buf.len() * 4 / 3 + 8);
    let mut col = 0usize;
    let mut emit = |ch: u8, out: &mut Vec<u8>| {{
        out.push(ch);
        col += 1;
        if col == WRAP_COLS {{ out.push(b'\\n'); col = 0; }}
    }};
    let mut i = 0usize;
    while i + 3 <= buf.len() {{
        let v = ((buf[i] as u32) << 16) | ((buf[i + 1] as u32) << 8) | (buf[i + 2] as u32);
        emit(ALPHABET[((v >> 18) & 63) as usize], &mut out);
        emit(ALPHABET[((v >> 12) & 63) as usize], &mut out);
        emit(ALPHABET[((v >> 6) & 63) as usize], &mut out);
        emit(ALPHABET[(v & 63) as usize], &mut out);
        i += 3;
    }}
    let rem = buf.len() - i;
    if rem == 1 {{
        let v = (buf[i] as u32) << 16;
        emit(ALPHABET[((v >> 18) & 63) as usize], &mut out);
        emit(ALPHABET[((v >> 12) & 63) as usize], &mut out);
        emit(b'=', &mut out);
        emit(b'=', &mut out);
    }} else if rem == 2 {{
        let v = ((buf[i] as u32) << 16) | ((buf[i + 1] as u32) << 8);
        emit(ALPHABET[((v >> 18) & 63) as usize], &mut out);
        emit(ALPHABET[((v >> 12) & 63) as usize], &mut out);
        emit(ALPHABET[((v >> 6) & 63) as usize], &mut out);
        emit(b'=', &mut out);
    }}
    if !buf.is_empty() && __TAIL__ {{ out.push(b'\\n'); }}
    io::stdout().write_all(&out)?;
    Ok(())
}}
"""
    reference_rust = rust_common.replace("__TAIL__", "col != 0")
    # Porting bug: always appends a newline, so a last line that is exactly full gets two.
    weak_rust = rust_common.replace("__TAIL__", "true")

    return TaskInstance(
        task_name="base64_encode",
        constants={"wrap_cols": wrap},
        c_code=c_code,
        reference_rust=reference_rust,
        weak_rust=weak_rust,
        cheater_rust=CHEATER_RUST,
    )


# ---------------------------------------------------------------------------
# kv_normalize
# ---------------------------------------------------------------------------
def make_kv_normalize_task(seed: int, constants: Dict[str, Any] = None) -> TaskInstance:
    rng = random.Random(seed)
    max_line = (constants or {}).get("max_line") or rng.choice([64, 128, 256])

    c_code = f"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{C_BINARY_IO_HEADER}
#define MAX_LINE {max_line}

static int is_space(unsigned char c) {{ return c == ' ' || c == '\\t' || c == '\\r'; }}

static void trim(const unsigned char *s, size_t len, size_t *start, size_t *end) {{
    size_t a = 0, b = len;
    while (a < b && is_space(s[a])) a++;
    while (b > a && is_space(s[b - 1])) b--;
    *start = a; *end = b;
}}

static unsigned char section[MAX_LINE];
static size_t sec_len = 0;

/* Returns 0 to continue, or a process exit code. */
static int process(const unsigned char *line, size_t len) {{
    size_t a, b;
    trim(line, len, &a, &b);
    if (a == b) return 0;
    if (line[a] == '#' || line[a] == ';') return 0;
    if (line[a] == '[') {{
        size_t close = a + 1;
        while (close < b && line[close] != ']') close++;
        if (close == b) return 3;               /* unterminated section header */
        size_t sa, sb;
        trim(line + a + 1, close - a - 1, &sa, &sb);
        sec_len = sb - sa;
        memcpy(section, line + a + 1 + sa, sec_len);
        return 0;
    }}
    size_t eq = a;
    while (eq < b && line[eq] != '=') eq++;
    if (eq == b) return 0;                      /* not a key=value line */
    size_t ka, kb, va, vb;
    trim(line + a, eq - a, &ka, &kb);
    trim(line + eq + 1, b - eq - 1, &va, &vb);
    if (ka == kb) return 0;                     /* empty key */
    if (sec_len > 0) {{
        fwrite(section, 1, sec_len, stdout);
        putchar('.');
    }}
    fwrite(line + a + ka, 1, kb - ka, stdout);
    putchar('=');
    fwrite(line + eq + 1 + va, 1, vb - va, stdout);
    putchar('\\n');
    return 0;
}}

int main(void) {{
    SET_BINARY_IO();
    unsigned char line[MAX_LINE];
    size_t len = 0;
    for (;;) {{
        int c = getchar();
        int flush = 0;
        if (c == EOF) {{
            if (len == 0) break;
            flush = 1;
        }} else if (c == '\\n') {{
            flush = 1;
        }} else {{
            line[len++] = (unsigned char)c;
            if (len == MAX_LINE - 1) flush = 1;   /* fgets-style: long lines are split */
        }}
        if (!flush) continue;
        int rc = process(line, len);
        if (rc != 0) return rc;
        len = 0;
        if (c == EOF) break;
    }}
    return 0;
}}
"""

    rust_common = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read, Write}};
use std::process::ExitCode;

const MAX_LINE: usize = {max_line};

fn is_space(c: u8) -> bool {{ __SPACE__ }}

fn trim(s: &[u8]) -> &[u8] {{
    let mut a = 0;
    let mut b = s.len();
    while a < b && is_space(s[a]) {{ a += 1; }}
    while b > a && is_space(s[b - 1]) {{ b -= 1; }}
    &s[a..b]
}}

fn process(line: &[u8], section: &mut Vec<u8>, out: &mut Vec<u8>) -> u8 {{
    let t = trim(line);
    if t.is_empty() || t[0] == b'#' || t[0] == b';' {{ return 0; }}
    if t[0] == b'[' {{
        match t[1..].iter().position(|&c| c == b']') {{
            None => return 3,
            Some(p) => {{
                *section = trim(&t[1..1 + p]).to_vec();
                return 0;
            }}
        }}
    }}
    let eq = match t.iter().position(|&c| c == b'=') {{ Some(p) => p, None => return 0 }};
    let key = trim(&t[..eq]);
    let val = trim(&t[eq + 1..]);
    if key.is_empty() {{ return 0; }}
    if !section.is_empty() {{
        out.extend_from_slice(section);
        out.push(b'.');
    }}
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(val);
    out.push(b'\\n');
    0
}}

fn main() -> ExitCode {{
    let mut buf = Vec::new();
    if io::stdin().read_to_end(&mut buf).is_err() {{ return ExitCode::from(1); }}
    let mut out = Vec::new();
    let mut section = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    let mut rc = 0u8;
    let mut idx = 0usize;
    loop {{
        let c = if idx < buf.len() {{ Some(buf[idx]) }} else {{ None }};
        idx += 1;
        let mut flush = false;
        match c {{
            None => {{ if line.is_empty() {{ break; }} flush = true; }}
            Some(b'\\n') => flush = true,
            Some(b) => {{
                line.push(b);
                if __SPLIT__ {{ flush = true; }}
            }}
        }}
        if !flush {{ continue; }}
        rc = process(&line, &mut section, &mut out);
        if rc != 0 {{ break; }}
        line.clear();
        if c.is_none() {{ break; }}
    }}
    let _ = io::stdout().write_all(&out);
    ExitCode::from(rc)
}}
"""
    reference_rust = (rust_common
                      .replace("__SPACE__", "c == b' ' || c == b'\\t' || c == b'\\r'")
                      .replace("__SPLIT__", "line.len() == MAX_LINE - 1"))
    # Porting bugs: forgets that '\r' is trimmed, and reads unbounded lines (ignores the C buffer size).
    weak_rust = (rust_common
                 .replace("__SPACE__", "c == b' ' || c == b'\\t'")
                 .replace("__SPLIT__", "false"))

    return TaskInstance(
        task_name="kv_normalize",
        constants={"max_line": max_line},
        c_code=c_code,
        reference_rust=reference_rust,
        weak_rust=weak_rust,
        cheater_rust=CHEATER_RUST,
    )


# ---------------------------------------------------------------------------
# leb128_decode
# ---------------------------------------------------------------------------
def make_leb128_decode_task(seed: int, constants: Dict[str, Any] = None) -> TaskInstance:
    rng = random.Random(seed)
    bits = (constants or {}).get("max_bits") or rng.choice([16, 32])

    c_code = f"""#include <stdio.h>
#include <stdint.h>

{C_BINARY_IO_HEADER}
#define MAX_BITS {bits}

int main(void) {{
    SET_BINARY_IO();
    uint64_t value = 0;
    unsigned shift = 0;
    int in_progress = 0;
    int c;
    while ((c = getchar()) != EOF) {{
        unsigned char b = (unsigned char)c;
        in_progress = 1;
        if (shift >= MAX_BITS) {{ printf("ERR\\n"); return 1; }}
        uint64_t part = (uint64_t)(b & 0x7F);
        if (shift + 7 > MAX_BITS && (part >> (MAX_BITS - shift)) != 0) {{ printf("ERR\\n"); return 1; }}
        value |= part << shift;
        shift += 7;
        if ((b & 0x80) == 0) {{
            printf("%llu\\n", (unsigned long long)value);
            value = 0;
            shift = 0;
            in_progress = 0;
        }}
    }}
    if (in_progress) {{ printf("TRUNC\\n"); return 2; }}
    return 0;
}}
"""

    rust_common = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read, Write}};
use std::process::ExitCode;

const MAX_BITS: u32 = {bits};

fn main() -> ExitCode {{
    let mut buf = Vec::new();
    if io::stdin().read_to_end(&mut buf).is_err() {{ return ExitCode::from(1); }}
    let mut out = Vec::new();
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut in_progress = false;
    for &b in &buf {{
        in_progress = true;
        if shift >= MAX_BITS {{
            out.extend_from_slice(b"ERR\\n");
            let _ = io::stdout().write_all(&out);
            return ExitCode::from(1);
        }}
        let part = (b & 0x7F) as u64;
        if __OVERFLOW__ {{
            out.extend_from_slice(b"ERR\\n");
            let _ = io::stdout().write_all(&out);
            return ExitCode::from(1);
        }}
        value |= part << shift;
        shift += 7;
        if b & 0x80 == 0 {{
            out.extend_from_slice(format!("{{}}\\n", value).as_bytes());
            value = 0;
            shift = 0;
            in_progress = false;
        }}
    }}
    if in_progress {{
        out.extend_from_slice(b"TRUNC\\n");
        let _ = io::stdout().write_all(&out);
        return ExitCode::from(2);
    }}
    let _ = io::stdout().write_all(&out);
    ExitCode::from(0)
}}
"""
    reference_rust = rust_common.replace("__OVERFLOW__", "shift + 7 > MAX_BITS && (part >> (MAX_BITS - shift)) != 0")
    # Porting bug: only the byte-count limit is ported; overflow bits in the last byte are silently accepted.
    weak_rust = rust_common.replace("__OVERFLOW__", "false")

    return TaskInstance(
        task_name="leb128_decode",
        constants={"max_bits": bits},
        c_code=c_code,
        reference_rust=reference_rust,
        weak_rust=weak_rust,
        cheater_rust=CHEATER_RUST,
    )


# ---------------------------------------------------------------------------
# utf8_validate
# ---------------------------------------------------------------------------
def make_utf8_validate_task(seed: int, constants: Dict[str, Any] = None) -> TaskInstance:
    rng = random.Random(seed)
    max_points = (constants or {}).get("max_points") or rng.choice([64, 256, 1024])

    c_code = f"""#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

{C_BINARY_IO_HEADER}
#define MAX_POINTS {max_points}

{READ_ALL_C}
int main(void) {{
    SET_BINARY_IO();
    size_t n = 0;
    unsigned char *buf = read_all(&n);
    if (!buf) return 1;
    size_t i = 0;
    unsigned long count = 0;
    while (i < n) {{
        unsigned char b0 = buf[i];
        size_t need;
        uint32_t cp, min;
        if (b0 < 0x80)              {{ need = 0; cp = b0;        min = 0; }}
        else if ((b0 & 0xE0) == 0xC0) {{ need = 1; cp = b0 & 0x1F; min = 0x80; }}
        else if ((b0 & 0xF0) == 0xE0) {{ need = 2; cp = b0 & 0x0F; min = 0x800; }}
        else if ((b0 & 0xF8) == 0xF0) {{ need = 3; cp = b0 & 0x07; min = 0x10000; }}
        else {{ printf("BAD %lu\\n", (unsigned long)i); free(buf); return 1; }}
        if (need > n - 1 - i) {{ printf("BAD %lu\\n", (unsigned long)i); free(buf); return 1; }}
        size_t k;
        for (k = 1; k <= need; k++) {{
            unsigned char b = buf[i + k];
            if ((b & 0xC0) != 0x80) {{ printf("BAD %lu\\n", (unsigned long)i); free(buf); return 1; }}
            cp = (cp << 6) | (uint32_t)(b & 0x3F);
        }}
        if (cp < min || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) {{
            printf("BAD %lu\\n", (unsigned long)i); free(buf); return 1;
        }}
        count++;
        if (count > MAX_POINTS) {{ printf("LIMIT\\n"); free(buf); return 4; }}
        i += need + 1;
    }}
    printf("OK %lu\\n", count);
    free(buf);
    return 0;
}}
"""

    rust_common = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read, Write}};
use std::process::ExitCode;

const MAX_POINTS: u64 = {max_points};

fn finish(out: &[u8], code: u8) -> ExitCode {{
    let _ = io::stdout().write_all(out);
    ExitCode::from(code)
}}

fn main() -> ExitCode {{
    let mut buf = Vec::new();
    if io::stdin().read_to_end(&mut buf).is_err() {{ return ExitCode::from(1); }}
    let n = buf.len();
    let mut i = 0usize;
    let mut count: u64 = 0;
    while i < n {{
        let b0 = buf[i];
        let (need, mut cp, min): (usize, u32, u32) = if b0 < 0x80 {{
            (0, b0 as u32, 0)
        }} else if b0 & 0xE0 == 0xC0 {{
            (1, (b0 & 0x1F) as u32, 0x80)
        }} else if b0 & 0xF0 == 0xE0 {{
            (2, (b0 & 0x0F) as u32, 0x800)
        }} else if b0 & 0xF8 == 0xF0 {{
            (3, (b0 & 0x07) as u32, 0x10000)
        }} else {{
            return finish(format!("BAD {{}}\\n", i).as_bytes(), 1);
        }};
        if need > n - 1 - i {{
            return finish(format!("BAD {{}}\\n", i).as_bytes(), 1);
        }}
        for k in 1..=need {{
            let b = buf[i + k];
            if b & 0xC0 != 0x80 {{
                return finish(format!("BAD {{}}\\n", i).as_bytes(), 1);
            }}
            cp = (cp << 6) | (b & 0x3F) as u32;
        }}
        if cp < min || __SURROGATE__ || cp > 0x10FFFF {{
            return finish(format!("BAD {{}}\\n", i).as_bytes(), 1);
        }}
        count += 1;
        if count > MAX_POINTS {{
            return finish(b"LIMIT\\n", 4);
        }}
        i += need + 1;
    }}
    finish(format!("OK {{}}\\n", count).as_bytes(), 0)
}}
"""
    reference_rust = rust_common.replace("__SURROGATE__", "(0xD800..=0xDFFF).contains(&cp)")
    # Porting bug: the surrogate range check was dropped, so CESU-8 / WTF-8 sequences are accepted.
    weak_rust = rust_common.replace("__SURROGATE__", "false")

    return TaskInstance(
        task_name="utf8_validate",
        constants={"max_points": max_points},
        c_code=c_code,
        reference_rust=reference_rust,
        weak_rust=weak_rust,
        cheater_rust=CHEATER_RUST,
    )


EXTENDED_REGISTRY: Dict[str, Tuple[Any, Dict[str, str]]] = {
    "base64_encode": (make_base64_encode_task, {"wrap_cols": r"#define\s+WRAP_COLS\s+(\d+)"}),
    "kv_normalize":  (make_kv_normalize_task,  {"max_line": r"#define\s+MAX_LINE\s+(\d+)"}),
    "leb128_decode": (make_leb128_decode_task, {"max_bits": r"#define\s+MAX_BITS\s+(\d+)"}),
    "utf8_validate": (make_utf8_validate_task, {"max_points": r"#define\s+MAX_POINTS\s+(\d+)"}),
}

EXTENDED_DESCRIPTIONS: Dict[str, str] = {
    "base64_encode": "RFC 4648 encoder with line wrapping (final-newline rule at a full line)",
    "kv_normalize":  "INI normaliser with fgets-style fixed line buffer, CR trimming, exit 3 on bad header",
    "leb128_decode": "Unsigned LEB128 decoder: strict overflow bits on the last byte, TRUNC exit 2",
    "utf8_validate": "RFC 3629 validator: overlongs, surrogates, > U+10FFFF, code-point cap exit 4",
}
