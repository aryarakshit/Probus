"""
Parameterized Task Pool for Aegis Subnet (dataset/tasks.py)
UB-Free C reference algorithms with per-round constant injection,
matching Safe Rust reference implementations, weak flawed variants,
and adversarial test case generators.
"""

import re
import random
import string
import struct
from typing import Dict, Any, List, Tuple


class TaskInstance:
    def __init__(
        self,
        task_name: str,
        constants: Dict[str, Any],
        c_code: str,
        reference_rust: str,
        weak_rust: str,
        cheater_rust: str
    ):
        self.task_name = task_name
        self.constants = constants
        self.c_code = c_code
        self.reference_rust = reference_rust
        self.weak_rust = weak_rust
        self.cheater_rust = cheater_rust


C_BINARY_IO_HEADER = """#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#define SET_BINARY_IO() do { _setmode(_fileno(stdin), _O_BINARY); _setmode(_fileno(stdout), _O_BINARY); } while (0)
#else
#define SET_BINARY_IO() ((void)0)
#endif
"""


def make_reverse_bytes_task(seed: int, constants: Dict[str, Any] = None) -> TaskInstance:
    """
    Task 1: reverse_bytes
    Inverts byte order of consecutive chunks of CHUNK_SIZE bytes.
    Forces raw byte handling (null bytes, invalid UTF-8) vs char decoding.
    """
    rng = random.Random(seed)
    chunk_size = (constants or {}).get("chunk_size") or rng.choice([2, 3, 4, 5, 7, 8])

    c_code = f"""#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

{C_BINARY_IO_HEADER}

#define CHUNK_SIZE {chunk_size}

int main(void) {{
    SET_BINARY_IO();
    size_t capacity = 4096;
    size_t size = 0;
    unsigned char *buffer = (unsigned char *)malloc(capacity);
    if (!buffer) return 1;

    size_t n;
    unsigned char chunk[512];
    while ((n = fread(chunk, 1, sizeof(chunk), stdin)) > 0) {{
        if (size + n > capacity) {{
            size_t new_cap = (capacity * 2 > size + n) ? capacity * 2 : size + n + 4096;
            unsigned char *new_buf = (unsigned char *)realloc(buffer, new_cap);
            if (!new_buf) {{
                free(buffer);
                return 1;
            }}
            buffer = new_buf;
            capacity = new_cap;
        }}
        for (size_t i = 0; i < n; i++) {{
            buffer[size + i] = chunk[i];
        }}
        size += n;
    }}

    size_t csz = CHUNK_SIZE;
    for (size_t offset = 0; offset < size; offset += csz) {{
        size_t cur_len = (size - offset < csz) ? (size - offset) : csz;
        if (cur_len > 1) {{
            size_t left = offset;
            size_t right = offset + cur_len - 1;
            while (left < right) {{
                unsigned char tmp = buffer[left];
                buffer[left] = buffer[right];
                buffer[right] = tmp;
                left++;
                right--;
            }}
        }}
    }}

    if (size > 0) {{
        fwrite(buffer, 1, size, stdout);
    }}
    free(buffer);
    return 0;
}}
"""

    reference_rust = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read, Write}};

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;

    let chunk_size = {chunk_size};
    for chunk in buffer.chunks_mut(chunk_size) {{
        chunk.reverse();
    }}

    io::stdout().write_all(&buffer)?;
    Ok(())
}}
"""

    weak_rust = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read, Write}};

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;

    if let Ok(s) = std::str::from_utf8(&buffer) {{
        let mut out = String::new();
        let chunk_size = {chunk_size};
        let chars: Vec<char> = s.chars().collect();
        for chunk in chars.chunks(chunk_size) {{
            for &c in chunk.iter().rev() {{
                out.push(c);
            }}
        }}
        io::stdout().write_all(out.as_bytes())?;
    }} else {{
        let mut filtered: Vec<u8> = buffer.into_iter().filter(|&b| b != 0).collect();
        for chunk in filtered.chunks_mut({chunk_size}) {{
            chunk.reverse();
        }}
        io::stdout().write_all(&filtered)?;
    }}
    Ok(())
}}
"""

    cheater_rust = f"""#![allow(unsafe_code)]
use std::io::{{self, Read, Write}};

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    unsafe {{
        let ptr = buffer.as_mut_ptr();
        let len = buffer.len();
        let chunk_size = {chunk_size};
        let mut offset = 0;
        while offset < len {{
            let cur_len = if len - offset < chunk_size {{ len - offset }} else {{ chunk_size }};
            if cur_len > 1 {{
                let mut l = offset;
                let mut r = offset + cur_len - 1;
                while l < r {{
                    let tmp = *ptr.add(l);
                    *ptr.add(l) = *ptr.add(r);
                    *ptr.add(r) = tmp;
                    l += 1;
                    r -= 1;
                }}
            }}
            offset += chunk_size;
        }}
    }}
    io::stdout().write_all(&buffer)?;
    Ok(())
}}
"""

    return TaskInstance(
        task_name="reverse_bytes",
        constants={"chunk_size": chunk_size},
        c_code=c_code,
        reference_rust=reference_rust,
        weak_rust=weak_rust,
        cheater_rust=cheater_rust
    )


def make_rle_encode_task(seed: int, constants: Dict[str, Any] = None) -> TaskInstance:
    """
    Task 2: rle_encode
    Encodes repeated consecutive bytes as [count: 1 byte][value: 1 byte].
    Splits runs larger than MAX_RUN.
    """
    rng = random.Random(seed)
    max_run = (constants or {}).get("max_run") or rng.choice([16, 32, 64, 128, 255])

    c_code = f"""#include <stdio.h>
#include <stdint.h>

{C_BINARY_IO_HEADER}

#define MAX_RUN {max_run}

int main(void) {{
    SET_BINARY_IO();
    int first = getchar();
    if (first == EOF) return 0;

    unsigned char current = (unsigned char)first;
    unsigned int count = 1;

    int next_ch;
    while ((next_ch = getchar()) != EOF) {{
        unsigned char next_byte = (unsigned char)next_ch;
        if (next_byte == current && count < MAX_RUN) {{
            count++;
        }} else {{
            fputc((unsigned char)count, stdout);
            fputc(current, stdout);
            current = next_byte;
            count = 1;
        }}
    }}

    fputc((unsigned char)count, stdout);
    fputc(current, stdout);
    return 0;
}}
"""

    reference_rust = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read, Write}};

fn main() -> io::Result<()> {{
    let mut stdin = io::stdin();
    let mut buffer = Vec::new();
    stdin.read_to_end(&mut buffer)?;

    if buffer.is_empty() {{
        return Ok(());
    }}

    let max_run: usize = {max_run};
    let mut out = Vec::new();

    let mut current = buffer[0];
    let mut count: usize = 1;

    for &byte in &buffer[1..] {{
        if byte == current && count < max_run {{
            count += 1;
        }} else {{
            out.push(count as u8);
            out.push(current);
            current = byte;
            count = 1;
        }}
    }}

    out.push(count as u8);
    out.push(current);

    io::stdout().write_all(&out)?;
    Ok(())
}}
"""

    weak_rust = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read, Write}};

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    if buffer.is_empty() {{
        return Ok(());
    }}

    let mut out = Vec::new();
    let mut current = buffer[0];
    let mut count: usize = 1;

    for &byte in &buffer[1..] {{
        if byte == current {{
            count += 1;
        }} else {{
            out.push((count & 0xFF) as u8);
            out.push(current);
            current = byte;
            count = 1;
        }}
    }}
    out.push((count & 0xFF) as u8);
    out.push(current);

    io::stdout().write_all(&out)?;
    Ok(())
}}
"""

    cheater_rust = f"""#![allow(unsafe_code)]
use std::io::{{self, Read, Write}};

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    unsafe {{
        let _ptr = buffer.as_ptr();
    }}
    let max_run = {max_run};
    if buffer.is_empty() {{ return Ok(()); }}
    let mut out = Vec::new();
    let mut cur = buffer[0];
    let mut cnt = 1;
    for &b in &buffer[1..] {{
        if b == cur && cnt < max_run {{ cnt += 1; }}
        else {{
            out.push(cnt as u8);
            out.push(cur);
            cur = b;
            cnt = 1;
        }}
    }}
    out.push(cnt as u8);
    out.push(cur);
    io::stdout().write_all(&out)?;
    Ok(())
}}
"""

    return TaskInstance(
        task_name="rle_encode",
        constants={"max_run": max_run},
        c_code=c_code,
        reference_rust=reference_rust,
        weak_rust=weak_rust,
        cheater_rust=cheater_rust
    )


def make_fnv1a_lines_task(seed: int, constants: Dict[str, Any] = None) -> TaskInstance:
    """
    Task 3: fnv1a_lines
    Computes 32-bit FNV-1a hash of each line in stdin.
    Tests uint32 wraparound, empty lines, CRLF vs LF, no trailing newline.
    """
    rng = random.Random(seed)
    offset_basis = (constants or {}).get("offset_basis") or rng.choice([2166136261, 2166136267, 2166136279])
    prime = (constants or {}).get("prime") or rng.choice([16777619, 16777621, 16777627])

    c_code = f"""#include <stdio.h>
#include <stdint.h>

{C_BINARY_IO_HEADER}

#define OFFSET_BASIS {offset_basis}U
#define FNV_PRIME {prime}U

int main(void) {{
    SET_BINARY_IO();
    uint32_t hash = OFFSET_BASIS;
    int ch;
    int has_content = 0;

    while ((ch = getchar()) != EOF) {{
        has_content = 1;
        if (ch == '\\n') {{
            printf("%08X\\n", hash);
            hash = OFFSET_BASIS;
        }} else {{
            uint8_t byte = (uint8_t)ch;
            hash = (hash ^ byte) * FNV_PRIME;
        }}
    }}

    if (has_content && hash != OFFSET_BASIS) {{
        printf("%08X\\n", hash);
    }}
    return 0;
}}
"""

    reference_rust = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read}};

fn main() -> io::Result<()> {{
    let mut stdin = io::stdin();
    let mut buffer = Vec::new();
    stdin.read_to_end(&mut buffer)?;

    let offset_basis: u32 = {offset_basis};
    let prime: u32 = {prime};

    let mut hash = offset_basis;
    let mut has_content = false;

    for &byte in &buffer {{
        has_content = true;
        if byte == b'\\n' {{
            println!("{{:08X}}", hash);
            hash = offset_basis;
        }} else {{
            hash = (hash ^ (byte as u32)).wrapping_mul(prime);
        }}
    }}

    if has_content && hash != offset_basis {{
        println!("{{:08X}}", hash);
    }}
    Ok(())
}}
"""

    weak_rust = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read}};

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    let offset_basis: u32 = {offset_basis};
    let prime: u32 = {prime};
    let mut hash = offset_basis;

    for &byte in &buffer {{
        if byte == b'\\n' {{
            println!("{{:08X}}", hash);
            hash = offset_basis;
        }} else {{
            hash = (hash ^ (byte as u32)).wrapping_mul(prime);
        }}
    }}
    Ok(())
}}
"""

    cheater_rust = f"""#![allow(unsafe_code)]
use std::io::{{self, Read}};

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    unsafe {{
        let _ptr = buffer.as_ptr();
    }}
    let offset_basis: u32 = {offset_basis};
    let prime: u32 = {prime};
    let mut hash = offset_basis;
    let mut has_content = false;
    for &byte in &buffer {{
        has_content = true;
        if byte == b'\\n' {{
            println!("{{:08X}}", hash);
            hash = offset_basis;
        }} else {{
            hash = (hash ^ (byte as u32)).wrapping_mul(prime);
        }}
    }}
    if has_content && hash != offset_basis {{
        println!("{{:08X}}", hash);
    }}
    Ok(())
}}
"""

    return TaskInstance(
        task_name="fnv1a_lines",
        constants={"offset_basis": offset_basis, "prime": prime},
        c_code=c_code,
        reference_rust=reference_rust,
        weak_rust=weak_rust,
        cheater_rust=cheater_rust
    )


def make_crc32_task(seed: int, constants: Dict[str, Any] = None) -> TaskInstance:
    """
    Task 4: crc32
    Computes standard 32-bit CRC bitwise over all stdin bytes.
    """
    rng = random.Random(seed)
    poly = (constants or {}).get("poly") or rng.choice([0xEDB88320, 0x82F63B78, 0xEB31D82E])

    c_code = f"""#include <stdio.h>
#include <stdint.h>

{C_BINARY_IO_HEADER}

#define POLY {poly}U

int main(void) {{
    SET_BINARY_IO();
    uint32_t crc = 0xFFFFFFFFU;
    int ch;
    while ((ch = getchar()) != EOF) {{
        uint8_t byte = (uint8_t)ch;
        crc ^= (uint32_t)byte;
        for (int i = 0; i < 8; i++) {{
            if (crc & 1) {{
                crc = (crc >> 1) ^ POLY;
            }} else {{
                crc >>= 1;
            }}
        }}
    }}
    crc ^= 0xFFFFFFFFU;
    printf("%08X\\n", crc);
    return 0;
}}
"""

    reference_rust = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read}};

fn main() -> io::Result<()> {{
    let mut stdin = io::stdin();
    let mut buffer = Vec::new();
    stdin.read_to_end(&mut buffer)?;

    let poly: u32 = {poly};
    let mut crc: u32 = 0xFFFFFFFF;

    for &byte in &buffer {{
        crc ^= byte as u32;
        for _ in 0..8 {{
            if (crc & 1) != 0 {{
                crc = (crc >> 1) ^ poly;
            }} else {{
                crc >>= 1;
            }}
        }}
    }}

    crc ^= 0xFFFFFFFF;
    println!("{{:08X}}", crc);
    Ok(())
}}
"""

    # Porting bug: the translator assumed a fixed 4 KB input buffer, so anything past
    # byte 4096 is silently ignored. Every hidden test is shorter than that; only an
    # adversary that reads the Rust and probes the 4096 boundary will notice.
    weak_rust = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read}};

const BUF_SIZE: usize = 4096;

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    buffer.truncate(BUF_SIZE);
    let poly: u32 = {poly};
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in &buffer {{
        crc ^= byte as u32;
        for _ in 0..8 {{
            if (crc & 1) != 0 {{
                crc = (crc >> 1) ^ poly;
            }} else {{
                crc >>= 1;
            }}
        }}
    }}
    crc ^= 0xFFFFFFFF;
    println!("{{:08X}}", crc);
    Ok(())
}}
"""

    cheater_rust = f"""#![allow(unsafe_code)]
use std::io::{{self, Read}};

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    unsafe {{
        let _ptr = buffer.as_ptr();
    }}
    let poly: u32 = {poly};
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in &buffer {{
        crc ^= byte as u32;
        for _ in 0..8 {{
            if (crc & 1) != 0 {{
                crc = (crc >> 1) ^ poly;
            }} else {{
                crc >>= 1;
            }}
        }}
    }}
    crc ^= 0xFFFFFFFF;
    println!("{{:08X}}", crc);
    Ok(())
}}
"""

    return TaskInstance(
        task_name="crc32",
        constants={"poly": poly},
        c_code=c_code,
        reference_rust=reference_rust,
        weak_rust=weak_rust,
        cheater_rust=cheater_rust
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
# name -> (factory, {constant_name: regex that recovers it from the C source})
# The regexes let dataset/fixtures.py rebuild the exact task instance a miner
# received from nothing but the C code, so benchmark fixtures stay in sync with
# the per-round constants the validator sampled.
TASK_REGISTRY: Dict[str, Tuple[Any, Dict[str, str]]] = {
    "reverse_bytes": (make_reverse_bytes_task, {"chunk_size": r"#define\s+CHUNK_SIZE\s+(\d+)"}),
    "rle_encode":    (make_rle_encode_task,    {"max_run": r"#define\s+MAX_RUN\s+(\d+)"}),
    "fnv1a_lines":   (make_fnv1a_lines_task,   {"offset_basis": r"#define\s+OFFSET_BASIS\s+(\d+)U?",
                                                "prime": r"#define\s+FNV_PRIME\s+(\d+)U?"}),
    "crc32":         (make_crc32_task,         {"poly": r"#define\s+POLY\s+(\d+)U?"}),
}

TASK_DESCRIPTIONS: Dict[str, str] = {
    "reverse_bytes": "Reverse fixed-size byte chunks (raw-byte handling, tail chunk)",
    "rle_encode":    "Run-length encode with a max run (counter overflow at the boundary)",
    "fnv1a_lines":   "FNV-1a hash per line (wrapping u32 arithmetic, trailing-newline rules)",
    "crc32":         "Bitwise CRC-32 with a per-round polynomial (shift/xor semantics)",
}

try:  # real-world-shaped programs live in their own module
    from dataset.tasks_extended import EXTENDED_REGISTRY, EXTENDED_DESCRIPTIONS
    TASK_REGISTRY.update(EXTENDED_REGISTRY)
    TASK_DESCRIPTIONS.update(EXTENDED_DESCRIPTIONS)
except ImportError:
    pass


def list_tasks() -> List[str]:
    return list(TASK_REGISTRY.keys())


def build_task(task_name: str, constants: Dict[str, Any] = None, seed: int = 0) -> TaskInstance:
    factory, _ = TASK_REGISTRY[task_name]
    return factory(seed, constants=constants)


def infer_task(c_code: str) -> Tuple[str, Dict[str, Any]]:
    """Recover (task_name, constants) from a C source produced by this pool."""
    # The validator stamps `// aegis-task: <name>` on every sampled program; without the stamp,
    # fall back to the constant names, which are unique per task.
    marker = re.search(r"//\s*aegis-task:\s*([a-z0-9_]+)", c_code)
    candidates = [marker.group(1)] if marker and marker.group(1) in TASK_REGISTRY else list(TASK_REGISTRY)
    for name in candidates:
        _, regexes = TASK_REGISTRY[name]
        consts: Dict[str, Any] = {}
        for cname, rx in regexes.items():
            m = re.search(rx, c_code)
            if not m:
                break
            raw = m.group(1)
            consts[cname] = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        else:
            return name, consts
    raise ValueError("C source does not match any task in the pool")


def sample_task(task_name: str = None, seed: int = None) -> TaskInstance:
    """Sample a parameterized task from the pool."""
    if seed is None:
        import secrets
        seed = secrets.randbits(32)
    rng = random.Random(seed)
    if task_name and task_name in TASK_REGISTRY:
        factory = TASK_REGISTRY[task_name][0]
    else:
        factory = rng.choice([f for f, _ in TASK_REGISTRY.values()])
    inst = factory(seed)
    # Stamp the task name into the C source so fixtures and dashboards can identify it.
    if "aegis-task:" not in inst.c_code:
        inst.c_code = "// aegis-task: " + inst.task_name + "\n" + inst.c_code
    return inst
