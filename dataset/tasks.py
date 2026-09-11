"""
Parameterized Task Pool for Aegis Subnet (dataset/tasks.py)
UB-Free C reference algorithms with per-round constant injection,
matching Safe Rust reference implementations, weak flawed variants,
and adversarial test case generators.
"""

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


def make_reverse_bytes_task(seed: int) -> TaskInstance:
    """
    Task 1: reverse_bytes
    Inverts byte order of consecutive chunks of CHUNK_SIZE bytes.
    Forces raw byte handling (null bytes, invalid UTF-8) vs char decoding.
    """
    rng = random.Random(seed)
    chunk_size = rng.choice([2, 3, 4, 5, 7, 8])

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


def make_rle_encode_task(seed: int) -> TaskInstance:
    """
    Task 2: rle_encode
    Encodes repeated consecutive bytes as [count: 1 byte][value: 1 byte].
    Splits runs larger than MAX_RUN.
    """
    rng = random.Random(seed)
    max_run = rng.choice([16, 32, 64, 128, 255])

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


def make_fnv1a_lines_task(seed: int) -> TaskInstance:
    """
    Task 3: fnv1a_lines
    Computes 32-bit FNV-1a hash of each line in stdin.
    Tests uint32 wraparound, empty lines, CRLF vs LF, no trailing newline.
    """
    rng = random.Random(seed)
    offset_basis = rng.choice([2166136261, 2166136267, 2166136279])
    prime = rng.choice([16777619, 16777621, 16777627])

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


def make_crc32_task(seed: int) -> TaskInstance:
    """
    Task 4: crc32
    Computes standard 32-bit CRC bitwise over all stdin bytes.
    """
    rng = random.Random(seed)
    poly = rng.choice([0xEDB88320, 0x82F63B78, 0xEB31D82E])

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

    weak_rust = f"""#![forbid(unsafe_code)]
use std::io::{{self, Read}};

fn main() -> io::Result<()> {{
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
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
    // Flawed: forgets final XOR inversion
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


def sample_task(task_name: str = None, seed: int = None) -> TaskInstance:
    """Sample a parameterized task from the pool."""
    if seed is None:
        import secrets
        seed = secrets.randbits(32)

    rng = random.Random(seed)
    task_factories = {
        "reverse_bytes": make_reverse_bytes_task,
        "rle_encode": make_rle_encode_task,
        "fnv1a_lines": make_fnv1a_lines_task,
        "crc32": make_crc32_task,
    }

    if task_name and task_name in task_factories:
        factory = task_factories[task_name]
    else:
        factory = rng.choice(list(task_factories.values()))

    return factory(seed)
