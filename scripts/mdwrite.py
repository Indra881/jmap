"""Minimal Windows-minidump writer shared by the capture frontends."""

import struct
import time

CHUNK = 1 << 20

# --- minidump constants ---
MDMP = 0x504D444D  # 'MDMP'
MINIDUMP_VERSION = 0xA793
HEADER_SIZE = 32

STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_SYSTEM_INFO = 7
STREAM_MEMORY64_LIST = 9
STREAM_MISC_INFO = 15
STREAM_MEMORY_INFO_LIST = 16
STREAM_THREAD_NAMES = 24
STREAM_LINUX_MAPS = 0x47670009  # breakpad: raw /proc/<pid>/maps

# ProcessorArchitecture
ARCH = {"arm64": 12, "x64": 9, "ia32": 0, "arm": 5}
# breakpad PlatformId values
PLAT_WINDOWS, PLAT_LINUX, PLAT_ANDROID, PLAT_MAC = 2, 0x8201, 0x8203, 0x8205

CONTEXT_ARM64_SIZE = 912
CONTEXT_AMD64_SIZE = 1232


# --- small serialization helpers ---

def reg(regs, name):
    v = regs.get(name)
    return int(v, 16) if v else 0


def page_protect(p):
    """protection string ("rwx"/"r--"/...) -> Windows PAGE_* constant."""
    r, w, x = p[0] == "r", p[1] == "w", p[2] == "x"
    if x:
        return 0x40 if w else (0x20 if r else 0x10)  # EXEC_READWRITE / EXEC_READ / EXEC
    if w:
        return 0x04  # READWRITE
    if r:
        return 0x02  # READONLY
    return 0x01      # NOACCESS


def md_string(s):
    """MINIDUMP_STRING: u32 byte-length + UTF-16LE body + NUL terminator."""
    b = s.encode("utf-16-le")
    return struct.pack("<I", len(b)) + b + b"\x00\x00"


def memory_info(base, size, prot):
    """MINIDUMP_MEMORY_INFO (48 bytes)."""
    P = page_protect(prot)
    # BaseAddress, AllocationBase, AllocProtect, pad, RegionSize, State=MEM_COMMIT, Protect, Type=MEM_PRIVATE, pad
    return struct.pack("<QQIIQIIII", base, base, P, 0, size, 0x1000, P, 0x20000, 0)


def module_record(base, size, name_rva):
    """MINIDUMP_MODULE (108 bytes); version/cv/misc fields left zeroed."""
    return (
        struct.pack("<QIIII", base, size & 0xFFFFFFFF, 0, 0, name_rva)
        + b"\x00" * 52   # VS_FIXEDFILEINFO
        + b"\x00" * 16   # CvRecord + MiscRecord location descriptors
        + b"\x00" * 16   # Reserved0, Reserved1
    )


def build_context_arm64(regs):
    iregs = [reg(regs, f"x{i}") for i in range(29)] + [reg(regs, "fp"), reg(regs, "lr")]
    body = struct.pack("<II", 0x400003, 0)            # ContextFlags=ARM64|CONTROL|INTEGER, Cpsr
    body += struct.pack("<31Q", *iregs)               # X0..X30
    body += struct.pack("<QQ", reg(regs, "sp"), reg(regs, "pc"))
    body += b"\x00" * (CONTEXT_ARM64_SIZE - len(body))  # NEON V[32], Fpcr/Fpsr, debug regs
    return body


def build_context_amd64(regs):
    buf = bytearray(CONTEXT_AMD64_SIZE)
    struct.pack_into("<I", buf, 0x30, 0x100003)       # ContextFlags=AMD64|CONTROL|INTEGER
    layout = [
        ("rax", 0x78), ("rcx", 0x80), ("rdx", 0x88), ("rbx", 0x90), ("rsp", 0x98),
        ("rbp", 0xA0), ("rsi", 0xA8), ("rdi", 0xB0), ("r8", 0xB8), ("r9", 0xC0),
        ("r10", 0xC8), ("r11", 0xD0), ("r12", 0xD8), ("r13", 0xE0), ("r14", 0xE8),
        ("r15", 0xF0), ("rip", 0xF8),
    ]
    for name, off in layout:
        struct.pack_into("<Q", buf, off, reg(regs, name))
    return bytes(buf)


CONTEXT_BUILDERS = {"arm64": build_context_arm64, "x64": build_context_amd64}


# --- stream bodies (return (stream_body, loose_aux)) ---

def build_thread_list_body(start, threads, arch):
    """MINIDUMP_THREAD_LIST; register contexts + stack copies are loose aux."""
    build_ctx = CONTEXT_BUILDERS.get(arch)
    n = len(threads)
    cursor = start + 4 + 48 * n

    ctx_blobs, ctx_locs = [], []
    for t in threads:
        c = build_ctx(t["context"]) if build_ctx else b""
        ctx_locs.append((len(c), cursor if c else 0))
        ctx_blobs.append(c)
        cursor += len(c)

    stack_blobs, stack_locs = [], []
    for t in threads:
        sb = t.get("stack_bytes") or b""
        if sb:
            stack_locs.append((t.get("stack_addr", 0), len(sb), cursor))
            cursor += len(sb)
        else:
            stack_locs.append((0, 0, 0))
        stack_blobs.append(sb)

    body = bytearray(struct.pack("<I", n))
    for i, t in enumerate(threads):
        sa, ssize, srva = stack_locs[i]
        csize, crva = ctx_locs[i]
        body += struct.pack("<IIII", t["id"] & 0xFFFFFFFF, 0, 0, 0)  # id, suspend, prioclass, prio
        body += struct.pack("<Q", 0)                                 # Teb
        body += struct.pack("<QII", sa, ssize, srva)                 # Stack MEMORY_DESCRIPTOR
        body += struct.pack("<II", csize, crva)                      # ThreadContext LOCATION
    aux = b"".join(ctx_blobs) + b"".join(stack_blobs)
    return bytes(body), aux


def build_thread_names_body(start, named):
    """MINIDUMP_THREAD_NAME_LIST: count + (u32 id, u64 name_rva); strings are aux."""
    n = len(named)
    cursor = start + 4 + 12 * n
    strs, rvas = [], []
    for _, name in named:
        rvas.append(cursor)
        b = md_string(name)
        strs.append(b)
        cursor += len(b)
    body = bytearray(struct.pack("<I", n))
    for (tid, _), rva in zip(named, rvas):
        body += struct.pack("<IQ", tid & 0xFFFFFFFF, rva)
    return bytes(body), b"".join(strs)


def build_misc_info_body(pid):
    """MINIDUMP_MISC_INFO (24 bytes); only the process id is marked valid."""
    return struct.pack("<IIIIII", 24, 0x1, pid & 0xFFFFFFFF, 0, 0, 0), b""


def detect_platform(platform, ranges):
    if platform == "windows":
        return PLAT_WINDOWS
    if platform == "darwin":
        return PLAT_MAC
    if any(r.get("file") and "libart.so" in r["file"] for r in ranges):
        return PLAT_ANDROID
    return PLAT_LINUX


def build_system_info_body(start, info, ranges):
    """MINIDUMP_SYSTEM_INFO (56 bytes) + an (empty) CSD version string."""
    arch_code = ARCH.get(info["arch"], 0)
    platform_id = detect_platform(info["platform"], ranges)
    csd_rva = start + 56
    body = struct.pack("<HHHBB", arch_code, 0, 0, 0, 1)   # arch, level, rev, numproc, producttype
    body += struct.pack("<IIII", 0, 0, 0, platform_id)    # major, minor, build, platformid
    body += struct.pack("<I", csd_rva)                    # CSDVersionRva
    body += struct.pack("<HH", 0, 0)                      # suitemask, reserved2
    body += b"\x00" * 24                                  # CPU_INFORMATION union
    return body, md_string("")


def build_module_list_body(start, modules):
    """One MINIDUMP_MODULE per loaded image"""
    n = len(modules)
    cursor = start + 4 + 108 * n
    names, rvas = [], []
    for m in modules:
        rvas.append(cursor)
        b = md_string(m.get("path") or m.get("name") or "")
        names.append(b)
        cursor += len(b)
    body = bytearray(struct.pack("<I", n))
    for m, rva in zip(modules, rvas):
        body += module_record(int(m["base"], 16), m["size"], rva)
    return bytes(body), b"".join(names)


def build_memory_info_list_body(ranges):
    """MINIDUMP_MEMORY_INFO_LIST: header(16) + one 48-byte entry per VMA."""
    body = bytearray(struct.pack("<IIQ", 16, 48, len(ranges)))
    for r in ranges:
        body += memory_info(int(r["base"], 16), r["size"], r["protection"])
    return bytes(body), b""


# --- top-level assembly ---

def write_metadata(f, runs, ranges, modules, maps, info, threads):
    """Write header placeholder + metadata streams + directory + Memory64List descriptors"""
    f.write(b"\x00" * HEADER_SIZE)
    dirents = []  # (stream_type, rva, size)

    def emit(stream_type, body_and_aux):
        body, aux = body_and_aux
        rva = f.tell()
        f.write(body)
        dirents.append((stream_type, rva, len(body)))
        f.write(aux)  # loose referent data, reached by RVA, not part of the stream

    if threads:
        start = f.tell()
        emit(STREAM_THREAD_LIST, build_thread_list_body(start, threads, info["arch"]))
        named = [(t["id"], t["name"]) for t in threads if t.get("name")]
        if named:
            start = f.tell()
            emit(STREAM_THREAD_NAMES, build_thread_names_body(start, named))

    emit(STREAM_MISC_INFO, build_misc_info_body(info["pid"]))
    start = f.tell()
    emit(STREAM_SYSTEM_INFO, build_system_info_body(start, info, ranges))
    start = f.tell()
    emit(STREAM_MODULE_LIST, build_module_list_body(start, modules))
    emit(STREAM_MEMORY_INFO_LIST, build_memory_info_list_body(ranges))
    if maps:
        emit(STREAM_LINUX_MAPS, (maps.encode("utf-8", "replace"), b""))

    # Memory64List + directory: the blob trails the directory, so compute its
    # offset from the (now known) directory size before emitting either.
    dir_rva = f.tell()
    num_streams = len(dirents) + 1
    dir_size = 12 * num_streams
    m64_start = dir_rva + dir_size
    nruns = len(runs)
    m64_size = 16 + 16 * nruns  # header(count+BaseRva) + 16-byte descriptors
    base_rva = m64_start + m64_size
    dirents.append((STREAM_MEMORY64_LIST, m64_start, m64_size))

    for stream_type, rva, size in dirents:
        f.write(struct.pack("<III", stream_type, size, rva))
    assert f.tell() == m64_start

    f.write(struct.pack("<QQ", nruns, base_rva))
    for addr, length in runs:
        f.write(struct.pack("<QQ", addr, length))
    assert f.tell() == base_rva

    return dir_rva, num_streams


def write_blob(f, runs, read_fn):
    """Write the memory blob: contiguous, one descriptor's bytes per run."""
    total = sum(length for _, length in runs)
    captured = 0
    for addr, length in runs:
        off = 0
        while off < length:
            n = min(CHUNK, length - off)
            data = read_fn(addr + off, n)
            if data is None or len(data) < n:
                buf = bytearray(n)
                if data:
                    buf[: len(data)] = data
                f.write(buf)
            else:
                f.write(data)
            captured += n
            off += n
        print(f"\r  captured {captured / (1 << 20):.0f}/{total / (1 << 20):.0f} MiB, "
              f"{len(runs)} runs", end="", flush=True)
    return captured


def patch_header(f, dir_rva, num_streams):
    """Seek to 0 and write the MINIDUMP_HEADER now that the directory is placed."""
    f.seek(0)
    f.write(struct.pack("<IIIIIIQ", MDMP, MINIDUMP_VERSION, num_streams, dir_rva,
                        0, int(time.time()), 0))


def find_range(ranges, addr):
    for r in ranges:
        base = int(r["base"], 16)
        if base <= addr < base + r["size"]:
            return base, r["size"]
    return None
