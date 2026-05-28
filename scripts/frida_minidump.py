#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "frida==17.9.5",
# ]
# ///
import argparse

import frida

from mdwrite import find_range, patch_header, write_blob, write_metadata

AGENT = r"""
var BLK = %d;
var memcmp = new NativeFunction(Module.findGlobalExportByName("memcmp"), "int", ["pointer", "pointer", "ulong"]);
var memset = new NativeFunction(Module.findGlobalExportByName("memset"), "pointer", ["pointer", "int", "ulong"]);
var ZERO = Memory.alloc(BLK);
memset(ZERO, 0, BLK);

function ctxToObj(c) {
    var keys;
    if (Process.arch === 'arm64') {
        keys = ['pc', 'sp', 'fp', 'lr'];
        for (var i = 0; i <= 28; i++) keys.push('x' + i);
    } else if (Process.arch === 'x64') {
        keys = ['rip', 'rsp', 'rbp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];
    } else if (Process.arch === 'ia32') {
        keys = ['eip', 'esp', 'ebp', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'];
    } else if (Process.arch === 'arm') {
        keys = ['pc', 'sp', 'lr', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12'];
    } else {
        keys = [];
    }
    var o = {};
    keys.forEach(function (k) {
        try { if (c[k] !== undefined && c[k] !== null) o[k] = c[k].toString(); } catch (e) {}
    });
    return o;
}

rpc.exports = {
    info: function () {
        return { arch: Process.arch, platform: Process.platform, pid: Process.id,
                 pointerSize: Process.pointerSize, pageSize: Process.pageSize };
    },
    threads: function () {
        return Process.enumerateThreads().map(function (t) {
            return { id: t.id, name: t.name || null, state: t.state, context: ctxToObj(t.context) };
        });
    },
    ranges: function (protection) {
        return Process.enumerateRanges(protection).map(function (r) {
            return { base: r.base.toString(), size: r.size, protection: r.protection,
                     file: r.file ? r.file.path : null };
        });
    },
    modules: function () {
        return Process.enumerateModules().map(function (m) {
            return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
        });
    },
    maps: function () {
        try {
            if (Process.platform !== 'linux') return null;
            return File.readAllText('/proc/self/maps');
        } catch (e) { return null; }
    },
    nzruns: function (baseStr, size) {
        var base = ptr(baseStr);
        var runs = [];
        var runStart = -1;
        var off = 0;
        while (off < size) {
            var n = Math.min(BLK, size - off);
            var nonzero;
            try { nonzero = memcmp(base.add(off), ZERO, n) !== 0; }
            catch (e) { nonzero = false; }
            if (nonzero) {
                if (runStart < 0) runStart = off;
            } else if (runStart >= 0) {
                runs.push([base.add(runStart).toString(), off - runStart]);
                runStart = -1;
            }
            off += n;
        }
        if (runStart >= 0) runs.push([base.add(runStart).toString(), size - runStart]);
        return runs;
    },
    read: function (addr, size) {
        try { return ptr(addr).readByteArray(size); }
        catch (e) { return null; }
    },
};
"""

BLOCK = 1 << 16  # zero-scan block size for the agent
SCAN_ABOVE = 64 << 20
STACK_CAP = 2 << 20

def gather_threads(api, ranges):
    threads = api.threads()
    for t in threads:
        regs = t.get("context", {})
        spv = regs.get("sp") or regs.get("rsp") or regs.get("esp")
        t["stack_bytes"] = b""
        t["stack_addr"] = 0
        if not spv:
            continue
        sp = int(spv, 16)
        rng = find_range(ranges, sp)
        if not rng:
            continue
        base, size = rng
        n = min((base + size) - sp, STACK_CAP)
        data = api.read(hex(sp), n)
        if data:
            t["stack_bytes"] = bytes(data)
            t["stack_addr"] = sp
    return threads


def dump(api, ranges, modules, maps, info, threads, out_path):
    runs = []
    for r in ranges:
        base = int(r["base"], 16)
        size = r["size"]
        if size > SCAN_ABOVE:
            runs.extend((int(a, 16), length) for a, length in api.nzruns(r["base"], size))
        else:
            runs.append((base, size))

    with open(out_path, "wb") as f:
        dir_rva, num_streams = write_metadata(f, runs, ranges, modules, maps, info, threads)
        captured = write_blob(f, runs, lambda addr, n: api.read(hex(addr), n))
        patch_header(f, dir_rva, num_streams)

    print(f"\nDone. {captured / (1 << 20):.0f} MiB across {len(runs)} runs, "
          f"{len(ranges)} regions, {len(threads)} threads -> {out_path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("-p", "--pid", type=int, help="target pid")
    target.add_argument("-n", "--name", help="target process name")
    ap.add_argument("-U", "--usb", action="store_true", help="use the USB device")
    ap.add_argument("--remote", metavar="HOST:PORT", help="remote frida-server")
    ap.add_argument("--out", required=True, help="output minidump (.dmp) path")
    args = ap.parse_args()

    if args.remote:
        device = frida.get_device_manager().add_remote_device(args.remote)
    elif args.usb:
        device = frida.get_usb_device()
    else:
        device = frida.get_local_device()

    session = device.attach(args.pid if args.pid is not None else args.name)
    script = session.create_script(AGENT % BLOCK)
    script.load()
    api = script.exports_sync

    info = api.info()
    pid = info["pid"]
    ranges = api.ranges("r--")
    modules = api.modules()
    maps = api.maps()
    total = sum(r["size"] for r in ranges)
    print(f"pid {pid}, {info['arch']}/{info['platform']}, "
          f"{len(ranges)} ranges, {len(modules)} modules, "
          f"{total / (1 << 30):.1f} GiB of address space")

    print("note: Capturing minidump without suspending process. May be internally inconsistent")

    threads = gather_threads(api, ranges)
    dump(api, ranges, modules, maps, info, threads, args.out)

    session.detach()


if __name__ == "__main__":
    main()
