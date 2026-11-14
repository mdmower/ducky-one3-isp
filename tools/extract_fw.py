#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Extract the APROM image from a Ducky One 3 updater, and protocol constants from the .NET ones.

Both updater formats store the firmware unencrypted:
- .NET (`Updater_Nuvoton`, V1.15 and V1.16): a static byte array, a FieldRVA blob typed
  __StaticArrayInitTypeSize=N. The largest such blob is the APROM image. Reading it needs the dnfile package.
- Native MFC (V1.11 and V1.13): a byte array in .data, followed by a 32-bit word, aligned to 4 bytes, that holds
  the array's length. Found with the standard library only.

    extract_fw.py Ducky_One_3_RGB_V1.16.exe -o firmware/One_3_RGB_V1.16.bin
    extract_fw.py Ducky_One_3_RGB_V1.16.exe --consts --types
"""
import argparse
import hashlib
import struct
import sys

RAM = (0x20000000, 0x20005000)  # NUC1261: 20 KB
MAX_IMAGE = 0x40000

ELEMENT_TYPE_I4, ELEMENT_TYPE_U4, ELEMENT_TYPE_STRING = 0x08, 0x09, 0x0E


def read_compressed_uint(b, i):
    if b[i] & 0x80 == 0:
        return b[i], i + 1
    if b[i] & 0xC0 == 0x80:
        return ((b[i] & 0x3F) << 8) | b[i + 1], i + 2
    return ((b[i] & 0x1F) << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3], i + 4


def static_array_size(pe, field):
    """Return N for a field typed __StaticArrayInitTypeSize=N, else None."""
    sig = field.Signature.value
    if len(sig) < 3 or sig[0] != 0x06 or sig[1] != 0x11:  # FIELD, VALUETYPE
        return None
    coded, _ = read_compressed_uint(sig, 2)
    if coded & 3 != 0:  # TypeDef only
        return None
    name = str(pe.net.mdtables.TypeDef[(coded >> 2) - 1].TypeName)
    prefix = "__StaticArrayInitTypeSize="
    return int(name[len(prefix):]) if name.startswith(prefix) else None


def blobs(pe):
    for r in pe.net.mdtables.FieldRva or []:
        field = r.Field.row
        size = static_array_size(pe, field)
        if size:
            off = pe.get_offset_from_rva(r.Rva)
            yield str(field.Name), r.Rva, pe.__data__[off:off + size]


def dump_consts(pe):
    for r in pe.net.mdtables.Constant:
        name = str(r.Parent.row.Name)
        if name == "value__":
            continue
        v = r.Value.value
        if r.Type == ELEMENT_TYPE_STRING:
            val = repr(v.decode("utf-16le", errors="replace"))
        elif r.Type == ELEMENT_TYPE_I4:
            val = hex(struct.unpack("<i", v)[0])
        elif r.Type == ELEMENT_TYPE_U4:
            val = hex(struct.unpack("<I", v)[0])
        else:
            val = v.hex()
        print(f"  {name:30} {val}")


def dump_types(pe):
    for t in pe.net.mdtables.TypeDef:
        print(f"  {t.TypeNamespace}.{t.TypeName}")
        for m in t.MethodList:
            print(f"      {m.row.Name}()  rva={m.row.Rva:#x}")
        for f in t.FieldList:
            print(f"      .{f.row.Name}")


def is_dotnet(data):
    """True if the PE file has a CLR runtime header (data directory 14)."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dirs = opt + (96 if magic == 0x10B else 112)
    return struct.unpack_from("<II", data, dirs + 14 * 8)[1] != 0


def vector_ok(data, off, size):
    """A Cortex-M0 vector table at off: SP in RAM, Thumb reset/NMI/HardFault vectors inside size bytes."""
    sp, reset, nmi, hardfault = struct.unpack_from("<4I", data, off)
    return RAM[0] < sp <= RAM[1] and sp % 4 == 0 and all(v & 1 and 0xC0 <= (v & ~1) < size
                                                        for v in (reset, nmi, hardfault))


def native_images(data):
    """Return [(offset, image)] for each vector table followed, after the image, by a word holding its length."""
    found = []
    for off in range(0, len(data) - 0xC0, 4):
        if not vector_ok(data, off, MAX_IMAGE):
            continue
        for n in range(0xC0, min(MAX_IMAGE, len(data) - off - 4)):
            end = off + ((n + 3) & ~3)
            if struct.unpack_from("<I", data, end)[0] == n and not any(data[off + n:end]) and vector_ok(data, off, n):
                found.append((off, data[off:off + n]))
                break
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("updater")
    ap.add_argument("-o", "--out", help="write the APROM image here")
    ap.add_argument("--consts", action="store_true", help="print field constants (VID/PID, ISP commands, strings)")
    ap.add_argument("--types", action="store_true", help="print types, methods and fields")
    args = ap.parse_args()

    data = open(args.updater, "rb").read()
    pe = None
    if is_dotnet(data):
        try:
            import dnfile
        except ImportError:
            sys.exit("this is a .NET updater; reading it needs the dnfile package (python -m pip install dnfile)")
        pe = dnfile.dnPE(args.updater)
        found = sorted(blobs(pe), key=lambda b: len(b[2]), reverse=True)
        if not found:
            sys.exit("no static array blobs found")
        for name, rva, blob in found:
            print(f"blob {name[:16]}... rva={rva:#x} size={len(blob)}")
        _, _, fw = found[0]
    else:
        if args.consts or args.types:
            sys.exit("--consts and --types read .NET metadata, and this updater is native code")
        found = native_images(data)
        if len(found) != 1:
            sys.exit(f"found {len(found)} images with a length word after them; expected exactly one")
        off, fw = found[0]
        print(f"native updater: image at file offset {off:#x}, size {len(fw)}")

    sp, reset = struct.unpack_from("<II", fw)
    ok = vector_ok(fw, 0, len(fw))
    print(f"vector table: SP={sp:#010x} Reset={reset:#x} -> {'looks like plaintext Cortex-M' if ok else 'NOT a plain vector table'}")
    print(f"sha256: {hashlib.sha256(fw).hexdigest()}")

    if args.out:
        with open(args.out, "wb") as f:
            f.write(fw)
        print(f"wrote {args.out}")
    if args.consts:
        print("constants:")
        dump_consts(pe)
    if args.types:
        print("types:")
        dump_types(pe)


if __name__ == "__main__":
    main()
