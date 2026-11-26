#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Client for the Ducky One 3 stock bootloader (Nuvoton ISP-over-HID in LDROM) and for the app-mode vendor
interface that asks the stock firmware to reboot into it.

Runs on Linux (sysfs and hidraw) and Windows (hid.dll and SetupAPI, in hid_win.py) with the Python standard
library only. The framing is copied from the official updater (Updater_Nuvoton.MainForm, decompiled), which
matches the OpenNuvoton NUC126BSP ISP_HID sample.

The only flash write is `flash`: UPDATE_APROM plus its data packets, the updater's own sequence. UPDATE_CONFIG,
ERASE_ALL, UPDATE_DATAFLASH and RESEND_PACKET are deliberately not implemented; send() refuses any code outside
READ_ONLY, and accepts UPDATE_APROM and data packets only from flash(). RUN_APROM writes no flash: it sets
ISPCTL.BS=0 and resets.

    isp.py list                    # the keyboard's HID devices and whether they can be opened
    isp.py version                 # app mode: firmware version string (vendor interface 0)
    isp.py reboot-ldrom --yes      # app mode: stock reboot-to-LDROM request, exactly as the updater sends it
    isp.py info [--wait 15]        # LDROM: CONNECT, SYNC_PACKNO, GET_FWVER, GET_DEVICEID, READ_CONFIG
    isp.py run-aprom               # LDROM: leave the bootloader and start the application
    isp.py flash IMAGE             # LDROM: every pre-flight check, then stop (dry run)
    isp.py flash IMAGE --yes       # ... then erase APROM, write IMAGE at 0x0, RUN_APROM

Ducky's LDROM erases more than the BSP: a reflash also resets the stock settings in data flash to factory
defaults.

Every Ducky One 3 model except the Pro uses this bootloader and protocol (MODELS). `flash` reports whether the
image's SHA-256 is listed in firmware/SHA256SUMS, the known images; a listed name like One_3_TKL_RGB_V1.16 gives
the image's model. Before erasing anything it checks that the image's vector table is plausible (SP in RAM, Thumb
reset/NMI/HardFault vectors inside the image), that the chip is one of CHIPS with a CONFIG1 that stock enforces
for it, that CONFIG0 boots the LDROM with data flash enabled, that the image fits below the data flash base, and,
when the bootloader's USB ID names a model, that a listed stock image is for that model. While writing, each
reply's checksum must equal the sum of the packet sent. The BSP computes it after programming the chunk and
reading it back, so a match also means the chunk is in flash. On any failure it stops without RUN_APROM. The
board boots the LDROM first, which flash checks in CONFIG0, so it stays in the bootloader and the same command
can be re-run.

On Linux the hidraw nodes are root-only by default; tools/udev/70-ducky.rules grants access (see its header).
Windows needs no driver and no administrator rights.
"""
import argparse
import glob
import hashlib
import importlib.util
import os
import re
import select
import struct
import sys
import time

# Stock app PID per model, from Ducky's updaters. The LDROM enumerates as 3233:(app PID - 1) after the stock
# firmware's reboot request, and as Nuvoton's 0416:3F00 after D+L or QMK's QK_BOOT.
MODELS = {0x1011: "One 3", 0x8011: "One 3 TKL", 0x1311: "One 3 RGB", 0x8311: "One 3 TKL RGB",
          0x5311: "One 3 SF RGB", 0x6311: "One 3 Mini RGB"}
APP_IDS = {(0x3233, pid) for pid in MODELS}
QMK_IDS = {(0x3233, 0x2108)}  # doombadroid's ducky/one3/rgb
LDROM_IDS = {(0x3233, pid - 1) for pid in MODELS} | {(0x0416, 0x3F00)}  # the updaters accept Nuvoton's IDs too
ALL_IDS = APP_IDS | QMK_IDS | LDROM_IDS
VENDOR_PAGE, VENDOR_USAGE = 0xFF00, 1  # the stock app's vendor interface (USB interface 0)
VENDOR_DESC_PREFIX = bytes.fromhex("0600ff0901")  # its report descriptor: Usage Page (0xFF00), Usage (1)

CMD_CONNECT, CMD_SYNC_PACKNO, CMD_GET_FWVER = 0xAE, 0xA4, 0xA6
CMD_GET_DEVICEID, CMD_READ_CONFIG, CMD_RUN_APROM = 0xB1, 0xA2, 0xAB
READ_ONLY = {
    CMD_CONNECT: "CONNECT", CMD_SYNC_PACKNO: "SYNC_PACKNO", CMD_GET_FWVER: "GET_FWVER",
    CMD_GET_DEVICEID: "GET_DEVICEID", CMD_READ_CONFIG: "READ_CONFIG", CMD_RUN_APROM: "RUN_APROM",
}

CMD_UPDATE_APROM, CMD_DATA = 0xA0, 0x00  # a cmd-0 packet carries the next chunk of the last write command
WRITE = {CMD_UPDATE_APROM: "UPDATE_APROM", CMD_DATA: "UPDATE_APROM data"}

# PDID: (part, flash KB, CONFIG1 values). Every stock image supports both parts and rewrites CONFIG1 at boot to its
# data flash base, minus 0x20000 on the 128 KB part: 0x33200 from V1.12 (RGB V1.16: 0x479c, 0x4adc), 0x32800 up to
# V1.11 (RGB V1.11: 0x4898, 0x4bd4; built as 0xCA << 10, so not a literal). A board that never ran V1.12 or later
# still reads the older value.
CHIPS = {0x01205212: ("NUC1261SG4AE", 256, (0x00033200, 0x00032800)),
         0x01205213: ("NUC1261SE4AE", 128, (0x00013200, 0x00012800))}
RAM = (0x20000000, 0x20005000)  # both parts: 20 KB
SHA256SUMS = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "firmware", "SHA256SUMS")
FIRST_CHUNK, CHUNK = 48, 56  # UPDATE_APROM carries address + length + 48 bytes; data packets carry 56
ERASE_TIMEOUT = 20.0  # the first UPDATE_APROM reply comes after the LDROM's erase (APROM, and data flash too)

CBS = {  # CONFIG0[7:6], NUC126 TRM. Bit 1: 1 = APROM, 0 = LDROM; bit 0: 0 = IAP enabled.
    0b00: "boot LDROM, IAP enabled",
    0b01: "boot LDROM, no IAP",
    0b10: "boot APROM, IAP enabled",
    0b11: "boot APROM, no IAP",
}


class Node:
    """A HID node of one of the IDs above. path is what Hid opens (/dev/hidrawN, or a Windows device path); phys is
    the USB port. vendor: the node's report descriptor is the stock app's vendor collection."""

    def __init__(self, path, ids, phys, vendor):
        self.path, self.ids, self.phys = path, ids, phys
        if ids in LDROM_IDS:
            self.kind = "ldrom"
        elif ids in APP_IDS:
            self.kind = "app-vendor" if vendor else "app-other"
        elif ids in QMK_IDS:
            self.kind = "qmk"
        else:
            self.kind = None

    @property
    def model(self):
        """The model the USB ID names, or None (QMK, or the LDROM as 0416:3F00)."""
        vid, pid = self.ids
        return (MODELS.get(pid) or MODELS.get(pid + 1)) if vid == 0x3233 else None

    def __str__(self):
        ok = "rw ok" if can_open(self.path) else "no access"
        model = f"  {self.model}" if self.model and self.kind != "qmk" else ""
        return f"{self.path}  {self.ids[0]:04x}:{self.ids[1]:04x}  {self.kind:10}{model}  {self.phys}  ({ok})"


# --- Linux: sysfs and hidraw ---------------------------------------------------------------------------------

def nodes():
    found = []
    for d in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        try:
            lines = open(f"{d}/device/uevent").read().splitlines()  # HID_NAME contains spaces
            uevent = dict(line.split("=", 1) for line in lines if "=" in line)
            _, vid, pid = uevent["HID_ID"].split(":")
            desc = open(f"{d}/device/report_descriptor", "rb").read()
        except (OSError, KeyError, ValueError):
            continue
        n = Node("/dev/" + os.path.basename(d), (int(vid, 16), int(pid, 16)), uevent.get("HID_PHYS", ""),
                 desc.startswith(VENDOR_DESC_PREFIX))
        if n.kind:
            found.append(n)
    return found


def can_open(path):
    return os.access(path, os.R_OK | os.W_OK)


class HidDevice:
    """write() takes a report with its report ID byte first; read() returns one report without it."""

    def __init__(self, path):
        try:
            self.fd = os.open(path, os.O_RDWR)
        except PermissionError:
            sys.exit(f"no access to {path}: install tools/udev/70-ducky.rules (see its header)")

    def write(self, report):
        os.write(self.fd, report)

    def read(self, timeout):
        r, _, _ = select.select([self.fd], [], [], timeout)
        return os.read(self.fd, 64) if r else None

    def close(self):
        os.close(self.fd)


# --- Windows: hid_win.py, loaded by path because `python -I` leaves this directory out of sys.path ------------

if sys.platform == "win32":
    _spec = importlib.util.spec_from_file_location(
        "hid_win", os.path.join(os.path.dirname(os.path.abspath(__file__)), "hid_win.py"))
    hid_win = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(hid_win)

    def nodes():
        found = [Node(c.path, (c.vid, c.pid), c.location, (c.page, c.usage) == (VENDOR_PAGE, VENDOR_USAGE))
                 for c in hid_win.hid_collections(ALL_IDS)]
        return [n for n in found if n.kind]

    can_open = hid_win.can_open

    def HidDevice(path):
        try:
            return hid_win.Device(path)
        except OSError as e:
            sys.exit(f"cannot open {path}: {e.strerror}")


def find(kind, wait=0.0):
    deadline = time.monotonic() + wait
    while True:
        match = [n for n in nodes() if n.kind == kind]
        # After re-enumeration the node exists briefly before udev applies the rule's permissions (Linux) or the
        # HID driver is installed for a new USB ID (Windows).
        ready = can_open(match[0].path) if len(match) == 1 else False
        if len(match) == 1 and (ready or time.monotonic() >= deadline):
            return match[0]
        if len(match) > 1:
            sys.exit(f"more than one {kind} device: {', '.join(n.path for n in match)}; pass one with --dev")
        if time.monotonic() >= deadline:
            sys.exit(f"no {kind} device found")
        time.sleep(0.25)


class Hid:
    """64-byte reports, no report IDs: writes carry a leading 0x00 report ID, which the OS's HID driver removes."""

    def __init__(self, path, verbose=False):
        self.dev = HidDevice(path)
        self.verbose = verbose

    def write(self, pkt):
        assert len(pkt) == 64
        if self.verbose:
            print("  >", pkt.hex(" "))
        self.dev.write(b"\x00" + pkt)

    def read(self, timeout):
        data = self.dev.read(timeout)
        if data is not None and self.verbose:
            print("  <", data.hex(" "))
        return data

    def close(self):
        self.dev.close()


# --- app mode (stock firmware, vendor interface 0) -------------------------------------------------------

def app_request(hid, body, pkt_id, cmd, mode, timeout=2.0):
    """Updater framing: [0]=0, [1]=':', [2]=packet id, [3]=length, [4]=type, [5]=cmd, [6]=rw, [7]=mode, [8..]."""
    pkt = bytes([0, ord(":"), pkt_id, 4 + len(body)]) + body
    hid.write(pkt.ljust(64, b"\x00"))
    deadline = time.monotonic() + timeout
    while (left := deadline - time.monotonic()) > 0:
        r = hid.read(left)
        if r and r[2] == pkt_id and r[5] == cmd and r[7] == mode:
            return r
    return None


def app_version(path, verbose=False):
    hid = Hid(path, verbose)
    pkt_id = os.getpid() & 0x7F | 1
    # type 1, cmd 1 (READ_CONFIG), rw 1, mode 1 (VERSION)
    r = app_request(hid, bytes([1, 1, 1, 1]), pkt_id, cmd=1, mode=1)
    hid.close()
    return None if r is None else r[8:r[3]].decode("latin-1")


def cmd_version(args):
    text = app_version(args.dev or find("app-vendor").path, args.verbose)
    if text is None:
        sys.exit("no reply")
    print(f"version reply: {text!r}  (the updater shows {text[3:8]!r})")


def cmd_reboot_ldrom(args):
    if not args.yes:
        sys.exit("this reboots the keyboard into its bootloader (it stops typing until it leaves); pass --yes")
    hid = Hid(args.dev or find("app-vendor").path, args.verbose)
    pkt_id = os.getpid() & 0x7F | 1
    # ApmodeCmdReboot: type 1, cmd 4 (SYS_SETTING), rw 0, mode 1 (REBOOT), data 1
    # Stock (RGB V1.16: 0x9b70 -> 0x8fd0) reboots only if the handshake page (0x3F800, 0x1F800 on the 128 KB part)
    # holds "SuiL", which the LDROM seems to write at power-on; it then resets before replying. Otherwise it just
    # sends the reply and keeps running.
    try:
        r = app_request(hid, bytes([1, 4, 0, 1, 1]), pkt_id, cmd=4, mode=1)
    except OSError:  # the read fails with EIO when the device drops off the bus
        r = None
        print("keyboard disconnected (rebooting)")
    hid.close()
    if r is not None:
        time.sleep(3)
        if not any(n.kind == "ldrom" for n in nodes()):
            sys.exit("the firmware replied but did not reboot. It only honors this request when its handshake "
                     "flash page holds 'SuiL', which seems to be rewritten at power-on after a bootloader visit. "
                     "Unplug and replug the keyboard, then retry.")
    print("waiting for the bootloader to enumerate...")
    n = find("ldrom", wait=10)
    print(f"bootloader present: {n}")


# --- LDROM (Nuvoton ISP_HID) -------------------------------------------------------------------------------

class Ldrom:
    """Request: [0:4] cmd, [4:8] packet number (the updater leaves it 0), [8:64] payload.
    Response: [0:2] u16 sum of the request's 64 bytes, [4:8] device packet number, [8:] data.
    The device counts: CONNECT or SYNC_PACKNO(1) makes the next reply number 2, then +2 per command."""

    def __init__(self, hid):
        self.hid = hid
        self.expect = 2

    def send(self, cmd, payload=b"", timeout=2.0, write=False):
        """Returns the reply, or b"" for RUN_APROM, which gets none. write=True is passed only by flash(), and only
        allows UPDATE_APROM and its data packets."""
        names = READ_ONLY | WRITE if write else READ_ONLY
        if cmd not in names:
            raise ValueError(f"refusing ISP command 0x{cmd:02X}: not allowed here")
        assert len(payload) <= 56
        pkt = (struct.pack("<II", cmd, 0) + payload).ljust(64, b"\x00")
        if cmd in (CMD_CONNECT, CMD_SYNC_PACKNO):
            self.expect = 2
        self.hid.write(pkt)
        if cmd == CMD_RUN_APROM:
            return b""  # the device resets without replying
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            r = self.hid.read(left)
            if r is None:
                break
            csum, packno = struct.unpack_from("<H2xI", r)
            if packno != self.expect:
                continue  # the updater also skips stale replies
            if csum != sum(pkt) & 0xFFFF:
                raise IOError(f"{names[cmd]}: checksum 0x{csum:04x}, expected 0x{sum(pkt) & 0xFFFF:04x}")
            self.expect += 2
            return r
        raise TimeoutError(f"{names[cmd]}: no reply with packet number {self.expect}")


def decode_config(c0, c1):
    cbs = (c0 >> 6) & 3
    lines = [
        f"CONFIG0 = 0x{c0:08X}",
        f"  CBS[7:6]  = {cbs:02b}: {CBS[cbs]}",
        f"  LOCK[1]   = {(c0 >> 1) & 1}: {'unlocked' if c0 & 2 else 'LOCKED (flash reads blocked to ICE/ISP)'}",
        f"  DFEN[0]   = {c0 & 1}: data flash {'disabled' if c0 & 1 else 'enabled, base = CONFIG1'}",
        f"CONFIG1 = 0x{c1:08X}" + ("" if c0 & 1 else f"  (data flash base 0x{c1 & 0xFFFFF:05X})"),
    ]
    return "\n".join(lines)


def identify(isp):
    """CONNECT, SYNC_PACKNO(1), then the updater's three queries. Returns ({name: value}, raw READ_CONFIG reply)."""
    isp.send(CMD_CONNECT)
    isp.send(CMD_SYNC_PACKNO, struct.pack("<I", 1))
    fwver = isp.send(CMD_GET_FWVER)[8]
    pdid = struct.unpack_from("<I", isp.send(CMD_GET_DEVICEID), 8)[0]
    r = isp.send(CMD_READ_CONFIG)
    c0, c1 = struct.unpack_from("<II", r, 8)
    return {"LDROM FW ver": fwver, "PDID": pdid, "CONFIG0": c0, "CONFIG1": c1}, r


def chip_name(pdid):
    part = CHIPS.get(pdid)
    return f"{part[0]}, {part[1]} KB flash" if part else "unknown chip"


def cmd_info(args):
    node = None if args.dev else find("ldrom", wait=args.wait)
    hid = Hid(node.path if node else args.dev, args.verbose)
    ident, r = identify(Ldrom(hid))
    hid.close()
    if node and node.model:
        print(f"model        = {node.model} (from the bootloader's USB ID)")
    print(f"LDROM FW ver = 0x{ident['LDROM FW ver']:02X}")
    print(f"PDID         = 0x{ident['PDID']:08X} ({chip_name(ident['PDID'])})")
    print(decode_config(ident["CONFIG0"], ident["CONFIG1"]))
    print(f"raw READ_CONFIG reply: {r.hex(' ')}")


def wait_for_app(timeout=10.0):
    """After RUN_APROM: wait for the LDROM to leave, then report whichever firmware enumerated."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = nodes()
        apps = [n for n in found if n.kind in ("app-vendor", "qmk")]
        if apps and not any(n.kind == "ldrom" for n in found):
            app = next((n for n in apps if n.kind == "app-vendor"), apps[0])
            # The caller opens the stock app's node next: wait for udev's permissions or Windows' HID driver.
            while app.kind == "app-vendor" and not can_open(app.path) and time.monotonic() < deadline:
                time.sleep(0.1)
            return app
        time.sleep(0.25)
    return None


def cmd_run_aprom(args):
    hid = Hid(args.dev or find("ldrom").path, args.verbose)
    isp = Ldrom(hid)
    isp.send(CMD_CONNECT)
    isp.send(CMD_RUN_APROM)
    hid.close()
    print("RUN_APROM sent; waiting for the keyboard to come back...")
    app = wait_for_app()
    print(f"application present: {app}" if app else "no stock or QMK keyboard enumerated within 10 s")


# --- flash ---------------------------------------------------------------------------------------------------

def listed_names(digest):
    names = []
    try:
        lines = open(SHA256SUMS, encoding="utf-8-sig").read().splitlines()  # -sig: Windows editors may add a BOM
    except FileNotFoundError:
        return names
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and not line.startswith("#") and parts[0].lower() == digest:
            names.append(parts[1].strip())
    return names


def check_image(path):
    """Returns (image padded to whole words with 0xFF, sha256, names in SHA256SUMS); exits on any problem."""
    data = open(path, "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    names = listed_names(digest)
    problems = []
    if len(data) < 0xC0:
        problems.append(f"{len(data)} bytes is smaller than a Cortex-M0 vector table")
    else:
        sp, reset, nmi, hardfault = struct.unpack_from("<4I", data)
        if not (RAM[0] < sp <= RAM[1] and sp % 4 == 0):
            problems.append(f"initial SP 0x{sp:08X} is not a word-aligned address in RAM {RAM[0]:#x}..{RAM[1]:#x}")
        for name, v in (("reset", reset), ("NMI", nmi), ("HardFault", hardfault)):
            if not (v & 1 and (v & ~1) < len(data)):
                problems.append(f"{name} vector 0x{v:08X} is not a Thumb address inside the image (base 0x0)")
    if len(set(data)) <= 1:
        problems.append("the image is one repeated byte")
    if problems:
        sys.exit("image check failed:\n  " + "\n  ".join(problems))
    return data + b"\xff" * (-len(data) % 4), digest, names


def image_models(names):
    """Models named by SHA256SUMS entries such as firmware/One_3_TKL_RGB_V1.16.bin."""
    found = set()
    for name in names:
        m = re.match(r"(One_3(?:_[A-Za-z]+)*)_V\d", os.path.basename(name))
        if m and m.group(1).replace("_", " ") in MODELS.values():
            found.add(m.group(1).replace("_", " "))
    return found


def check_device(ident, image_len, models, board_model):
    """models: the image's models from SHA256SUMS; board_model: the model the bootloader's USB ID names, or None."""
    problems = []
    pdid, c0, c1 = ident["PDID"], ident["CONFIG0"], ident["CONFIG1"]
    if pdid not in CHIPS:
        problems.append(f"PDID 0x{pdid:08X} is not one of " + ", ".join(f"0x{k:08X} ({v[0]})" for k, v in CHIPS.items()))
    elif c1 not in CHIPS[pdid][2]:
        problems.append(f"CONFIG1 0x{c1:08X} is not " + " or ".join(f"0x{v:08X}" for v in CHIPS[pdid][2])
                        + f", which stock firmware sets on the {CHIPS[pdid][0]}")
    if c0 & 0x80:  # CBS[7:6] = 1x
        problems.append(f"CONFIG0 0x{c0:08X} boots APROM first, so a failed flash could not be retried over USB")
    if c0 & 1:
        problems.append(f"CONFIG0 0x{c0:08X} disables data flash, so CONFIG1 does not give the end of APROM")
    aprom_end = c1 & 0xFFFFF  # DFEN=0: data flash starts here, APROM ends here
    if image_len > aprom_end:
        problems.append(f"image is {image_len} bytes; APROM ends at 0x{aprom_end:X}")
    if board_model and models and board_model not in models:
        problems.append(f"the image is stock firmware for the {', '.join(sorted(models))}; this bootloader is the "
                        f"{board_model}'s")
    if problems:
        sys.exit("device check failed (nothing was written):\n  " + "\n  ".join(problems))
    return aprom_end


def packet_count(n):
    return 1 + max(0, -(-(n - FIRST_CHUNK) // CHUNK))


def flash(isp, image, progress=None, state=None):
    """The updater's sequence. Raises on the first bad reply; returns the number of packets sent.
    state["erasing"] is set just before UPDATE_APROM, which erases APROM on receipt."""
    state = {} if state is None else state
    isp.send(CMD_SYNC_PACKNO, struct.pack("<I", 1))
    state["erasing"] = True
    # address is ignored by the BSP (always 0); length bounds the write
    isp.send(CMD_UPDATE_APROM, struct.pack("<II", 0, len(image)) + image[:FIRST_CHUNK],
             timeout=ERASE_TIMEOUT, write=True)
    sent, off = 1, FIRST_CHUNK
    while off < len(image):
        isp.send(CMD_DATA, image[off:off + CHUNK], timeout=3.0, write=True)
        sent, off = sent + 1, off + CHUNK
        if progress:
            progress(min(off, len(image)))
    return sent


def cmd_flash(args):
    image, digest, names = check_image(args.image)
    models = image_models(names)
    n = packet_count(len(image))
    print(f"image   {args.image}: {len(image)} bytes, sha256 {digest}")
    print(f"        {'listed in SHA256SUMS as ' + ', '.join(names) if names else 'not listed in SHA256SUMS'}; "
          "vector table ok")
    node = None if args.dev else find("ldrom", wait=args.wait)
    board_model = node.model if node else None
    hid = Hid(node.path if node else args.dev, args.verbose)
    isp = Ldrom(hid)
    ident, _ = identify(isp)
    aprom_end = check_device(ident, len(image), models, board_model)
    print(f"device  {board_model or 'model unknown from this USB ID'}; {chip_name(ident['PDID'])}; "
          + ", ".join(f"{k} 0x{v:X}" for k, v in ident.items()) + "  (checks passed)")
    print(f"plan    UPDATE_APROM (LDROM erases APROM 0x0-0x{aprom_end - 1:X} and, as observed, stock settings in data "
          f"flash), write 0x0-0x{len(image) - 1:X} in {n} packets, RUN_APROM")
    print("note    stock keyboard settings (lighting mode, brightness, profiles) come back as factory defaults")
    if not args.yes:
        hid.close()
        print("dry run: nothing written. Pass --yes to flash. The keyboard is still in the bootloader "
              "(isp.py run-aprom to leave).")
        return

    start, last, state = time.monotonic(), [0], {}

    def progress(done):
        if done * 10 // len(image) != last[0] * 10 // len(image) or done == len(image):
            print(f"  {done:6d}/{len(image)} bytes", flush=True)
        last[0] = done

    try:
        sent = flash(isp, image, progress, state)
    except (OSError, KeyboardInterrupt) as e:
        hid.close()
        if not state.get("erasing"):
            sys.exit(f"FLASH FAILED before UPDATE_APROM: {e!r}\nNothing was erased or written.")
        sys.exit(f"FLASH FAILED after {last[0]} bytes: {e!r}\n"
                 "APROM is erased or partly written. RUN_APROM was not sent, so the keyboard stays in the "
                 "bootloader (it boots LDROM first). Re-run the same command; UPDATE_APROM erases and starts over.")
    print(f"written: {sent} packets in {time.monotonic() - start:.1f} s, every reply checksum matched")
    if args.no_run:
        hid.close()
        print("--no-run: left in the bootloader")
        return
    isp.send(CMD_RUN_APROM)
    hid.close()
    print("RUN_APROM sent")
    app = wait_for_app()
    if app is None:
        print("no stock or QMK keyboard enumerated within 10 s")
    elif app.kind == "app-vendor":
        print(f"stock app present: {app}; version reply {app_version(app.path)!r}")
    else:
        print(f"{app.kind} present: {app}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dev", help="device to use instead of searching: a path that `list` prints (/dev/hidrawN, "
                    "or a \\\\?\\hid#... path on Windows)")
    ap.add_argument("-v", "--verbose", action="store_true", help="hex-dump every report")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("version")
    p = sub.add_parser("reboot-ldrom")
    p.add_argument("--yes", action="store_true")
    p = sub.add_parser("info")
    p.add_argument("--wait", type=float, default=0, help="seconds to wait for the bootloader to appear")
    sub.add_parser("run-aprom")
    p = sub.add_parser("flash")
    p.add_argument("image", help="raw APROM image, loaded at 0x0")
    p.add_argument("--yes", action="store_true", help="actually erase and write (default: checks only)")
    p.add_argument("--no-run", action="store_true", help="stay in the bootloader after writing")
    p.add_argument("--wait", type=float, default=0, help="seconds to wait for the bootloader to appear")
    args = ap.parse_args()

    if args.cmd == "list":
        for n in nodes():
            print(n)
        return
    {"version": cmd_version, "reboot-ldrom": cmd_reboot_ldrom, "info": cmd_info,
     "run-aprom": cmd_run_aprom, "flash": cmd_flash}[args.cmd](args)


if __name__ == "__main__":
    main()
