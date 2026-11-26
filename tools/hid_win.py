# SPDX-License-Identifier: GPL-2.0-or-later
"""Windows HID access for isp.py, which loads this file on Windows in place of its sysfs and hidraw code.

SetupAPI, cfgmgr32, hid.dll and kernel32 through ctypes; Python standard library only. Windows creates one HID
device per top-level collection. isp.py uses two of them: the stock firmware's collection on USB interface 0
(usage page 0xFF00, usage 1 in V1.15 and later; Generic Desktop, usage 0 in V1.11 and V1.12) and the LDROM's only
collection. Any user can open these read/write, so no driver and no administrator rights are needed. Windows
refuses read/write opens of keyboard and mouse collections.
"""
import collections
import re

try:
    import ctypes
    from ctypes import wintypes as W
except ImportError as e:  # Smart App Control can block the libffi DLL of an unsigned Python build
    raise SystemExit(f"this Python cannot load ctypes ({e}), which isp.py needs on Windows. Smart App Control can "
                     "block the DLLs of unsigned Python builds: use Python from python.org or the Microsoft "
                     "Store.") from e

GENERIC_READ_WRITE = 0xC0000000
FILE_SHARE_READ_WRITE = 3
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
DIGCF_PRESENT, DIGCF_DEVICEINTERFACE = 0x02, 0x10
CM_DRP_LOCATION_INFORMATION, CM_DRP_LOCATION_PATHS = 0x0E, 0x24
ERROR_OPERATION_ABORTED, ERROR_IO_PENDING = 995, 997
WAIT_OBJECT_0 = 0
WRITE_TIMEOUT = 5.0  # seconds; the Linux USB core's timeout for hidraw writes

# location: the USB device's location path, e.g. PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(6)#USB(2). It stays the same
# when the keyboard enumerates again with another USB ID at the same port.
Collection = collections.namedtuple("Collection", "path vid pid page usage location")


# --- Win32 bindings --------------------------------------------------------------------------------------------

class GUID(ctypes.Structure):
    _fields_ = [("Data1", W.DWORD), ("Data2", W.WORD), ("Data3", W.WORD), ("Data4", ctypes.c_ubyte * 8)]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", W.DWORD), ("InterfaceClassGuid", GUID), ("Flags", W.DWORD),
                ("Reserved", ctypes.c_size_t)]


class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [("cbSize", W.DWORD), ("ClassGuid", GUID), ("DevInst", W.DWORD), ("Reserved", ctypes.c_size_t)]


class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Size", W.ULONG), ("VendorID", W.USHORT), ("ProductID", W.USHORT),
                ("VersionNumber", W.USHORT)]


class HIDP_CAPS(ctypes.Structure):
    _fields_ = [("Usage", W.USHORT), ("UsagePage", W.USHORT), ("InputReportByteLength", W.USHORT),
                ("OutputReportByteLength", W.USHORT), ("FeatureReportByteLength", W.USHORT),
                ("Reserved", W.USHORT * 17), ("Counts", W.USHORT * 10)]


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t), ("Offset", W.DWORD),
                ("OffsetHigh", W.DWORD), ("hEvent", W.HANDLE)]


def _fn(dll, name, restype, *argtypes):
    f = getattr(dll, name)
    f.restype, f.argtypes = restype, argtypes
    return f


_hid, _setupapi, _cfgmgr, _kernel = (ctypes.WinDLL(n, use_last_error=True)
                                     for n in ("hid", "setupapi", "cfgmgr32", "kernel32"))
_P, _VP = ctypes.POINTER, ctypes.c_void_p
HidD_GetHidGuid = _fn(_hid, "HidD_GetHidGuid", None, _P(GUID))
HidD_GetAttributes = _fn(_hid, "HidD_GetAttributes", W.BOOLEAN, W.HANDLE, _P(HIDD_ATTRIBUTES))
HidD_GetPreparsedData = _fn(_hid, "HidD_GetPreparsedData", W.BOOLEAN, W.HANDLE, _P(_VP))
HidD_FreePreparsedData = _fn(_hid, "HidD_FreePreparsedData", W.BOOLEAN, _VP)
HidP_GetCaps = _fn(_hid, "HidP_GetCaps", W.LONG, _VP, _P(HIDP_CAPS))
HidD_GetSerialNumberString = _fn(_hid, "HidD_GetSerialNumberString", W.BOOLEAN, W.HANDLE, _VP, W.ULONG)
SetupDiGetClassDevsW = _fn(_setupapi, "SetupDiGetClassDevsW", W.HANDLE, _P(GUID), W.LPCWSTR, W.HWND, W.DWORD)
SetupDiEnumDeviceInterfaces = _fn(_setupapi, "SetupDiEnumDeviceInterfaces", W.BOOL, W.HANDLE, _VP, _P(GUID),
                                  W.DWORD, _P(SP_DEVICE_INTERFACE_DATA))
SetupDiGetDeviceInterfaceDetailW = _fn(_setupapi, "SetupDiGetDeviceInterfaceDetailW", W.BOOL, W.HANDLE,
                                       _P(SP_DEVICE_INTERFACE_DATA), _VP, W.DWORD, _P(W.DWORD),
                                       _P(SP_DEVINFO_DATA))
SetupDiDestroyDeviceInfoList = _fn(_setupapi, "SetupDiDestroyDeviceInfoList", W.BOOL, W.HANDLE)
CM_Get_Parent = _fn(_cfgmgr, "CM_Get_Parent", W.DWORD, _P(W.DWORD), W.DWORD, W.ULONG)
CM_Get_Device_IDW = _fn(_cfgmgr, "CM_Get_Device_IDW", W.DWORD, W.DWORD, W.LPWSTR, W.ULONG, W.ULONG)
CM_Get_DevNode_Registry_PropertyW = _fn(_cfgmgr, "CM_Get_DevNode_Registry_PropertyW", W.DWORD, W.DWORD,
                                        W.ULONG, _P(W.ULONG), _VP, _P(W.ULONG), W.ULONG)
CreateFileW = _fn(_kernel, "CreateFileW", W.HANDLE, W.LPCWSTR, W.DWORD, W.DWORD, _VP, W.DWORD, W.DWORD,
                  W.HANDLE)
CloseHandle = _fn(_kernel, "CloseHandle", W.BOOL, W.HANDLE)
CreateEventW = _fn(_kernel, "CreateEventW", W.HANDLE, _VP, W.BOOL, W.BOOL, W.LPCWSTR)
WriteFile = _fn(_kernel, "WriteFile", W.BOOL, W.HANDLE, _VP, W.DWORD, _P(W.DWORD), _P(OVERLAPPED))
ReadFile = _fn(_kernel, "ReadFile", W.BOOL, W.HANDLE, _VP, W.DWORD, _P(W.DWORD), _P(OVERLAPPED))
WaitForSingleObject = _fn(_kernel, "WaitForSingleObject", W.DWORD, W.HANDLE, W.DWORD)
CancelIoEx = _fn(_kernel, "CancelIoEx", W.BOOL, W.HANDLE, _P(OVERLAPPED))
GetOverlappedResult = _fn(_kernel, "GetOverlappedResult", W.BOOL, W.HANDLE, _P(OVERLAPPED), _P(W.DWORD),
                          W.BOOL)
INVALID_HANDLE = W.HANDLE(-1).value


def _open(path, access, flags=0):
    """CreateFile on a HID collection; None if it cannot be opened (the last error says why)."""
    h = CreateFileW(path, access, FILE_SHARE_READ_WRITE, None, OPEN_EXISTING, flags, None)
    return None if h in (None, INVALID_HANDLE) else h


def can_open(path):
    h = _open(path, GENERIC_READ_WRITE, FILE_FLAG_OVERLAPPED)
    if h is None:
        return False
    CloseHandle(h)
    return True


def serial_number(path):
    """The USB serial number string of a HID collection's device ("" if it has none or cannot be opened). Windows
    may ask the device for its string descriptor; no HID report is sent."""
    h = _open(path, 0)  # access 0 suffices, as for attributes and caps
    if h is None:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(128)  # a USB string descriptor holds at most 126 UTF-16 code units
        return buf.value if HidD_GetSerialNumberString(h, buf, ctypes.sizeof(buf)) else ""
    finally:
        CloseHandle(h)


# --- discovery -------------------------------------------------------------------------------------------------

def _devnode_id(devinst):
    buf = ctypes.create_unicode_buffer(512)
    return buf.value if CM_Get_Device_IDW(devinst, buf, len(buf), 0) == 0 else ""


def _devnode_strings(devinst, prop):
    """A string or string-list property of a device node ([] if it has none)."""
    buf = ctypes.create_unicode_buffer(1024)
    n = W.ULONG(ctypes.sizeof(buf))
    if CM_Get_DevNode_Registry_PropertyW(devinst, prop, None, buf, ctypes.byref(n), 0) != 0:
        return []
    return [s for s in ctypes.wstring_at(ctypes.addressof(buf), n.value // 2).split("\0") if s]


def _usb_location(devinst):
    """Location path of the USB device above a HID collection: HID\\... -> USB\\VID_...&MI_00\\... -> USB\\VID_...\\..."""
    while True:
        inst = _devnode_id(devinst)
        if not (inst.upper().startswith("HID\\") or "&MI_" in inst.upper()):
            break
        parent = W.DWORD()
        if CM_Get_Parent(ctypes.byref(parent), devinst, 0) != 0:
            break
        devinst = parent.value
    return (_devnode_strings(devinst, CM_DRP_LOCATION_PATHS)
            or _devnode_strings(devinst, CM_DRP_LOCATION_INFORMATION) or [inst])[0]


def hid_collections(ids):
    """Return [Collection] for the present HID collections of the (vid, pid) pairs in ids. Nothing is sent."""
    guid = GUID()
    HidD_GetHidGuid(ctypes.byref(guid))
    hdev = SetupDiGetClassDevsW(ctypes.byref(guid), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if hdev in (None, INVALID_HANDLE):
        raise ctypes.WinError(ctypes.get_last_error())
    found = []
    try:
        i = 0
        while True:
            ifd = SP_DEVICE_INTERFACE_DATA(cbSize=ctypes.sizeof(SP_DEVICE_INTERFACE_DATA))
            if not SetupDiEnumDeviceInterfaces(hdev, None, ctypes.byref(guid), i, ctypes.byref(ifd)):
                break
            i += 1
            need = W.DWORD()
            SetupDiGetDeviceInterfaceDetailW(hdev, ctypes.byref(ifd), None, 0, ctypes.byref(need), None)
            buf = ctypes.create_string_buffer(max(need.value, 8))
            # SP_DEVICE_INTERFACE_DETAIL_DATA_W.cbSize: a DWORD and one WCHAR, padded to the pointer alignment
            ctypes.c_uint32.from_buffer(buf).value = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
            dinfo = SP_DEVINFO_DATA(cbSize=ctypes.sizeof(SP_DEVINFO_DATA))
            if not SetupDiGetDeviceInterfaceDetailW(hdev, ctypes.byref(ifd), buf, len(buf), None,
                                                    ctypes.byref(dinfo)):
                continue
            path = ctypes.wstring_at(ctypes.addressof(buf) + 4)
            m = re.search(r"vid_([0-9a-f]{4})&pid_([0-9a-f]{4})", path, re.I)
            if not m or (int(m.group(1), 16), int(m.group(2), 16)) not in ids:
                continue
            h = _open(path, 0)  # access 0: attributes and caps only, also for keyboard collections
            if h is None:
                continue
            try:
                attrs, caps, pp = HIDD_ATTRIBUTES(Size=ctypes.sizeof(HIDD_ATTRIBUTES)), HIDP_CAPS(), _VP()
                if not (HidD_GetAttributes(h, ctypes.byref(attrs)) and HidD_GetPreparsedData(h, ctypes.byref(pp))):
                    continue
                HidP_GetCaps(pp, ctypes.byref(caps))
                HidD_FreePreparsedData(pp)
            finally:
                CloseHandle(h)
            if (attrs.VendorID, attrs.ProductID) not in ids:
                continue
            found.append(Collection(path, attrs.VendorID, attrs.ProductID, caps.UsagePage, caps.Usage,
                                    _usb_location(dinfo.DevInst)))
    finally:
        SetupDiDestroyDeviceInfoList(hdev)
    return sorted(found)


# --- transport -------------------------------------------------------------------------------------------------

class Device:
    """An open HID collection. write() takes a report with its report ID byte first; read() returns one input
    report without it, as hidraw does for a device without report IDs."""

    def __init__(self, path):
        self.h = _open(path, GENERIC_READ_WRITE, FILE_FLAG_OVERLAPPED)
        if self.h is None:
            raise ctypes.WinError(ctypes.get_last_error())
        caps, pp = HIDP_CAPS(), _VP()
        if HidD_GetPreparsedData(self.h, ctypes.byref(pp)):
            HidP_GetCaps(pp, ctypes.byref(caps))
            HidD_FreePreparsedData(pp)
        self.inp, self.out = caps.InputReportByteLength, caps.OutputReportByteLength  # with the report ID byte
        self.event = CreateEventW(None, True, False, None)

    def _io(self, start, timeout):
        """Run the overlapped call start(overlapped). Return the byte count, or None if it did not complete within
        timeout seconds."""
        ov, n = OVERLAPPED(hEvent=self.event), W.DWORD()
        if not start(ctypes.byref(ov)):
            err = ctypes.get_last_error()
            if err != ERROR_IO_PENDING:
                raise ctypes.WinError(err)
        signaled = False
        try:
            signaled = WaitForSingleObject(self.event, max(0, int(timeout * 1000))) == WAIT_OBJECT_0
        finally:
            # On a timeout or a KeyboardInterrupt, cancel. Waiting for the result then guarantees that the kernel no
            # longer writes to ov or the caller's buffer.
            if not signaled:
                CancelIoEx(self.h, ctypes.byref(ov))
            ok = GetOverlappedResult(self.h, ctypes.byref(ov), ctypes.byref(n), True)
            err = ctypes.get_last_error()
        if ok:
            return n.value  # also when it completed just before the cancel
        if err == ERROR_OPERATION_ABORTED and not signaled:
            return None
        raise ctypes.WinError(err)

    def write(self, report):
        if len(report) > self.out:
            raise OSError(f"output report of {len(report)} bytes; the collection's is {self.out}")
        buf = ctypes.create_string_buffer(bytes(report), self.out)  # zero-padded to the collection's length
        if self._io(lambda ov: WriteFile(self.h, buf, len(buf), None, ov), WRITE_TIMEOUT) is None:
            raise TimeoutError("output report timed out")

    def read(self, timeout):
        """One input report, or None if none arrives within timeout seconds."""
        buf = ctypes.create_string_buffer(self.inp)
        n = self._io(lambda ov: ReadFile(self.h, buf, len(buf), None, ov), timeout)
        return None if n is None else buf.raw[1:n]

    def close(self):
        CloseHandle(self.event)
        CloseHandle(self.h)
