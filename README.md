# Ducky One 3: stock bootloader tools

Tools for the stock bootloader of the Ducky One 3 keyboards. Use them to check the bootloader, to restore stock
firmware, and to flash other firmware such as QMK (for example the One 3 RGB full-size port in
[qmk/qmk_firmware#26499](https://github.com/qmk/qmk_firmware/pull/26499)). They were tested on a One 3 RGB
full-size (ANSI) under Linux and under Windows 11 with Python 3.14, together with Ducky's updater. They were
written with Claude Code.

These models use the same bootloader and are supported. The IDs come from Ducky's updaters.

| Model | Stock firmware USB ID | Bootloader USB ID after a reboot request |
|---|---|---|
| One 3 | `3233:1011` | `3233:1010` |
| One 3 TKL | `3233:8011` | `3233:8010` |
| One 3 RGB | `3233:1311` | `3233:1310` |
| One 3 TKL RGB | `3233:8311` | `3233:8310` |
| One 3 SF RGB | `3233:5311` | `3233:5310` |
| One 3 Mini RGB | `3233:6311` | `3233:6310` |

The One 3 Pro models are not supported. Their updaters use another bootloader protocol.

## The bootloader

Ducky's bootloader (LDROM, Nuvoton ISP over HID) runs first after every reset, because CONFIG0 selects boot from
LDROM. It starts the installed firmware unless D and L are held or the firmware asked for the bootloader.

Enter the bootloader in one of these ways:

- Hold D and L while you plug in the keyboard. The bootloader checks these keys itself, before it starts the
  installed firmware, so this works as long as CONFIG0 still selects boot from LDROM. This was tested on the One 3
  RGB.
- Press the key mapped to `QK_BOOT` in QMK (Fn+Esc in the One 3 RGB port's default keymap).
- Run `isp.py reboot-ldrom --yes` while the stock firmware runs. Ducky's updater sends the same request. After a
  bootloader visit that ends with the stock firmware starting again, such as a flash of stock firmware or
  `isp.py run-aprom`, the stock firmware ignores the request until you unplug and replug the keyboard.
  `reboot-ldrom` then says so. `QK_BOOT` and D+L have no such limit.

The bootloader enumerates as `0416:3f00` after D+L or `QK_BOOT`, and with the model's own ID (table above) after
the reboot request. To leave it without flashing, unplug and replug the keyboard, or run `isp.py run-aprom`.

Every stock firmware supports two chips:

| Chip | Flash | PDID | CONFIG1 (data flash base), V1.12 and later | Up to V1.11 |
|---|---|---|---|---|
| NUC1261SG4AE | 256 KB | 0x01205212 | 0x00033200 | 0x00032800 |
| NUC1261SE4AE | 128 KB | 0x01205213 | 0x00013200 | 0x00012800 |

`isp.py info` shows which one your keyboard has.

Each flash erases the whole application flash and resets the stock settings (lighting mode, brightness, and
profiles) to factory defaults. It also erases QMK's settings.

On the One 3 RGB, CONFIG0 has the security lock set, so the SWD header is not a recovery path there. Removing the
lock erases the whole chip, including the bootloader.

## isp.py

`isp.py` needs Python 3.9 or later and nothing outside the standard library.

- Windows: use Python from python.org or the Microsoft Store. No driver and no administrator rights are needed.
- Linux: install `tools/udev/70-ducky.rules` (the commands are in its header) or run `isp.py` as root.

The commands below use `python`. On Linux, use `python3` if `python` is not available.

| Command | Mode | What it does |
|---|---|---|
| `python tools/isp.py list` | any | Lists the keyboard's HID devices and whether you can open them |
| `python tools/isp.py version` | stock | Prints the stock firmware version |
| `python tools/isp.py reboot-ldrom --yes` | stock | Reboots the stock firmware into the bootloader |
| `python tools/isp.py info --wait 15` | bootloader | Prints the bootloader version, chip, CONFIG0, and CONFIG1 |
| `python tools/isp.py run-aprom` | bootloader | Starts the installed firmware |
| `python tools/isp.py flash --wait 30 IMAGE` | bootloader | Runs every check below, then stops without writing |
| `python tools/isp.py flash --wait 30 IMAGE --yes` | bootloader | Runs the checks, erases, writes IMAGE, and starts it |

`--wait` gives you that many seconds to enter the bootloader after you start the command.

IMAGE is a raw binary that starts at address 0, such as the `.bin` that `qmk compile` writes. `flash` refuses
`.hex` and `.uf2` files.

`flash` prints whether the image's SHA-256 is listed in `firmware/SHA256SUMS`, which lists the known stock
images. Before it erases anything, `flash` checks that:

- the image starts with a plausible vector table and fits below the data flash;
- the chip is one of the two above, with a CONFIG1 that the stock firmware sets for it;
- CONFIG0 boots the bootloader first and enables data flash;
- a listed stock image is for the keyboard's model, when the bootloader's USB ID names the model (after a reboot
  request).

While writing, `flash` checks each reply's checksum, which the bootloader computes after it writes the chunk and
reads it back. If a check fails after the erase, `flash` stops without starting the firmware. The keyboard then
stays in the bootloader, and you can run the same command again.

If `flash` refuses your keyboard, open an issue with the output of `info`.

## Get a stock image

Download your model's updater from Ducky's [downloads page](https://ducky.global/pages/downloads). Some older
versions are on the product pages at mechanicalkeyboards.com, for example the
[One 3 Classic](https://mechanicalkeyboards.com/products/ducky-one-3-classic) page. The stock firmware is stored
unencrypted inside the updater, and this repository does not include it. Extract it with `extract_fw.py`. For the
V1.15 and V1.16 updaters, which are .NET programs, it needs the `dnfile` package:

```
python -m pip install dnfile
python tools/extract_fw.py Ducky_One_3_TKL_RGB_V1.16.exe -o firmware/One_3_TKL_RGB_V1.16.bin
```

The V1.11 and V1.13 updaters need no package. `extract_fw.py` prints the image's SHA-256, and `firmware/SHA256SUMS`
lists the images of V1.11, V1.13, V1.15, and V1.16 for every model above. `flash` looks up the image there by its
SHA-256 and takes the image's model from the entry's name.

## Test the restore first

While the stock firmware is still installed:

1. Hold D and L while you plug in the keyboard, and run `python tools/isp.py info --wait 15`. This writes nothing.
   It shows that D+L and `isp.py` work on your keyboard, and which chip it has. Unplug and replug the keyboard to
   return to the stock firmware.
2. Enter the bootloader again and flash stock over stock, for example:
   `python tools/isp.py flash --wait 30 firmware/One_3_RGB_V1.16.bin --yes`.

## Flash QMK or other firmware

Enter the bootloader and run `python tools/isp.py flash --wait 30 firmware/my-qmk.bin --yes`. To go back to
stock, enter the bootloader and flash your model's stock image the same way, or use Ducky's updater (below).

Firmware that rewrites CONFIG0 to boot from APROM stops the bootloader from running first after a reset, and D+L
then no longer works. A ChibiOS build with `NUC126_CONFIG_ENABLED TRUE` does this. The One 3 RGB port in
qmk/qmk_firmware#26499 keeps it `FALSE` and never writes the LDROM or CONFIG0.

That port keeps its settings at 0x30000-0x31FFF and writes its `QK_BOOT` handshake at 0x3F800. Both are outside
the 128 KB chip.

## Restore stock with Ducky's updater (Windows)

Enter the bootloader, then start your model's V1.15 or V1.16 updater. While the updater searches for the keyboard,
it also searches for the bootloader, and it flashes its firmware as soon as it finds it, without the Start button.
The updater reads the bootloader version, chip ID, and CONFIG registers but checks none of them, and it does not
check the bootloader's replies. This was tested with the One 3 RGB V1.16 updater.

- While it flashes, its window may still say "No any Ducky keyboard...". Wait for the "Program complete" dialog.
- Close the updater and its dialogs when it is done. While it runs, it flashes its firmware again whenever the
  bootloader appears, also with the dialog open. Close it before you run `isp.py reboot-ldrom` or `isp.py flash`,
  or hold D and L at plug-in.

The V1.11 and V1.13 updaters are a different program, and they can't restore stock from QMK. Their code, which
was read but not run, shows that they search only for the model's two Ducky IDs (table above). They don't find a
keyboard that entered the bootloader with D+L or `QK_BOOT`, because it enumerates as `0416:3f00`. They also flash
only after you press Start, and only on the NUC1261SG4AE.

## License

GPL-2.0-or-later. The license text is in [LICENSE](LICENSE).
