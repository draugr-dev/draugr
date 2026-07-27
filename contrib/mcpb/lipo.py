#!/usr/bin/env python3
"""Combine two Mach-O binaries into one universal (fat) binary.

Apple's `lipo` only exists on macOS, and the release runs on Linux. The container format is
simple enough to write directly, and doing so keeps the bundle build on one runner.

Why a universal binary at all: the MCP Registry's package schema has no architecture field, and
an .mcpb manifest's platform_overrides key on OS ("darwin") rather than arch. So a single bundle
entry must serve both Apple silicon and Intel, and the only way to do that is one file that
contains both.

Usage: lipo.py <amd64> <arm64> <output>
"""

import struct
import sys

FAT_MAGIC_64 = 0xCAFEBABF  # 64-bit fat header; offsets/sizes are 8 bytes
CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_X86_64 = CPU_ARCH_ABI64 | 7
CPU_TYPE_ARM64 = CPU_ARCH_ABI64 | 12
CPU_SUBTYPE_X86_64_ALL = 3
CPU_SUBTYPE_ARM64_ALL = 0

# Mach-O slices must start on a page boundary, and arm64 pages are 16 KiB. Using the larger
# alignment for both is correct and costs at most a few kilobytes of padding.
ALIGN_POW2 = 14
ALIGN = 1 << ALIGN_POW2


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    amd64_path, arm64_path, out_path = sys.argv[1:4]

    slices = []
    for path, cpu, sub in (
        (amd64_path, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL),
        (arm64_path, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL),
    ):
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) < 4:
            print(f"{path}: too small to be a Mach-O binary", file=sys.stderr)
            return 1
        magic = struct.unpack(">I", data[:4])[0]
        # Mach-O 64-bit is 0xFEEDFACF, little-endian on disk so it reads as CFFAEDFE big-endian.
        if magic not in (0xFEEDFACF, 0xCFFAEDFE):
            print(f"{path}: not a 64-bit Mach-O binary (magic {magic:#x})", file=sys.stderr)
            return 1
        slices.append((cpu, sub, data))

    # The fat header and its arch table come first, then each slice on an aligned offset.
    header_size = 8 + 32 * len(slices)
    offset = (header_size + ALIGN - 1) // ALIGN * ALIGN

    entries = []
    for cpu, sub, data in slices:
        entries.append((cpu, sub, offset, len(data), ALIGN_POW2))
        offset = (offset + len(data) + ALIGN - 1) // ALIGN * ALIGN

    # Everything in a fat header is big-endian, whatever the slices themselves are.
    with open(out_path, "wb") as out:
        out.write(struct.pack(">II", FAT_MAGIC_64, len(slices)))
        for cpu, sub, off, size, align in entries:
            out.write(struct.pack(">iiQQI4x", cpu, sub, off, size, align))
        for (_, _, data), (_, _, off, _, _) in zip(slices, entries):
            out.write(b"\0" * (off - out.tell()))
            out.write(data)

    print(f"  universal binary: {out_path} ({offset} bytes, {len(slices)} slices)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
