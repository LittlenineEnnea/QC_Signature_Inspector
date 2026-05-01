#!/usr/bin/env python3
"""
qc_inspect.py - Qualcomm firmware image inspector (MELF / MBN / ELF)
Author: Littlenine (github.com/LittlenineEnnea)
Usage:
    python qc_inspect.py <file.melf|file.mbn|file.elf>
    python qc_inspect.py <file> -v     # verbose: full cert chain + hex dumps
    python qc_inspect.py <file> -vv    # very verbose: raw bytes of all fields
"""

import sys
import os
import re
import struct
import hashlib
import argparse
import subprocess
import tempfile

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"

def c(color, text):
    return f"{color}{text}{RESET}"

def header(title):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")

def section(title):
    print(f"\n{BOLD}{YELLOW}[{title}]{RESET}")

def field(name, value, extra=""):
    extra_str = f"  {DIM}({extra}){RESET}" if extra else ""
    print(f"  {name:<28} {c(GREEN, str(value))}{extra_str}")

def hexdump(data, base_offset=0, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {DIM}0x{base_offset+i:08x}:{RESET}  {hex_part:<{width*3}}  {asc_part}")

# ---------------------------------------------------------------------------
# ELF parsing
# ---------------------------------------------------------------------------
ELF_MAGIC = b'\x7fELF'

ELF_MACHINE = {
    0xF3: "RISC-V",
    0x28: "ARM",
    0xB7: "AArch64",
    0x03: "x86",
    0x3E: "x86-64",
}

ELF_OS_SEG_TYPE = {
    0x0: "NULL",
    0x1: "HASH (Qualcomm Hash Table Segment)",
    0x2: "ENCRYPT",
    0x3: "NON_PAGED_SEGMENT",
}

def parse_elf(data, verbose):
    section("ELF Header")
    if data[:4] != ELF_MAGIC:
        print(c(RED, "  ERROR: Not a valid ELF file"))
        return None, []

    ei_class = data[4]  # 1=32bit, 2=64bit
    is64 = (ei_class == 2)
    field("Class", "ELF64" if is64 else "ELF32")
    field("Data encoding", "little-endian" if data[5] == 1 else "big-endian")

    machine = struct.unpack_from('<H', data, 18)[0]
    field("Machine", f"0x{machine:04x}  {ELF_MACHINE.get(machine, 'Unknown')}")

    if is64:
        e_entry, e_phoff, _, e_flags, _, e_phentsize, e_phnum = struct.unpack_from('<QQQI3H', data, 24)
    else:
        e_entry, e_phoff, _, e_flags, _, e_phentsize, e_phnum = struct.unpack_from('<IIIIHHH', data, 24)

    field("Entry point", f"0x{e_entry:08x}")
    field("Program header offset", f"0x{e_phoff:x}")
    field("Program header count", e_phnum)
    field("Flags", f"0x{e_flags:x}")

    # Parse program headers
    segments = []
    section("Program Headers")
    print(f"  {'Idx':<4} {'Type':<6} {'Offset':<12} {'VirtAddr':<12} {'FileSize':<12} {'MemSize':<12} {'Flags':<6} {'OS Type'}")
    print(f"  {'-'*90}")

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from('<IIQQQQQQ', data, off)
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from('<IIIIIIII', data, off)

        # OS-specific segment type (byte at p_flags >> 24 for Qualcomm)
        os_type = (p_flags >> 24) & 0xFF
        os_type_str = ELF_OS_SEG_TYPE.get(os_type, f"0x{os_type:02x}")
        flags_rwe = ('R' if p_flags & 4 else '-') + ('W' if p_flags & 2 else '-') + ('E' if p_flags & 1 else '-')

        type_str = {1: "LOAD", 0: "NULL", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE"}.get(p_type, f"0x{p_type:x}")
        print(f"  {i:<4} {type_str:<6} 0x{p_offset:<10x} 0x{p_vaddr:<10x} 0x{p_filesz:<10x} 0x{p_memsz:<10x} {flags_rwe:<6} {os_type_str}")

        seg_data = data[p_offset:p_offset + p_filesz]
        segments.append({
            'index': i,
            'type': p_type,
            'offset': p_offset,
            'vaddr': p_vaddr,
            'filesz': p_filesz,
            'memsz': p_memsz,
            'flags': p_flags,
            'os_type': os_type,
            'data': seg_data,
        })

        if verbose >= 2:
            print(f"    {DIM}raw hex (first 32 bytes):{RESET}")
            hexdump(seg_data[:32], base_offset=p_offset)

    return e_phoff + e_phnum * e_phentsize, segments

# ---------------------------------------------------------------------------
# MBNv7 Hash Table Segment parser
# ---------------------------------------------------------------------------
HASH_SEG_MAGIC   = 0x0015555A  # Hash Table Segment header
SIG_BLOCK_MAGIC  = 0x00155656  # Signature block

HASH_ALG = {0: "SHA384", 1: "SHA256", 2: "SHA512"}

def find_mbnv7(data, elf_end, verbose):
    """Scan beyond ELF for MBNv7 Hash Table Segment."""
    section("Scanning for MBNv7 Hash Table Segment")

    results = []
    # Search in extra data after ELF
    search_region = data[elf_end:]
    magic_bytes = struct.pack('<I', HASH_SEG_MAGIC)

    offsets = [m.start() + elf_end for m in re.finditer(re.escape(magic_bytes), search_region)]

    if not offsets:
        print(c(RED, "  No MBNv7 Hash Table Segment found"))
        return results

    print(f"  Found {len(offsets)} Hash Table Segment(s)")

    for base in offsets:
        if base + 32 > len(data):
            continue

        magic    = struct.unpack_from('<I', data, base)[0]
        version  = struct.unpack_from('<I', data, base + 0x04)[0]
        flags    = struct.unpack_from('<I', data, base + 0x08)[0]
        n_entry  = struct.unpack_from('<I', data, base + 0x0C)[0]
        reserved = struct.unpack_from('<I', data, base + 0x10)[0]
        total_sz = struct.unpack_from('<I', data, base + 0x14)[0]
        hash_alg = struct.unpack_from('<I', data, base + 0x18)[0]

        print(f"\n  {BOLD}Hash Table Segment @ 0x{base:x}{RESET}")
        field("  Magic",      f"0x{magic:08x}")
        field("  Version",    version)
        field("  Flags",      f"0x{flags:08x}")
        field("  Num entries", n_entry)
        field("  Total size", f"0x{total_sz:x} ({total_sz} bytes)")
        field("  Hash alg",   HASH_ALG.get(hash_alg, f"0x{hash_alg:x}"))

        # Find signature block nearby
        sig_magic_bytes = struct.pack('<I', SIG_BLOCK_MAGIC)
        search_window = data[base:base + total_sz + 0x200]
        sig_rel = [m.start() for m in re.finditer(re.escape(sig_magic_bytes), search_window)]

        sig_info = {}
        if sig_rel:
            sig_base = base + sig_rel[0]
            field("  Sig block offset", f"0x{sig_base:x}")

            # ECDSA signature: look for DER sequence 30 6x 02
            ecdsa_pat = re.compile(b'\x30[\x44\x46\x48\x60\x62\x64\x66\x68]\x02')
            sig_search = data[sig_base:sig_base + 0x400]
            ecdsa_matches = list(ecdsa_pat.finditer(sig_search))
            if ecdsa_matches:
                sig_off = sig_base + ecdsa_matches[0].start()
                sig_len = data[sig_off + 1] + 2
                sig_der = data[sig_off:sig_off + sig_len]
                field("  ECDSA sig offset", f"0x{sig_off:x}")
                field("  ECDSA sig length", f"{sig_len} bytes")
                if verbose >= 1:
                    _print_ecdsa(sig_der)
                sig_info['der'] = sig_der
                sig_info['offset'] = sig_off

        # Find hashes (48-byte non-zero blocks = SHA384)
        hashes = []
        scan_start = base + 0x100
        scan_end   = min(base + total_sz, len(data))
        for off in range(scan_start, scan_end - 48, 4):
            blk = data[off:off+48]
            if sum(blk) > 0x100 and blk[:4] != b'\x00'*4:
                hashes.append((off, blk))

        if hashes:
            field("  Segment hashes found", len(hashes))
            for i, (hoff, hblk) in enumerate(hashes[:4]):
                field(f"  Hash[{i}] @ 0x{hoff:x}", hblk.hex())

        results.append({
            'base': base,
            'version': version,
            'hash_alg': HASH_ALG.get(hash_alg, str(hash_alg)),
            'n_entry': n_entry,
            'sig_info': sig_info,
            'hashes': hashes,
        })

    return results

def _print_ecdsa(sig_der):
    """Parse and print ECDSA DER signature r, s values."""
    try:
        if sig_der[2] != 0x02:
            return
        r_len = sig_der[3]
        r = sig_der[4:4+r_len]
        s_off = 4 + r_len
        if sig_der[s_off] != 0x02:
            return
        s_len = sig_der[s_off+1]
        s = sig_der[s_off+2:s_off+2+s_len]
        print(f"    {DIM}ECDSA r ({r_len}B): {r.hex()}{RESET}")
        print(f"    {DIM}ECDSA s ({s_len}B): {s.hex()}{RESET}")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Certificate chain parser
# ---------------------------------------------------------------------------
def find_certs(data, verbose):
    """Find and parse all DER X.509 certificates in the file."""
    section("Certificate Chains")

    certs = []
    for m in re.finditer(b'\x30\x82', data):
        off = m.start()
        if off + 4 > len(data):
            continue
        cert_len = struct.unpack_from('>H', data, off+2)[0] + 4
        if not (100 < cert_len < 8192):
            continue
        cert_data = data[off:off+cert_len]

        # Try openssl to validate
        info = _parse_cert_openssl(cert_data)
        if info:
            certs.append({'offset': off, 'len': cert_len, 'data': cert_data, 'info': info})

    if not certs:
        print(c(RED, "  No valid X.509 certificates found"))
        return []

    # Deduplicate by content hash
    seen = set()
    unique = []
    for c_ in certs:
        h = hashlib.sha256(c_['data']).hexdigest()
        if h not in seen:
            seen.add(h)
            unique.append(c_)

    # Group into chains: root certs (self-signed) anchor chains
    roots = [c_ for c_ in unique if c_['info'].get('subject') == c_['info'].get('issuer')]
    non_roots = [c_ for c_ in unique if c_ not in roots]

    print(f"  Total unique certs: {len(unique)}  (roots: {len(roots)}, non-root: {len(non_roots)})")

    # Print all certs grouped
    chains = _group_chains(unique)
    for chain_idx, chain in enumerate(chains):
        print(f"\n  {BOLD}Certificate Chain {chain_idx+1}{RESET}")
        for depth, cert in enumerate(chain):
            info = cert['info']
            indent = "    " + "  " * depth
            role = "Root CA" if info.get('subject') == info.get('issuer') else ("CA" if depth < len(chain)-1 else "Leaf")
            print(f"{indent}{BOLD}[{role}]{RESET}  @ offset 0x{cert['offset']:x}")
            print(f"{indent}  Subject : {info.get('subject', 'N/A')}")
            print(f"{indent}  Issuer  : {info.get('issuer',  'N/A')}")
            print(f"{indent}  Validity: {info.get('not_before','?')} ~ {info.get('not_after','?')}")
            print(f"{indent}  Sig Alg : {info.get('sig_alg', 'N/A')}")
            print(f"{indent}  PubKey  : {info.get('pubkey_alg', 'N/A')}")

            if verbose >= 1 or role == "Root CA":
                pk_hash256, pk_hash384 = _pubkey_hashes(cert['data'])
                if pk_hash256:
                    print(f"{indent}  {BOLD}PubKey SHA256 (pkhash):{RESET} {c(GREEN, pk_hash256)}")
                if pk_hash384:
                    print(f"{indent}  {BOLD}PubKey SHA384 (pkhash):{RESET} {c(GREEN, pk_hash384)}")

            if verbose >= 2:
                print(f"{indent}  Raw DER ({cert['len']} bytes):")
                hexdump(cert['data'][:64], base_offset=cert['offset'])

    return unique

def _parse_cert_openssl(cert_data):
    """Use openssl to extract cert fields. Returns dict or None."""
    try:
        with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
            f.write(cert_data)
            tmp = f.name
        result = subprocess.run(
            ['openssl', 'x509', '-inform', 'DER', '-in', tmp, '-text', '-noout'],
            capture_output=True, text=True, timeout=5
        )
        os.unlink(tmp)
        if result.returncode != 0:
            return None
        info = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('Subject:'):
                info['subject'] = line[8:].strip()
            elif line.startswith('Issuer:'):
                info['issuer'] = line[7:].strip()
            elif line.startswith('Not Before:'):
                info['not_before'] = line[11:].strip()
            elif line.startswith('Not After'):
                info['not_after'] = line[11:].strip()
            elif 'Signature Algorithm:' in line and 'sig_alg' not in info:
                info['sig_alg'] = line.split(':', 1)[1].strip()
            elif 'Public Key Algorithm:' in line:
                info['pubkey_alg'] = line.split(':', 1)[1].strip()
        return info if info else None
    except Exception:
        return None

def _pubkey_hashes(cert_data):
    """Extract public key DER and compute SHA256/SHA384."""
    try:
        with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
            f.write(cert_data)
            tmp_cert = f.name

        pem_result = subprocess.run(
            ['openssl', 'x509', '-inform', 'DER', '-in', tmp_cert, '-pubkey', '-noout'],
            capture_output=True, text=True, timeout=5
        )
        os.unlink(tmp_cert)
        if pem_result.returncode != 0:
            return None, None

        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False, mode='w') as f:
            f.write(pem_result.stdout)
            tmp_pem = f.name

        der_result = subprocess.run(
            ['openssl', 'pkey', '-pubin', '-in', tmp_pem, '-outform', 'DER'],
            capture_output=True, timeout=5
        )
        os.unlink(tmp_pem)
        if der_result.returncode != 0:
            return None, None

        pk_der = der_result.stdout
        return hashlib.sha256(pk_der).hexdigest(), hashlib.sha384(pk_der).hexdigest()
    except Exception:
        return None, None

def _group_chains(certs):
    """Group certs into chains by issuer/subject relationships."""
    roots = [c for c in certs if c['info'].get('subject') == c['info'].get('issuer')]
    chains = []
    for root in roots:
        chain = [root]
        current = root
        for _ in range(10):
            children = [c for c in certs
                        if c['info'].get('issuer') == current['info'].get('subject')
                        and c is not current]
            if not children:
                break
            # pick closest offset child
            child = min(children, key=lambda x: abs(x['offset'] - current['offset']))
            chain.append(child)
            current = child
        # reverse so root is first
        chains.append(chain)
    return chains if chains else [certs]

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(data, elf_end, hash_segs, certs, verbose):
    header("SUMMARY")

    section("File")
    field("Total size", f"0x{len(data):x}  ({len(data):,} bytes)")
    field("ELF region", f"0x000000 ~ 0x{elf_end:06x}")
    field("Extra data", f"0x{elf_end:06x} ~ 0x{len(data):06x}  ({len(data)-elf_end:,} bytes)")

    # Check for FF padding at end
    tail = data[-0x200:]
    ff_count = tail.count(b'\xff')
    if ff_count > 0x100:
        field("Tail content", "Flash erase padding (0xFF)")

    section("Signing Info")
    if hash_segs:
        hs = hash_segs[0]
        field("Hash Table Segment", f"MBNv7 version {hs['version']}")
        field("Hash algorithm", hs['hash_alg'])
        field("Num entries", hs['n_entry'])
    else:
        field("Hash Table Segment", c(RED, "Not found"))

    section("Certificate Chains & pkhash")
    unique_roots = {}
    for cert in certs:
        info = cert['info']
        if info.get('subject') == info.get('issuer'):
            subj = info.get('subject', 'Unknown')
            pk256, pk384 = _pubkey_hashes(cert['data'])
            unique_roots[subj] = (pk256, pk384)

    if unique_roots:
        for i, (subj, (pk256, pk384)) in enumerate(unique_roots.items()):
            print(f"\n  Root CA #{i+1}: {c(BOLD, subj)}")
            if pk256:
                print(f"  {'pkhash SHA256':<28} {c(GREEN, pk256)}")
            if pk384:
                print(f"  {'pkhash SHA384':<28} {c(GREEN, pk384)}")
    else:
        print(c(RED, "  No root certificates found"))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='Qualcomm MELF/MBN firmware image inspector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python melf_inspect.py image.melf
  python melf_inspect.py image.melf -v      # show full cert chain details + pkhash
  python melf_inspect.py image.melf -vv     # show raw hex dumps
        """
    )
    parser.add_argument('file', help='Input .melf / .elf / .mbn file')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase verbosity (-v, -vv)')
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(c(RED, f"Error: File not found: {args.file}"))
        sys.exit(1)

    with open(args.file, 'rb') as f:
        data = f.read()

    header(f"Qualcomm Firmware Inspector  —  {os.path.basename(args.file)}")
    print(f"  {DIM}Author : Littlenine (github.com/LittlenineEnnea){RESET}")
    print(f"  File: {args.file}")
    print(f"  Size: {len(data):,} bytes  (0x{len(data):x})")
    print(f"  MD5:  {hashlib.md5(data).hexdigest()}")
    print(f"  SHA256: {hashlib.sha256(data).hexdigest()}")

    # ELF
    elf_end, segments = parse_elf(data, args.verbose)
    if elf_end is None:
        sys.exit(1)

    # MBNv7
    hash_segs = find_mbnv7(data, elf_end or 0x904, args.verbose)

    # Certs
    certs = find_certs(data, args.verbose)

    # Summary
    print_summary(data, elf_end or 0x904, hash_segs, certs, args.verbose)

    print()

if __name__ == '__main__':
    main()