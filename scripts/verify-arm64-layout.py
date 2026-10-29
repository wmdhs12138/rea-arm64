import collections
import json
import os
import re
import struct
import subprocess
import time
from pathlib import Path

import argparse
import datetime
import shutil

REPOSITORY = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description="Compare ARM64 ELF layout through the real REA CLI against GNU readelf/objdump. No fixture is executed.")
parser.add_argument("--entry", type=Path, default=REPOSITORY / "scripts/rea.mjs")
parser.add_argument("--output", type=Path)
args = parser.parse_args()
ENTRY = args.entry.resolve()
ROOT = (args.output or REPOSITORY / ".cache/arm64-verification" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")).resolve()
ROOT.mkdir(parents=True, exist_ok=False)
ENV = dict(os.environ)
assert Path(ENV.get("REA_PWNTOOLS_PYTHON", "")).is_absolute(), "Set REA_PWNTOOLS_PYTHON to a Python environment with pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2"
CC = ENV.get("REA_ARM64_CC", "gcc")
assert "aarch64" in subprocess.check_output([CC, "-dumpmachine"], text=True), "REA_ARM64_CC must target AArch64"
REA_NODE = shutil.which("node")
assert REA_NODE is not None, "Node.js is required"
SOURCE = REPOSITORY / "scripts/fixtures/arm64-layout.c"
BE_SOURCE = REPOSITORY / "scripts/fixtures/arm64-be-layout.c"
BE_START = REPOSITORY / "scripts/fixtures/arm64-be-start.c"

def build(name, source, *flags):
    subprocess.run([CC, *flags, str(source), "-o", str(ROOT / name)], check=True, timeout=60)

build("exec-unprotected", SOURCE, "-fno-stack-protector", "-fno-pie", "-no-pie", "-Wl,-z,norelro,-z,execstack")
protected = ["-fstack-protector-all", "-Wl,-z,noexecstack"]
full_relro = ["-Wl,-z,relro,-z,now"]
build("pie-full", SOURCE, *protected, *full_relro, "-fPIE", "-pie")
build("pie-partial", SOURCE, *protected, "-Wl,-z,relro,-z,lazy", "-fPIE", "-pie")
build("shared", SOURCE, *protected, *full_relro, "-fPIC", "-shared")
build("relocatable", SOURCE, "-fstack-protector-all", "-c")
shutil.copyfile(ROOT / "pie-full", ROOT / "pie-stripped")
subprocess.run([ENV.get("REA_ARM64_STRIP", "strip"), "--strip-all", str(ROOT / "pie-stripped")], check=True, timeout=30)
be = ["-mbig-endian", "-ffreestanding", "-fno-stack-protector"]
build("be-relocatable.o", BE_SOURCE, *be, "-fPIC", "-c")
build("be-shared.so", BE_SOURCE, *be, "-fPIC", "-shared", "-nostdlib", *full_relro)
build("be-exec", BE_SOURCE, *be, "-fno-pie", "-no-pie", "-nostdlib", str(BE_START))
build("be-pie", BE_SOURCE, *be, "-fPIE", "-pie", "-nostdlib", str(BE_START))
# A header-only x86-64 ELF is a regression input, never executed on the host.
ident = b'\x7fELF\x02\x01\x01' + bytes(9)
(ROOT / "x64-minimal.elf").write_bytes(struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 62, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0))
print("Verification records:", ROOT, flush=True)
results = []

def command(*args):
    return subprocess.check_output(list(args), text=True)

def inspect(name, path=None, expected_success=True):
    output = ROOT / (name + '.evidence.json')
    p = subprocess.run([REA_NODE, str(ENTRY), 'inspect-binary-layout',
                        str(path or ROOT / name), '--json'], env=ENV, capture_output=True, text=True, timeout=60)
    output.write_text(p.stdout)
    (ROOT / (name + '.stderr')).write_text(p.stderr)
    assert (p.returncode == 0) == expected_success, (name, p.returncode, p.stdout[-2000:], p.stderr[-1000:])
    return json.loads(p.stdout)

for name in ['exec-unprotected', 'pie-full', 'pie-partial', 'shared', 'relocatable', 'pie-stripped', 'be-shared.so', 'be-relocatable.o', 'be-exec', 'be-pie']:
    start = time.monotonic()
    evidence = inspect(name)
    value = evidence['normalized_result']
    assert evidence['subject']['architecture'] == 'arm64', name
    path = str(ROOT / name)
    header = command('readelf', '-Wh', path)
    sections = command('readelf', '-WS', path)
    segments = command('readelf', '-Wl', path)
    symbols = command('readelf', '-Ws', path)
    relocations = command('readelf', '-Wr', path)
    assert value['architecture'] == {'machine': 'EM_AARCH64', 'bits': 64, 'byte_order': 'big' if name.startswith('be-') else 'little'}
    assert len(value['sections']) == int(re.search(r'Number of section headers:\s+(\d+)', header)[1])
    assert len(value['segments']) == int(re.search(r'Number of program headers:\s+(\d+)', header)[1])
    assert int(value['entry_point']['reported_value'], 16) == int(re.search(r'Entry point address:\s+(0x[0-9a-f]+)', header)[1], 16)
    header_type = re.search(r'^\s*Type:\s+(\w+)', header, re.M)[1]
    assert value['image_type'] == 'ET_' + header_type
    for row in re.finditer(r'^\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+', sections, re.M):
        index, label, kind, address, offset, size = row.groups()
        if int(index) == 0:
            continue
        actual = value['sections'][int(index)]
        assert actual['name']['display'] == label
        assert int(actual['address'], 16) == int(address, 16)
        assert int(actual['offset'], 16) == int(offset, 16)
        assert int(actual['size'], 16) == int(size, 16)
    program_rows = re.findall(r'^\s*(\S+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+([RWE ]+)\s+(0x[0-9a-f]+)\s*$', segments, re.M)
    assert len(program_rows) == len(value['segments'])
    for actual, row in zip(value['segments'], program_rows):
        kind, offset, address, physical, file_size, memory_size, flags, alignment = row
        for field, number in [('offset', offset), ('virtual_address', address), ('physical_address', physical),
                              ('file_size', file_size), ('memory_size', memory_size), ('alignment', alignment)]:
            assert int(actual[field], 16) == int(number, 16)
        assert actual['permissions'] == {'read': 'R' in flags, 'write': 'W' in flags, 'execute': 'E' in flags}
    tables = {}
    table = None
    for line in symbols.splitlines():
        heading = re.search(r"Symbol table '([^']+)'", line)
        if heading:
            table = heading[1]
            continue
        row = re.match(r'^\s*(\d+):\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$', line)
        if row:
            tables[(table, int(row[1]))] = row.groups()[1:]
    assert len(tables) == len(value['symbols'])
    for actual in value['symbols']:
        table_name = value['sections'][actual['table_index']]['name']['display']
        raw = tables[(table_name, actual['entry_index'])]
        assert int(actual['value'], 16) == int(raw[0], 16)
        assert int(actual['size'], 16) == int(raw[1])
        if actual['name']['display'].startswith('rea_'):
            assert actual['name']['display'] == raw[6].split('@')[0].split()[0]
    expected_relocations = collections.defaultdict(list)
    jump_slots = {}
    table = None
    for line in relocations.splitlines():
        heading = re.search(r"Relocation section '([^']+)'", line)
        if heading:
            table = heading[1]
            continue
        row = re.match(r'^([0-9a-f]{8,16})\s+([0-9a-f]{8,16})\s+(R_AARCH64_\S+)\s+(.*)$', line)
        if row:
            offset, info, kind, tail = row.groups()
            numeric = int(info, 16)
            tokens = tail.split()
            addend = int(tokens[-1], 16) * (-1 if len(tokens) > 1 and tokens[-2] == '-' else 1)
            expected_relocations[table].append((int(offset, 16), numeric & 0xffffffff, numeric >> 32, addend))
            if kind == 'R_AARCH64_JUMP_SLOT':
                jump_slots[tokens[1].split('@')[0]] = int(offset, 16)
    actual_relocations = collections.defaultdict(list)
    for row in value['relocations']:
        table_name = value['sections'][row['section_index']]['name']['display']
        actual_relocations[table_name].append((int(row['reported_offset'], 16), row['type'], row['symbol_index'], int(row['addend'])))
        if value['image_type'] == 'ET_REL':
            assert row['target']['kind'] == 'section-offset'
        else:
            assert row['target']['kind'] == 'linked-virtual-address'
    assert dict(actual_relocations) == dict(expected_relocations), name
    got = {row['display_name']: int(row['address'], 16) for row in value['linkage']['got']}
    plt = {row['display_name']: int(row['address'], 16) for row in value['linkage']['plt']}
    for label, address in jump_slots.items():
        assert got.get(label) == address, (name, label, 'GOT mismatch')
    if jump_slots:
        assembly = command('objdump', '-d', '-j', '.plt', path)
        (ROOT / (name + '.plt.txt')).write_text(assembly)
        expected_plt = {label: int(address, 16) for address, label in re.findall(r'^([0-9a-f]+) <([^>]+)@plt>:', assembly, re.M)}
        for label in jump_slots:
            assert plt.get(label) == expected_plt[label], (name, label, 'PLT mismatch')
    if value['image_type'] != 'ET_REL' and not name.startswith('be-'):
        expected = {'evidence_kind': 'inferred', 'position_independent': name != 'exec-unprotected',
                    'nx_indicator': None if name == 'exec-unprotected' else True, 'executable_stack_indicator': name == 'exec-unprotected',
                    'stack_canary_indicator': name != 'exec-unprotected',
                    'relro': None if name == 'exec-unprotected' else 'Partial' if name == 'pie-partial' else 'Full'}
        assert value['mitigations'] == expected, (name, value['mitigations'])
    result = {'name': name, 'passed': True, 'seconds': round(time.monotonic() - start, 1),
              'sections': len(value['sections']), 'symbols': len(value['symbols']), 'relocations': len(value['relocations']),
              'plt_entries': len(plt), 'evidence_id': evidence['evidence_id']}
    results.append(result)
    print(json.dumps(result), flush=True)

valid = (ROOT / 'pie-full').read_bytes()
(ROOT / 'truncated.elf').write_bytes(valid[:30])
outside = bytearray(valid)
first_phdr = struct.unpack_from('<Q', outside, 32)[0]
struct.pack_into('<Q', outside, first_phdr + 32, len(outside) + 65536)
(ROOT / 'out-of-bounds.elf').write_bytes(outside)
ident = b'\x7fELF\x02\x01\x01' + bytes(9)
(ROOT / 'unsupported-machine.elf').write_bytes(struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 0xffff, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0))
for name, expected in [('truncated.elf', 'invalid_request'), ('out-of-bounds.elf', 'invalid_request'), ('unsupported-machine.elf', 'unsupported_target')]:
    error = inspect(name, expected_success=False)
    assert error['code'] == expected, (name, error)
    results.append({'name': name, 'passed': True, 'rejected_with': error['code']})
    print(json.dumps(results[-1]), flush=True)
old = inspect('x64-regression', ROOT / 'x64-minimal.elf')
assert old['normalized_result']['architecture']['machine'] == 'EM_X86_64'
results.append({'name': 'x64-regression', 'passed': True, 'evidence_id': old['evidence_id']})
print(json.dumps(results[-1]), flush=True)
(ROOT / 'verification-summary.json').write_text(json.dumps(results, indent=2) + '\n')
