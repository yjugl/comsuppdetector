from pefile import PE

from re import finditer
from struct import unpack
from sys import argv

target="obj-x86_64-pc-mingw32/dist/bin/xul.dll"
if len(argv) >= 2:
    target = argv[1]

pe = PE(target)

ImageBase = pe.OPTIONAL_HEADER.ImageBase

text = None
data = None
for section in pe.sections:
    name = section.Name.rstrip(b"\0")
    if name == b".text":
        text = section
    if name == b".data":
        data = section
assert text is not None
assert data is not None

oleaut32 = None
for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
    if entry.dll.lower() == b"oleaut32.dll":
        oleaut32 = entry
        break
assert oleaut32 is not None

VariantClear = None
for import_ in oleaut32.imports:
    if import_.name == b"VariantClear":
        VariantClear = import_
        break
assert VariantClear is not None
assert data.contains(VariantClear.address - ImageBase)

code = pe.get_data(text.section_min_addr, text.section_max_addr - text.section_min_addr)

#`dynamic_atexit_destructor_for_'vtMissing''
#00007fff`23135340 488d0d919d0101  lea     rcx,[xul!vtMissing (00007fff`2414f0d8)]
#00007fff`23135347 48ff25e2dd0101  jmp     qword ptr [xul!_imp_VariantClear (00007fff`24153130)]
destructor_pattern = rb"\x48\x8D\x0D([\x00-\xFF]{4})\x48\xFF\x25([\x00-\xFF]{4})"
found_candidate = False
for match in finditer(destructor_pattern, code):
    candidate_start, _ = match.span()
    candidate_destructor = ImageBase + text.section_min_addr + candidate_start
    candidate_vtMissing = candidate_destructor + 7 + unpack("<i", match.group(1))[0]
    candidate_VariantClear = candidate_destructor + 14 + unpack("<i", match.group(2))[0]
    if candidate_VariantClear == VariantClear.address:
        found_candidate = True
        print("Found a potential instance of `dynamic_atexit_destructor_for_'vtMissing'' at 0x{:x}, vtMissing would be at 0x{:x}.".format(candidate_destructor, candidate_vtMissing))

if found_candidate:
    print("It is likely that comsupp.lib was statically linked into {}.".format(repr(target)))
else:
    print("No potential `dynamic_atexit_destructor_for_'vtMissing'' was found.")
    print("It is safe to assume that comsupp.lib was not statically linked into {}.".format(repr(target)))
