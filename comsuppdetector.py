from pefile import PE

from itertools import chain
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
idata = None
rdata = None
for section in pe.sections:
    name = section.Name.rstrip(b"\0")
    if name == b".text":
        text = section
    if name == b".data":
        data = section
    if name == b".idata":
        idata = section
    if name == b".rdata":
        rdata = section
assert text is not None
assert data is not None

oleaut32 = None
imports = pe.DIRECTORY_ENTRY_IMPORT
try:
    imports = chain(imports, pe.DIRECTORY_ENTRY_DELAY_IMPORT)
except AttributeError:
    # PE has no delay import directory entry
    pass
for entry in imports:
    if entry.dll.lower() == b"oleaut32.dll":
        oleaut32 = entry
        break

if oleaut32 is None:
    print("No import for oleaut32.dll was found.")
    print("It is safe to assume that neither comsupp.lib, comsuppw.lib, comsuppd.lib, nor comsuppwd.lib were statically linked into '{}'.".format(target))
    exit()

VariantClear = None
for import_ in oleaut32.imports:
    if import_.name == b"VariantClear":
        VariantClear = import_
        break
assert VariantClear is not None
assert data.contains(VariantClear.address - ImageBase) \
    or (idata is not None and idata.contains(VariantClear.address - ImageBase)) \
    or (rdata is not None and rdata.contains(VariantClear.address - ImageBase))

code = pe.get_data(text.section_min_addr, text.section_max_addr - text.section_min_addr)

found_release_candidate = False
found_debug_candidate = False

# Match `dynamic_atexit_destructor_for_'vtMissing'' to identify release variants of comsupp.lib
#00007fff`23135340 488d0d919d0101  lea     rcx,[xul!vtMissing (00007fff`2414f0d8)]
#00007fff`23135347 48ff25e2dd0101  jmp     qword ptr [xul!_imp_VariantClear (00007fff`24153130)]
destructor_pattern = rb"\x48\x8D\x0D([\x00-\xFF]{4})\x48\xFF\x25([\x00-\xFF]{4})"
for match in finditer(destructor_pattern, code):
    candidate_start, _ = match.span()
    candidate_destructor = ImageBase + text.section_min_addr + candidate_start
    candidate_vtMissing = candidate_destructor + 7 + unpack("<i", match.group(1))[0]
    candidate_VariantClear = candidate_destructor + 14 + unpack("<i", match.group(2))[0]
    if candidate_VariantClear == VariantClear.address and data.contains(candidate_vtMissing - ImageBase):
        found_release_candidate = True
        print("Found a potential instance of `dynamic_atexit_destructor_for_'vtMissing'' at 0x{:x}, vtMissing would be at 0x{:x}.".format(candidate_destructor, candidate_vtMissing))

# Match _variant_t::~_variant_t to identify debug versions of comsupp.lib
# 48 89 4C 24 08    mov [rsp+pvarg], rcx
# 57                push    rdi
# 48 83 EC 20       sub     rsp, 20h
# 48 8B 4C 24 30    mov     rcx, [rsp+28h+pvarg] ; pvarg
# FF 15 23 63 01 00 call    cs:__imp_VariantClear
# 48 83 C4 20       add     rsp, 20h
# 5F                pop     rdi
# C3                ret
call_pattern = rb"\x48\x89\x4C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x4C\x24\x30\xFF\x15([\x00-\xFF]{4})\x48\x83\xC4\x20\x5F\xC3"
for match in finditer(call_pattern, code):
    candidate_start, _ = match.span()
    candidate_call = ImageBase + text.section_min_addr + candidate_start
    candidate_VariantClear = candidate_call + 21 + unpack("<i", match.group(1))[0]
    if candidate_VariantClear == VariantClear.address:
        found_debug_candidate = True
        print("Found a potential instance of _variant_t::~_variant_t at 0x{:x}.".format(candidate_call))

if found_release_candidate:
    print("It is likely that comsupp.lib or comsuppw.lib was statically linked into '{}'.".format(target))
if found_debug_candidate:
    print("It is likely that comsuppd.lib or comsuppwd.lib was statically linked into '{}'.".format(target))
if not (found_release_candidate or found_debug_candidate):
    print("It appears safe to assume that neither comsupp.lib, comsuppw.lib, comsuppd.lib, nor comsuppwd.lib were statically linked into '{}'.".format(target))
