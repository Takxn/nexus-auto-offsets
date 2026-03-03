#! idapython
# -*- coding: utf-8 -*-
"""
NEXUS+ AUTO-OFFSET GENERATOR v3.1 - Muss als Python in IDA ausgefuehrt werden.
"""
import re
import ctypes
import struct
import idautils
import idaapi
import idc
import ida_hexrays
import ida_funcs
import ida_kernwin
import ida_name
import os
import datetime

# ================================================================
# NEXUS+ AUTO-OFFSET GENERATOR v3.1 - FULLY AUTOMATIC
# IDA Pro 9.x compatible
# - Auto-scans static TypeInfo addresses via string XRefs
# - Auto-finds IL2CPP getter functions (ClassName$$get_Field)
# - Auto-parses crypto ops (ADD/SUB/XOR/ROL/ROR/SHL/SHR)
# - Auto-generates Decrypt + Encrypt C++ by reversing ops
# - Falls back to hardcoded values if extraction fails
# ================================================================

# ----------------------------------------------------------------
# CONFIG: encrypted fields to auto-extract
# (class_name, field_name, field_offset, is_float_return)
# ----------------------------------------------------------------
CRYPTO_FIELDS = [
    ('AdminConvar',        'AdminLight',            0x44,  True),
    ('AdminConvar',        'UnderwaterScatter',      0xB0,  True),
    ('AdminConvar',        'AdminTime',              0xB8,  False),
    ('PlayerWalkMovement', 'LastSprintTime',         0x70,  True),
    ('PlayerWalkMovement', 'SprintForced',           0x78,  True),
    ('PlayerWalkMovement', 'CapsuleHeightDucked',    0xC0,  True),
    ('PlayerWalkMovement', 'CapsuleCenterDucked',    0xC8,  True),
    ('PlayerWalkMovement', 'CapsuleHeightCrawling',  0xD0,  True),
    ('PlayerWalkMovement', 'MaxAngleWalking',        0xF8,  True),
    ('PlayerWalkMovement', 'MaxAngleClimbing',       0x100, True),
    ('PlayerWalkMovement', 'MaxAngleSliding',        0x108, True),
    ('PlayerWalkMovement', 'MaxStepHeight',          0x110, True),
]

# Hardcoded fallback values (used when auto-extraction fails)
FALLBACK_DECRYPTS = {
    ('AdminConvar', 'AdminLight'): [('OR_ZERO',0),('SHL',0x1F),('SUB',0x2D4D0EE2),('XOR',0x31A4D432),('XOR',0x31A4D432)],
    ('AdminConvar', 'UnderwaterScatter'): [('OR_ZERO',0),('SHL',0x1F),('SUB',0x2D4D0EE2),('XOR',0x31A4D432),('XOR',0x31A4D432)],
    ('AdminConvar', 'AdminTime'): [('ROL',0x1B),('ADD',0x2CD58D07),('ROL',0xA),('SUB',0x1123E2ED)],
    ('PlayerWalkMovement', 'LastSprintTime'): [('ADD',0x7FA7902F),('ROR',24),('XOR',0x11456947),('XOR',0x11456947)],
    ('PlayerWalkMovement', 'SprintForced'): [('ROR',18),('XOR',0xBE2377E1),('SUB',0x7A01AFDA),('SUB',0x7A01AFDA)],
    ('PlayerWalkMovement', 'CapsuleHeightDucked'): [('XOR',0xF3223462),('ADD',0x7F9B1843),('OR_ZERO',0),('SHL',0x4),('XOR',0x2C38D0D5),('XOR',0x2C38D0D5)],
    ('PlayerWalkMovement', 'CapsuleCenterDucked'): [('ADD',0xF5DD728),('XOR',0x5F94AE90),('SUB',0x226C149C),('SUB',0x226C149C)],
    ('PlayerWalkMovement', 'CapsuleHeightCrawling'): [('ROR',28),('XOR',0xA1303263),('SUB',0x53A9ECDA),('SUB',0x53A9ECDA)],
    ('PlayerWalkMovement', 'MaxAngleWalking'): [('XOR',0xABACC70E),('OR_ZERO',0),('SHL',0x1F),('XOR',0xB609322A),('SUB',0x1BE2E84D),('SUB',0x1BE2E84D)],
    ('PlayerWalkMovement', 'MaxAngleClimbing'): [('ROR',10),('SUB',0x31E163B9),('XOR',0xE9AC743A),('XOR',0xE9AC743A)],
    ('PlayerWalkMovement', 'MaxAngleSliding'): [('ADD',0x5BE5D74A),('OR_ZERO',0),('SHL',0x1F),('XOR',0xB73EEE6D),('XOR',0xB73EEE6D)],
    ('PlayerWalkMovement', 'MaxStepHeight'): [('XOR',0x5FB2A55C),('ADD',0x48C26AEE),('ROR',16),('SUB',0xE4AB51B5),('SUB',0xE4AB51B5)],
}

STATIC_DEFAULTS = {
    'PaintingFavouriteColorButtonTypeInfo': 0x0,
    'PlayerWalkMovement':     0x3974010,
    'AdminConvar':            0xD793A18,
    'ConvarGraphicsTypeInfo': 0xD793B80,
    'MainCamera':             0xD7E7AF0,
    'Input':                  0xD7EA518,
    'Il2cppHandle':           0xDAD33E0,
    'STypeInfo0':             0xD750200,
    'STypeInfo1':             0xD755460,
    'STypeInfo2':             0xD75B388,
    'STypeInfo3':             0xD7B6498,
    'STypeInfo4':             0xD7F41F0,
    'StringPool':             0xD775728,
    'BaseViewModel':          0xD755460,
    'GameManager':            0xD7CFB88,
}

# F:: namespace: IL2CPP function names to search for (priority order per entry)
F_FUNC_PATTERNS = {
    'BasePlayer_OnViewModeChanged': [
        'BasePlayer$$OnViewModeChanged',
        'BasePlayer_OnViewModeChanged',
        'BasePlayer$$OnViewModeChanged_0',
        'OnViewModeChanged',
    ],
    'GameObject_Internal_InstantiateSingle': [
        'Object$$Internal_InstantiateSingle',
        'UnityEngine.Object$$Internal_InstantiateSingle',
        'GameObject$$Internal_InstantiateSingle',
        'Internal_InstantiateSingle',
    ],
}

F_FUNC_DEFAULTS = {
    'BasePlayer_OnViewModeChanged':              0x16E37B0,
    'GameObject_Internal_InstantiateSingle':     0xB45F4D0,
}

# ----------------------------------------------------------------
# UTILITY
# ----------------------------------------------------------------

def is_decompiler_available():
    try:
        return ida_hexrays.init_hexrays_plugin() or hasattr(ida_hexrays, 'decompile')
    except Exception:
        return False

def count_xrefs(addr):
    return sum(1 for _ in idautils.XrefsTo(addr))

def decompile_func(addr):
    try:
        cfunc = ida_hexrays.decompile(addr)
    except Exception as e:
        print(f"    [!] decompile({hex(addr)}): {e}")
        return None
    return str(cfunc) if cfunc else None

def find_matching_brace(code, open_pos):
    depth = 0
    for i in range(open_pos, len(code)):
        if code[i] == '{':
            depth += 1
        elif code[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    return -1

def extract_do_while_block(code):
    for m in re.finditer(r'\bdo\b', code):
        ob = code.find('{', m.start())
        if ob == -1:
            continue
        cb = find_matching_brace(code, ob)
        if cb == -1:
            continue
        if code[cb + 1:cb + 30].strip().startswith('while'):
            return code[ob:cb + 1].strip()
    return ""

# ----------------------------------------------------------------
# STATIC ADDRESS AUTO-SCAN
# ----------------------------------------------------------------

def find_typeinfo_by_string(class_name):
    """Scan binary for exact class name string, follow XRef to TypeInfo in .data."""
    target = class_name.encode()
    candidates = []
    for s in idautils.Strings():
        s_bytes = s.str if isinstance(s.str, bytes) else s.str.encode()
        if s_bytes == target:
            for xref in idautils.XrefsTo(s.ea, 0):
                if xref.type in (1, 3):
                    seg = idc.get_segm_name(xref.frm)
                    if seg in ('.data', '.rdata', 'DATA'):
                        candidates.append(xref.frm)
    if not candidates:
        return None
    return max(set(candidates), key=count_xrefs)

def auto_scan_static_addresses():
    """Returns dict: key -> address (auto-detected where possible, default otherwise)."""
    results = dict(STATIC_DEFAULTS)
    scan_map = {
        'PlayerWalkMovement': 'PlayerWalkMovement',
        'AdminConvar':        'AdminConvar',
        'MainCamera':         'MainCamera',
        'Input':              'Input',
        'GameManager':        'GameManager',
        'StringPool':         'StringPool',
        'BaseViewModel':      'BaseViewModel',
    }
    for key, class_name in scan_map.items():
        addr = find_typeinfo_by_string(class_name)
        if addr:
            results[key] = addr
            print(f"  [+] Static.{key}: {hex(addr)}")
        else:
            print(f"  [-] Static.{key}: {hex(results[key])} (fallback)")

    # STypeInfo0-4: unknown classes — must be updated manually after each Rust update
    for i in range(5):
        print(f"  [!] Static.STypeInfo{i}: {hex(results[f'STypeInfo{i}'])} (manual update required)")

    return results

# ----------------------------------------------------------------
# F:: NAMESPACE AUTO-FINDER
# ----------------------------------------------------------------

def auto_find_f_functions():
    """
    Finds F:: function addresses via IL2CPP naming patterns.
    Falls back to last known defaults if not found.
    """
    results = {}
    for func_name, patterns in F_FUNC_PATTERNS.items():
        ea = idc.BADADDR

        # Try exact patterns first
        for pattern in patterns:
            ea = idc.get_name_ea_simple(pattern)
            if ea != idc.BADADDR:
                print(f"  [+] F::{func_name}: {hex(ea)}  ('{pattern}')")
                break

        # Broad search: strip underscores/$ and compare lowercase
        if ea == idc.BADADDR:
            target = func_name.replace('_', '').lower()
            for name_ea, name in idautils.Names():
                normalized = name.lower().replace('_', '').replace('$', '').replace('.', '')
                if target in normalized:
                    # Make sure it's actually a function
                    if ida_funcs.get_func(name_ea):
                        ea = name_ea
                        print(f"  [+] F::{func_name}: {hex(ea)}  (broad: '{name}')")
                        break

        if ea == idc.BADADDR:
            ea = F_FUNC_DEFAULTS.get(func_name, 0)
            print(f"  [-] F::{func_name}: {hex(ea)}  (fallback)")

        results[func_name] = ea

    return results

# ----------------------------------------------------------------
# IL2CPP GETTER FINDER
# ----------------------------------------------------------------

def find_getter_ea(class_name, field_name):
    """Try multiple IL2CPP naming patterns to find a getter function."""
    patterns = [
        f"{class_name}$$get_{field_name}",
        f"{class_name}_get_{field_name}",
        f"{class_name}$$get_{field_name.lower()}",
        f"{class_name}_get_{field_name.lower()}",
    ]
    for pattern in patterns:
        ea = idc.get_name_ea_simple(pattern)
        if ea != idc.BADADDR:
            print(f"    [+] Getter: {pattern} @ {hex(ea)}")
            return ea

    # Broad search through all named functions
    cl = class_name.lower()
    fl = f"get_{field_name}".lower()
    for name_ea, name in idautils.Names():
        nl = name.lower()
        if cl in nl and fl in nl:
            print(f"    [+] Getter (broad): {name} @ {hex(name_ea)}")
            return name_ea

    return idc.BADADDR

def find_decrypt_subcall(getter_code):
    """Find the decrypt sub-function (sub_XXXX) called inside a getter."""
    for line in getter_code.splitlines():
        m = re.search(r'=\s*(sub_[0-9a-fA-F]+)\s*\(', line)
        if m:
            ea = idc.get_name_ea_simple(m.group(1))
            if ea != idc.BADADDR:
                return ea
    return idc.BADADDR

# ----------------------------------------------------------------
# CRYPTO OPERATION PARSER
# ----------------------------------------------------------------

def _parse_num(s):
    s = s.strip()
    return int(s, 16) if s.startswith(('0x', '0X')) else int(s)

def parse_ops(code):
    """
    Parse crypto operations from Hex-Rays pseudocode.
    Returns list of (op, val) where op in: ADD SUB XOR ROL ROR SHL SHR OR_ZERO
    Variable-name agnostic — finds the working uint32 variable automatically.
    """
    ops = []
    lines = [l.strip().rstrip(';') for l in code.splitlines() if l.strip()]

    # Identify the main working variable (first uint32 cast assignment)
    work_var = None
    for line in lines:
        m = re.match(r'(\w+)\s*=\s*(?:static_cast\s*<\s*(?:unsigned\s+int|uint32_t)\s*>|(?:unsigned\s+int|uint32_t))\s*\(', line)
        if m:
            work_var = m.group(1)
            break
    if not work_var:
        return ops

    v = re.escape(work_var)
    N = r'(0x[0-9a-fA-F]+|\d+)'

    for line in lines:
        if f'{work_var} = static_cast' in line or f'{work_var} = (unsigned int)' in line:
            continue

        # ROL: v = (v << N) | (v >> M)
        m = re.match(rf'{v}\s*=\s*\({v}\s*<<\s*{N}\)\s*\|\s*\({v}\s*>>\s*{N}\)', line)
        if m:
            ops.append(('ROL', _parse_num(m.group(1))))
            continue

        # ROR: v = (v >> N) | (v << M)
        m = re.match(rf'{v}\s*=\s*\({v}\s*>>\s*{N}\)\s*\|\s*\({v}\s*<<\s*{N}\)', line)
        if m:
            ops.append(('ROR', _parse_num(m.group(1))))
            continue

        # ADD: v += X  or  v = v + X
        m = re.match(rf'{v}\s*\+=\s*{N}', line) or re.match(rf'{v}\s*=\s*{v}\s*\+\s*{N}', line)
        if m:
            ops.append(('ADD', _parse_num(m.group(1))))
            continue

        # SUB: v -= X  or  v = v - X
        m = re.match(rf'{v}\s*-=\s*{N}', line) or re.match(rf'{v}\s*=\s*{v}\s*-\s*{N}', line)
        if m:
            ops.append(('SUB', _parse_num(m.group(1))))
            continue

        # XOR: v ^= X
        m = re.match(rf'{v}\s*\^=\s*{N}', line)
        if m:
            ops.append(('XOR', _parse_num(m.group(1))))
            continue

        # SHL: v <<= N
        m = re.match(rf'{v}\s*<<=\s*{N}', line)
        if m:
            ops.append(('SHL', _parse_num(m.group(1))))
            continue

        # SHR: v >>= N
        m = re.match(rf'{v}\s*>>=\s*{N}', line)
        if m:
            ops.append(('SHR', _parse_num(m.group(1))))
            continue

        # OR with 0 / other var → treat as no-op marker
        m = re.match(rf'{v}\s*\|=\s*{N}', line)
        if m:
            val = _parse_num(m.group(1))
            if val == 0:
                ops.append(('OR_ZERO', 0))
            continue

    return ops

# ----------------------------------------------------------------
# C++ CODE GENERATOR
# ----------------------------------------------------------------

def _op_cpp(op, val, var):
    if op == 'ROL':
        return f"{var} = ({var} << 0x{val:X}) | ({var} >> 0x{(32 - val) & 0x1F:X});"
    if op == 'ROR':
        return f"{var} = ({var} >> 0x{val:X}) | ({var} << 0x{(32 - val) & 0x1F:X});"
    if op == 'ADD':
        return f"{var} = {var} + 0x{val:08X};"
    if op == 'SUB':
        return f"{var} = {var} - 0x{val:08X};"
    if op == 'XOR':
        return f"{var} ^= 0x{val:08X};"
    if op == 'SHL':
        return f"{var} <<= 0x{val:X};"
    if op == 'SHR':
        return f"{var} >>= 0x{val:X};"
    if op == 'OR_ZERO':
        return f"{var} |= Val2;"  # preserve original style
    return f"// unknown op: {op}"

def _reverse_op(op, val):
    return {
        'ROL': ('ROR', val), 'ROR': ('ROL', val),
        'ADD': ('SUB', val), 'SUB': ('ADD', val),
        'XOR': ('XOR', val),
        'SHL': ('SHR', val), 'SHR': ('SHL', val),
        'OR_ZERO': ('OR_ZERO', 0),
    }.get(op, (op, val))

def gen_decrypt(func_name, ops, is_float):
    """Generate C++ decrypt function (8-space indent = inside namespace)."""
    i2 = "        "   # 8 spaces
    i3 = "            " # 12 spaces
    lines = []

    needs_val2 = any(op == 'OR_ZERO' for op, _ in ops)

    if is_float:
        lines.append(f"{i2}float {func_name}(uint32_t Value)")
        lines.append(f"{i2}{{")
        if needs_val2:
            lines.append(f"{i3}uint32_t Val1 = 0, Val2 = 0;")
        else:
            lines.append(f"{i3}uint32_t Val1 = 0;")
        lines.append(f"{i3}Val1 = static_cast<uint32_t>(Value);")
        var = "Val1"
    else:
        lines.append(f"{i2}uint32_t {func_name}(uint64_t a1)")
        lines.append(f"{i2}{{")
        lines.append(f"{i3}uint32_t eax = static_cast< uint32_t >( a1 );")
        var = "eax"

    for op, val in ops:
        lines.append(f"{i3}{_op_cpp(op, val, var)}")

    if is_float:
        lines.append(f"{i3}float Result = 0.0f;")
        lines.append(f"{i3}std::memcpy(&Result, &{var}, sizeof(Result));")
        lines.append(f"{i3}return Result;")
    else:
        lines.append(f"{i3}return {var};")

    lines.append(f"{i2}}}")
    lines.append("")
    return "\n".join(lines)

def gen_encrypt(func_name, ops, is_float):
    """Generate C++ encrypt function by reversing ops (8-space indent)."""
    reversed_ops = [_reverse_op(op, val) for op, val in reversed(ops)]
    i2 = "        "
    i3 = "            "
    lines = []

    needs_val2 = any(op == 'OR_ZERO' for op, _ in ops)

    if is_float:
        lines.append(f"{i2}uint64_t {func_name}(float Value)")
        lines.append(f"{i2}{{")
        if needs_val2:
            lines.append(f"{i3}uint32_t Val1 = 0, Val2 = 0;")
        else:
            lines.append(f"{i3}uint32_t Val1 = 0;")
        lines.append(f"{i3}uint32_t InputBits = 0;")
        lines.append(f"{i3}std::memcpy(&InputBits, &Value, sizeof(InputBits));")
        lines.append(f"{i3}Val1 = InputBits;")
        var = "Val1"
    else:
        lines.append(f"{i2}uint64_t {func_name}(uint32_t a1)")
        lines.append(f"{i2}{{")
        lines.append(f"{i3}uint64_t v1;")
        lines.append(f"{i3}uint32_t eax = a1;")
        var = "eax"

    for op, val in reversed_ops:
        lines.append(f"{i3}{_op_cpp(op, val, var)}")

    if is_float:
        lines.append(f"{i3}return static_cast<uint64_t>({var});")
    else:
        lines.append(f"{i3}*( uint32_t* ) &v1 = {var};")
        lines.append(f"{i3}return v1;")

    lines.append(f"{i2}}}")
    lines.append("")
    return "\n".join(lines)

# ----------------------------------------------------------------
# CRYPTO FIELD EXTRACTION
# ----------------------------------------------------------------

def extract_all_crypto():
    """
    For each CRYPTO_FIELDS entry:
      1. Find IL2CPP getter function
      2. Decompile → find decrypt sub-call
      3. Parse ops
      4. Fall back to FALLBACK_DECRYPTS if extraction fails
    Returns dict: (class_name, field_name) -> list of (op, val)
    """
    results = {}
    for class_name, field_name, offset, is_float in CRYPTO_FIELDS:
        key = (class_name, field_name)
        print(f"  [~] {class_name}::{field_name} (0x{offset:X})")

        ops = None

        if is_decompiler_available():
            getter_ea = find_getter_ea(class_name, field_name)
            if getter_ea != idc.BADADDR:
                getter_code = decompile_func(getter_ea)
                if getter_code:
                    sub_ea = find_decrypt_subcall(getter_code)
                    if sub_ea != idc.BADADDR:
                        sub_code = decompile_func(sub_ea)
                        if sub_code:
                            ops = parse_ops(sub_code)
                    if not ops:
                        ops = parse_ops(getter_code)

        if ops:
            print(f"    [+] {len(ops)} ops auto-extracted")
            results[key] = ops
        else:
            fallback = FALLBACK_DECRYPTS.get(key)
            if fallback:
                print(f"    [-] Using hardcoded fallback ({len(fallback)} ops)")
                results[key] = fallback
            else:
                print(f"    [!] No fallback available")
                results[key] = []

    return results

# ----------------------------------------------------------------
# BASE NETWORKABLE
# ----------------------------------------------------------------

def auto_extract_base_networkable():
    result = {'chain': [], 'decrypt_blk': '', 'func_ea': idc.BADADDR, 'sub_name': '???'}

    candidates = []
    for s in idautils.Strings():
        sb = s.str if isinstance(s.str, bytes) else s.str.encode()
        if b"BaseNetworkable" in sb:
            for xref in idautils.XrefsTo(s.ea, 0):
                if xref.type in (1, 3) and idc.get_segm_name(xref.frm) in ('.data', '.rdata', 'DATA'):
                    candidates.append(xref.frm)

    if not candidates:
        print("  [!] BaseNetworkable_c not found!")
        return result

    base_addr = max(set(candidates), key=count_xrefs)
    print(f"  [+] BaseNetworkable_c: {hex(base_addr)} ({count_xrefs(base_addr)} xrefs)")
    idc.set_name(base_addr, "BaseNetworkable_c", ida_name.SN_CHECK)

    code_xrefs = []
    for xref in idautils.XrefsTo(base_addr):
        seg = idc.get_segm_name(xref.frm)
        if seg and seg not in ('.data', '.rdata', 'DATA', '.idata'):
            f = ida_funcs.get_func(xref.frm)
            if f:
                code_xrefs.append((xref.frm, f.start_ea, f.size()))

    if not code_xrefs:
        print("  [!] No code XRefs to BaseNetworkable_c!")
        return result

    code_xrefs.sort(key=lambda x: x[2])
    _, outer_ea, _ = code_xrefs[0]
    outer_code = decompile_func(outer_ea)
    if not outer_code:
        return result

    name_var = None
    for line in outer_code.splitlines():
        if 'BaseNetworkable_c' in line and '=' in line:
            name_var = line.split('=')[0].strip()
            break
    if not name_var:
        name_var = "BaseNetworkable_c"

    calling_line = None
    for line in outer_code.splitlines():
        if name_var in line and '+' in line and '(' in line and '=' in line:
            calling_line = line.strip()
            break
    if not calling_line:
        return result

    chain = [v[2:] for v in re.findall(r'\+\s*(0x[0-9a-fA-F]+)', calling_line)]
    result['chain'] = chain if chain else ['184', '48']

    sub_match = re.search(r'=\s*(sub_[0-9a-fA-F]+|[a-zA-Z_]\w+)\s*\(', calling_line)
    if not sub_match:
        return result

    sub_name = sub_match.group(1)
    func_ea = idc.get_name_ea_simple(sub_name)
    if func_ea == idc.BADADDR:
        return result

    result['sub_name'] = sub_name
    result['func_ea'] = func_ea

    inner_code = decompile_func(func_ea)
    if inner_code:
        result['decrypt_blk'] = extract_do_while_block(inner_code)

    print(f"  [+] Chain: {[hex(int(v, 16)) for v in result['chain']]}")
    return result

# ----------------------------------------------------------------
# BUILD NAMESPACE BLOCKS
# ----------------------------------------------------------------

def _ns_block(ns_name, funcs_code):
    """Wrap function code in a namespace block."""
    return f"    namespace {ns_name} {{\n{funcs_code}    }}"

def build_decryptions(crypto_data):
    """Build the entire Decryptions section."""
    blocks = {}
    internal_lines = []

    for class_name, field_name, offset, is_float in CRYPTO_FIELDS:
        key = (class_name, field_name)
        ops = crypto_data.get(key, [])

        if is_float:
            func_code = gen_decrypt(field_name, ops, True)
        else:
            # Non-float → InternalFormat namespace
            func_name = f"decrypt_0x{offset:X}"
            func_code = gen_decrypt(func_name, ops, False)
            internal_lines.append(func_code)
            continue

        if class_name not in blocks:
            blocks[class_name] = ""
        blocks[class_name] += func_code

    result = ""
    # AdminConvar
    result += _ns_block('AdminConvar', blocks.get('AdminConvar', '')) + "\n"
    # BaseNetworkable (empty)
    result += "    namespace BaseNetworkable {\n    }\n"
    # BasePlayer::ActiveItem (hardcoded loop pattern — complex 64-bit decrypt)
    result += """    namespace BasePlayer {
        uint64_t ActiveItem(uint64_t Address)
        {
            uint64_t Value = ReadValue<uint64_t>(Address + 0x4D0);
            uint32_t Lo = static_cast<uint32_t>(Value);
            uint32_t Hi = static_cast<uint32_t>(Value >> 32);
            for (int I = 0; I < 2; I++) {
                uint32_t& Current = (I == 0) ? Lo : Hi;
                Current += 688567079;
                Current = (Current << 22) | (Current >> 10);
                Current -= 1981755704;
            }
            return (static_cast<uint64_t>(Hi) << 32) | Lo;
        }

    }\n"""
    # InternalFormat (non-float, per offset)
    for line_block in internal_lines:
        result += f"    namespace InternalFormat {{\n{line_block}    }}\n"
    # PlayerWalkMovement
    result += _ns_block('PlayerWalkMovement', blocks.get('PlayerWalkMovement', '')) + "\n"

    return result

def build_encryptions(crypto_data):
    """Build the entire Encryptions section."""
    blocks = {}
    internal_lines = []

    for class_name, field_name, offset, is_float in CRYPTO_FIELDS:
        key = (class_name, field_name)
        ops = crypto_data.get(key, [])

        if is_float:
            func_code = gen_encrypt(field_name, ops, True)
        else:
            func_name = f"encrypt_0x{offset:X}"
            func_code = gen_encrypt(func_name, ops, False)
            internal_lines.append(func_code)
            continue

        if class_name not in blocks:
            blocks[class_name] = ""
        blocks[class_name] += func_code

    result = ""
    result += _ns_block('AdminConvar', blocks.get('AdminConvar', '')) + "\n"
    result += "    namespace BaseNetworkable {\n    }\n"
    result += "    namespace BasePlayer {\n    }\n"
    for line_block in internal_lines:
        result += f"    namespace InternalFormat {{\n{line_block}    }}\n"
    result += _ns_block('PlayerWalkMovement', blocks.get('PlayerWalkMovement', '')) + "\n"

    return result

# ----------------------------------------------------------------
# FINAL OFFSETS.H GENERATOR
# ----------------------------------------------------------------

def generate_offsets_h(S, bn_data, crypto_data, f_funcs=None):
    ts = datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
    chain = bn_data['chain']
    decrypt_blk = bn_data.get('decrypt_blk', '')
    func_ea = bn_data.get('func_ea', idc.BADADDR)
    sub_name = bn_data.get('sub_name', '???')

    chain_defs = "".join(
        f"        constexpr size_t DecryptChain{i+1} = 0x{v};\n"
        for i, v in enumerate(chain)
    )

    if decrypt_blk:
        blk = "\n".join("            " + l for l in decrypt_blk.splitlines())
        bn_func = (
            f"        // Auto-extracted: {sub_name} @ "
            f"{hex(func_ea) if func_ea != idc.BADADDR else '???'}\n"
            f"        static uint64_t DecryptEntityList(uint64_t a1)\n"
            f"        {{\n{blk}\n"
            f"            return *(uint64_t*)&v24;\n"
            f"        }}"
        )
    else:
        bn_func = "        // [!] DecryptEntityList: auto-extraction failed — update manually"

    if f_funcs is None:
        f_funcs = F_FUNC_DEFAULTS

    f_bp_onviewmode   = f_funcs.get('BasePlayer_OnViewModeChanged',
                                    F_FUNC_DEFAULTS['BasePlayer_OnViewModeChanged'])
    f_go_instantiate  = f_funcs.get('GameObject_Internal_InstantiateSingle',
                                    F_FUNC_DEFAULTS['GameObject_Internal_InstantiateSingle'])

    decryptions_body = build_decryptions(crypto_data)
    encryptions_body = build_encryptions(crypto_data)

    return f"""#pragma once
#include <cstdint>
#include "Memory.h"

// ==================================================
// NEXUS+ Offsets.h - AUTO GENERATED {ts}
// IDA Pro 9.x - NEXUS+ AUTO-OFFSET GENERATOR v3.1
// ==================================================

namespace Offsets {{
    // ============================ Static =============================
    namespace Static {{
        constexpr size_t PaintingFavouriteColorButtonTypeInfo = 0x{S['PaintingFavouriteColorButtonTypeInfo']:X};
        constexpr size_t PlayerWalkMovement = 0x{S['PlayerWalkMovement']:X};
        constexpr size_t AdminConvar = 0x{S['AdminConvar']:X};
        constexpr size_t ConvarGraphicsTypeInfo = 0x{S['ConvarGraphicsTypeInfo']:X};
        constexpr size_t MainCamera = 0x{S['MainCamera']:X};
        constexpr size_t Input = 0x{S['Input']:X};
        constexpr size_t Il2cppHandle = 0x{S['Il2cppHandle']:X};

        // TODO: STypeInfo0-4 — unknown classes, verify manually after each update
        constexpr size_t STypeInfo0 = 0x{S['STypeInfo0']:X};
        constexpr size_t STypeInfo1 = 0x{S['STypeInfo1']:X};
        constexpr size_t STypeInfo2 = 0x{S['STypeInfo2']:X};
        constexpr size_t STypeInfo3 = 0x{S['STypeInfo3']:X};
        constexpr size_t STypeInfo4 = 0x{S['STypeInfo4']:X};
        constexpr size_t StringPool = 0x{S['StringPool']:X};
        constexpr size_t BaseViewModel = 0x{S['BaseViewModel']:X};
        constexpr size_t GameManager = 0x{S['GameManager']:X};
    }}

    // ========================= AdminConvar ===========================
    namespace AdminConvar {{
        constexpr size_t AdminAmbientMultiplier = 0x14;
        constexpr size_t UnderwaterEffect = 0x18;
        constexpr size_t AllowAdminUI = 0x34;
        constexpr size_t AdminLight = 0x44;
        constexpr size_t DdrawNetupdate = 0x98;
        constexpr size_t UnderwaterCinematic = 0x99;
        constexpr size_t UnderwaterScatter = 0xB0;
        constexpr size_t AdminTime = 0xB8;
        constexpr size_t OverrideOceanEnvironmentLerp = 0xBC;
        constexpr size_t WoundedFreecam = 0xC9;
        constexpr size_t AdminReflection = 0x160;
    }}

    // ======================= AnimationEvents =========================
    namespace AnimationEvents {{
        constexpr size_t targetEntity = 0x28;
    }}

    // ======================= BaseCombatEntity ========================
    namespace BaseCombatEntity {{
        constexpr size_t StartHealth = 0x1F0;
        constexpr size_t LifeState = 0x258;
    }}

    // ========================== BaseEntity ===========================
    namespace BaseEntity {{
        constexpr size_t Model = 0xE8;
    }}

    // ========================== BaseMelee ============================
    namespace BaseMelee {{
        constexpr size_t DamageProperties = 0x300;
        constexpr size_t DamageTypes = 0x308;
        constexpr size_t DeployableDamageOverrides = 0x310;
        constexpr size_t MaxDistance = 0x318;
        constexpr size_t AttackRadius = 0x31C;
        constexpr size_t IsAutomatic = 0x320;
        constexpr size_t BlockSprintOnAttack = 0x321;
        constexpr size_t CanUntieCrates = 0x322;
        constexpr size_t LongResourceForgiveness = 0x323;
        constexpr size_t StrikeFX = 0x328;
        constexpr size_t UseStandardHitEffects = 0x330;
        constexpr size_t AiStrikeDelay = 0x334;
        constexpr size_t SwingEffect = 0x338;
        constexpr size_t MaterialStrikeFX = 0x340;
        constexpr size_t HeartStress = 0x348;
        constexpr size_t Gathering = 0x350;
        constexpr size_t ThrowReady = 0x358;
        constexpr size_t CanThrowAsProjectile = 0x359;
        constexpr size_t CanThrowAsEntity = 0x35A;
        constexpr size_t CanAiHearIt = 0x35B;
        constexpr size_t CanScareAiWhenAimed = 0x35C;
        constexpr size_t OnlyThrowAsProjectile = 0x35D;
        constexpr size_t ThrowFullStack = 0x35E;
    }}

    // ======================= BaseNetworkable =========================
    namespace BaseNetworkable {{
        constexpr size_t Children = 0x28;
        constexpr size_t PrefabID = 0x30;

        // ================ AUTO UPDATED BY SCRIPT ================
{chain_defs}
{bn_func}
    }}

    // ========================== BasePlayer ===========================
    namespace BasePlayer {{
        constexpr size_t PlayerEyes = 0x2B0;
        constexpr size_t PlayerInput = 0x338;
        constexpr size_t DisplayName = 0x3E8;
        constexpr size_t CurrentTeam = 0x4A0;
        constexpr size_t ActiveItem = 0x4D0;
        constexpr size_t Movement = 0x4E0;
        constexpr size_t PlayerInventory = 0x4E8;
        constexpr size_t PlayerModel = 0x4F8;
        constexpr size_t ActiveItemDecryption = 0xDD4C0;
    }}

    // ======================== BaseProjectile =========================
    namespace BaseProjectile {{
        constexpr size_t ProjectileVelocityScale = 0x30C;
        constexpr size_t Automatic = 0x310;
        constexpr size_t MuzzlePoint = 0x348;
        constexpr size_t PrimaryMagazine = 0x358;
        constexpr size_t Recoil = 0x380;
        constexpr size_t IsBurstWeapon = 0x3B7;

        namespace Magazine {{
            constexpr size_t Definition = 0x10;
            constexpr size_t Capacity = 0x18;
            constexpr size_t Contents = 0x1C;
            constexpr size_t AmmoType = 0x20;
            constexpr size_t AllowPlayerReloading = 0x28;
            constexpr size_t AllowAmmoSwitching = 0x29;

            namespace Definition {{
                constexpr size_t BuiltInSize = 0x0;
                constexpr size_t AmmoTypes = 0x4;
            }}
        }}
    }}

    // ======================== BaseViewModel ==========================
    namespace BaseViewModel {{
        constexpr size_t baseSkinPieces = 0x68;
        constexpr size_t ViewmodelSway = 0x80;
        constexpr size_t ViewmodelCameraAnimation = 0x88;
        constexpr size_t ViewmodelPunch = 0x90;
        constexpr size_t IronSights = 0x98;
        constexpr size_t Animator = 0xA0;
        constexpr size_t ViewmodelAspectOffset = 0xC0;
        constexpr size_t AnimationEvents = 0xC8;
        constexpr size_t ViewmodelBob = 0xE0;
        constexpr size_t ViewmodelLower = 0xE8;
        constexpr size_t ListStart = 0x118;
    }}

    // ========================== BowWeapon ============================
    namespace BowWeapon {{
        constexpr size_t AttackReady = 0x438;
        constexpr size_t ArrowBack = 0x43C;
        constexpr size_t SwapArrows = 0x440;
        constexpr size_t WasAiming = 0x448;
    }}

    // ====================== CompoundBowWeapon ========================
    namespace CompoundBowWeapon {{
        constexpr size_t StringHoldDurationMax = 0x450;
        constexpr size_t StringBonusDamage = 0x454;
        constexpr size_t StringBonusDistance = 0x458;
        constexpr size_t StringBonusVelocity = 0x45C;
        constexpr size_t MovementPenaltyRampUpTime = 0x460;
        constexpr size_t ConditionLossPerSecondHeld = 0x464;
        constexpr size_t ConditionLossHeldDelay = 0x468;
        constexpr size_t ChargeUpSoundDef = 0x470;
        constexpr size_t StringHeldSoundDef = 0x478;
        constexpr size_t DrawFinishSoundDef = 0x480;
        constexpr size_t private_Sound_0 = 0x488;
        constexpr size_t private_Sound_1 = 0x490;
        constexpr size_t MovementPenalty = 0x498;
        constexpr size_t private_float_0 = 0x49C;
        constexpr size_t private_float_1 = 0x4A0;
        constexpr size_t internal_float_2 = 0x4A4;
        constexpr size_t private_bool_0 = 0x4A8;
    }}

    // ========================= Construction ==========================
    namespace Construction {{
        constexpr size_t holdToPlaceDuration = 0x100;
    }}

    // ======================== ConvarGraphics =========================
    namespace ConvarGraphics {{
        constexpr size_t FOV = 0x130;
    }}

    // ====================== FlintStrikeWeapon ========================
    namespace FlintStrikeWeapon {{
        constexpr size_t SuccessFraction = 0x438;
        constexpr size_t SuccessIncrease = 0x43C;
        constexpr size_t StrikeRecoil = 0x440;
        constexpr size_t DidSparkThisFrame = 0x448;
        constexpr size_t IsStriking = 0x449;
        constexpr size_t Strikes = 0x44C;
        constexpr size_t LastSpectatorAttack = 0x450;
    }}

    // ========================= GameManager ===========================
    namespace GameManager {{
        constexpr size_t ClientInstance = 0x20;
        constexpr size_t PrefabPoolCollection = 0x20;

        namespace PrefabPool {{
            constexpr size_t Stack = 0x18;

            namespace PoolManager {{
                constexpr size_t Storage = 0x10;
            }}
        }}
    }}

    // ============================ Input ==============================
    namespace Input {{
        constexpr size_t ButtonList = 0x128;
    }}

    // ========================= InputButtons ==========================
    namespace InputButtons {{
        constexpr size_t CurrentValue = 0x10;
        constexpr size_t CycleIndex = 0x14;
        constexpr size_t Code = 0x18;
        constexpr size_t Binds = 0x20;
        constexpr size_t LastValue = 0x28;
        constexpr size_t Transient = 0x29;
        constexpr size_t TestFunction = 0x30;
        constexpr size_t Name = 0x38;
        constexpr size_t Cycle = 0x40;
    }}

    // ============================= Item ==============================
    namespace Item {{
        constexpr size_t Contents = 0x18;
        constexpr size_t Info = 0x30;
        constexpr size_t MaxCondition = 0x38;
        constexpr size_t Uid = 0x70;
        constexpr size_t Position = 0xA0;
        constexpr size_t HeldEntity = 0xB0;
        constexpr size_t Amount = 0xC8;
        constexpr size_t Condition = 0xE0;
    }}

    // ======================== ItemContainer ==========================
    namespace ItemContainer {{
        constexpr size_t uid = 0x20;
        constexpr size_t Capacity = 0x38;
        constexpr size_t Flags = 0x3C;
        constexpr size_t PlayerOwner = 0x40;
        constexpr size_t EntityOwner = 0x50;
        constexpr size_t ItemList = 0x68;
    }}

    // ======================== ItemDefinition =========================
    namespace ItemDefinition {{
        constexpr size_t ItemId = 0x20;
        constexpr size_t ShortName = 0x28;
        constexpr size_t DisplayName = 0x40;
        constexpr size_t DisplayDescription = 0x48;
        constexpr size_t Category = 0x58;
        constexpr size_t Stackable = 0x78;
        constexpr size_t Rarity = 0x90;
        constexpr size_t Condition = 0xB8;
        constexpr size_t Parent = 0x100;
        constexpr size_t Traits = 0x150;
        constexpr size_t Children = 0x158;
        constexpr size_t Blueprint = 0x178;
    }}

    // ====================== ItemModProjectile ========================
    namespace ItemModProjectile {{
        constexpr size_t ProjectileObject = 0x20;
        constexpr size_t Mods = 0x28;
        constexpr size_t AmmoType = 0x30;
        constexpr size_t NumProjectiles = 0x38;
        constexpr size_t ProjectileSpread = 0x3C;
        constexpr size_t ProjectileVelocity = 0x40;
        constexpr size_t ProjectileVelocitySpread = 0x44;
        constexpr size_t UseCurve = 0x48;
        constexpr size_t SpreadScalar = 0x50;
        constexpr size_t AttackEffectOverride = 0x58;
        constexpr size_t BarrelConditionLoss = 0x60;
        constexpr size_t Category = 0x68;
    }}

    // ======================== LootableCorpse =========================
    namespace LootableCorpse {{
        constexpr size_t PlayerName = 0x2C8;
        constexpr size_t LootPanelName = 0x2D0;
        constexpr size_t PlayerSteamID = 0x2D8;
    }}

    // ========================== MainCamera ===========================
    namespace MainCamera {{
        constexpr size_t Camera = 0x60;
        constexpr size_t Matrix = 0x30C;
        constexpr size_t Position = 0x454;
    }}

    // ===================== MeshPaintController =======================
    namespace MeshPaintController {{
        constexpr size_t CurrentCanvas = 0xD0;
        constexpr size_t LastCanvas = 0xD8;
    }}

    // ============================ Model ==============================
    namespace Model {{
        constexpr size_t BoneTransforms = 0x50;
    }}

    // ========================== ModelState ===========================
    namespace ModelState {{
        constexpr size_t Flags = 0x2C;
        constexpr size_t BasePlayerModelState = 0x350;
    }}

    // ======================== Network_Client =========================
    namespace Network_Client {{
        constexpr size_t ConnectedAddress = 0x10;
        constexpr size_t ServerName = 0x18;
        constexpr size_t ConnectedPort = 0x58;
    }}

    // ========================= Network_Net ===========================
    namespace Network_Net {{
        constexpr size_t cl = 0x18;
    }}

    // ================= PaintingFavouriteColorButton ==================
    namespace PaintingFavouriteColorButton {{
        constexpr size_t meshPaintController = 0x20;
    }}

    // ========================= PlayerInput ===========================
    namespace PlayerInput {{
        constexpr size_t State = 0x28;
        constexpr size_t BodyAngles = 0x44;
        constexpr size_t RecoilAngles = 0x80;
    }}

    // ======================= PlayerInventory =========================
    namespace PlayerInventory {{
        constexpr size_t ReturnItems = 0x28;
        constexpr size_t ContainerSlot1 = 0x30;
        constexpr size_t ReturnItems2 = 0x38;
        constexpr size_t Crafting = 0x40;
        constexpr size_t Loot = 0x48;
        constexpr size_t ContainerSlot2 = 0x58;
        constexpr size_t ContainerSlot3 = 0x60;
    }}

    // ========================= PlayerModel ===========================
    namespace PlayerModel {{
        constexpr size_t SkinnedMultiMesh = 0x1F0;
        constexpr size_t Position = 0x1F8;
        constexpr size_t Velocity = 0x21C;
    }}

    // ====================== PlayerWalkMovement =======================
    namespace PlayerWalkMovement {{
        constexpr size_t CapsuleHeight = 0x2;
        constexpr size_t GroundAngle = 0x8;
        constexpr size_t GravityTestRadius = 0x10;
        constexpr size_t GroundNormalNew = 0x18;
        constexpr size_t GroundVelocity = 0x20;
        constexpr size_t MaxVelocity = 0x30;
        constexpr size_t CapsuleCenterCrawling = 0x38;
        constexpr size_t GroundTime = 0x40;
        constexpr size_t JumpTime = 0x48;
        constexpr size_t PreviousPosition = 0x50;
        constexpr size_t PreviousVelocity = 0x58;
        constexpr size_t GroundNormal = 0x60;
        constexpr size_t GroundVelocityNew = 0x68;
        constexpr size_t LastSprintTime = 0x70;
        constexpr size_t SprintForced = 0x78;
        constexpr size_t Grounded = 0x80;
        constexpr size_t Climbing = 0x88;
        constexpr size_t Swimming = 0x90;
        constexpr size_t WasSwimming = 0x98;
        constexpr size_t CapsuleCenter = 0xB8;
        constexpr size_t CapsuleHeightDucked = 0xC0;
        constexpr size_t CapsuleCenterDucked = 0xC8;
        constexpr size_t CapsuleHeightCrawling = 0xD0;
        constexpr size_t GravityMultiplierSwimming = 0xD8;
        constexpr size_t GravityMultiplier = 0xF0;
        constexpr size_t MaxAngleWalking = 0xF8;
        constexpr size_t MaxAngleClimbing = 0x100;
        constexpr size_t MaxAngleSliding = 0x108;
        constexpr size_t MaxStepHeight = 0x110;
        constexpr size_t Body = 0x118;
        constexpr size_t Capsule = 0x120;
        constexpr size_t GroundAngleNew = 0x128;
        constexpr size_t LandTime = 0x138;
        constexpr size_t PreviousInheritedVelocity = 0x148;
        constexpr size_t NextSprintTime = 0x158;
        constexpr size_t AttemptedMountTime = 0x168;
        constexpr size_t Sliding = 0x178;
        constexpr size_t Jumping = 0x188;
        constexpr size_t WasJumping = 0x198;
        constexpr size_t Falling = 0x1A0;
        constexpr size_t WasFalling = 0x1A8;
        constexpr size_t Flying = 0x1B0;
        constexpr size_t WasFlying = 0x1BC;
        constexpr size_t ForcedDuckDelta = 0x1C4;
        constexpr size_t AdminSpeed = 0x1CC;
    }}

    // ========================== Projectile ===========================
    namespace Projectile {{
        constexpr size_t InitialVelocity = 0x28;
        constexpr size_t Drag = 0x34;
        constexpr size_t GravityModifier = 0x38;
        constexpr size_t Thickness = 0x3C;
        constexpr size_t ChangeInitialOrientation = 0x40;
        constexpr size_t InitialDistance = 0x44;
        constexpr size_t InitialOrientation = 0x48;
        constexpr size_t PenetrationPower = 0x68;
    }}

    // ======================= RecoilProperties ========================
    namespace RecoilProperties {{
        constexpr size_t RecoilYawMin = 0x18;
        constexpr size_t RecoilYawMax = 0x1C;
        constexpr size_t RecoilPitchMin = 0x20;
        constexpr size_t RecoilPitchMax = 0x24;
        constexpr size_t MovementPenalty = 0x34;
    }}

    // ======================= SkinnedMultiMesh ========================
    namespace SkinnedMultiMesh {{
        constexpr size_t RendererList = 0x50;
    }}

    // ========================== StringPool ===========================
    namespace StringPool {{
        constexpr size_t ToString = 0x50;
        constexpr size_t ToNumber = 0x58;
    }}

    // =========================== TOD_Sky =============================
    namespace TOD_Sky {{
        constexpr size_t Cycle = 0x40;
        constexpr size_t Atmosphere = 0x50;
        constexpr size_t Day = 0x58;
        constexpr size_t Night = 0x60;
        constexpr size_t Sun = 0x68;
        constexpr size_t Moon = 0x70;
        constexpr size_t Stars = 0x78;
        constexpr size_t Clouds = 0x80;
        constexpr size_t Light = 0x88;
        constexpr size_t Fog = 0x90;
        constexpr size_t Ambient = 0x98;
        constexpr size_t Reflection = 0xA0;
        constexpr size_t Initialized = 0xA8;
        constexpr size_t TimeSinceReflectionUpdate = 0xC4;
        constexpr size_t TimeSinceAmbientUpdate = 0xE0;
        constexpr size_t Components = 0x230;
    }}

    // ========================== WorldItem ============================
    namespace WorldItem {{
        constexpr size_t Item = 0x1C8;
    }}

    // ============================== F ================================
    namespace F {{
        constexpr size_t BasePlayer_OnViewModeChanged = 0x{f_bp_onviewmode:X};
        constexpr size_t GameObject_Internal_InstantiateSingle = 0x{f_go_instantiate:X};
    }}

}} // namespace Offsets

// =========================== Decryptions =============================
namespace Decryptions {{
    template <typename T>
    static inline T ReadValue(uint64_t Address)
    {{
        T Value{{}};
        Mem.Read(Address, &Value, sizeof(T));
        return Value;
    }}

    static inline uint64_t Il2cppGetHandle(int32_t ObjectHandleId)
    {{
        const uint64_t Index = static_cast<uint64_t>(ObjectHandleId >> 3);
        const uint64_t Table = static_cast<uint64_t>((ObjectHandleId & 7) - 1);
        const uint64_t HandleBase = Mem.BaseAddress + Offsets::Static::Il2cppHandle;
        const uint64_t TableBase = HandleBase + (Table * 0x28);
        const uint64_t ObjectArrayBase = ReadValue<uint64_t>(TableBase + 0x8) + (Index << 3);
        const uint8_t Mode = ReadValue<uint8_t>(TableBase + 0x14);
        if (Mode > 1) {{
            return ReadValue<uint64_t>(ObjectArrayBase);
        }}
        uint32_t Eax = ReadValue<uint32_t>(ObjectArrayBase);
        Eax = ~Eax;
        return static_cast<uint64_t>(Eax);
    }}

{decryptions_body}
}} // namespace Decryptions

// =========================== Encryptions =============================
namespace Encryptions {{
{encryptions_body}
}} // namespace Encryptions

#endif // OFFSETS_H
"""

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------

def main():
    print("=" * 60)
    print("  NEXUS+ AUTO-OFFSET GENERATOR v3.1  |  IDA Pro 9.x")
    print("=" * 60)

    # Phase 1: Static TypeInfo addresses + STypeInfo0-4 cluster scan
    print("\n[1/5] Scanning static TypeInfo addresses + STypeInfo cluster...")
    static_addrs = auto_scan_static_addresses()

    # Phase 2: F:: namespace function addresses
    print("\n[2/5] Finding F:: function addresses...")
    f_funcs = auto_find_f_functions()

    # Phase 3: BaseNetworkable decrypt chain
    print("\n[3/5] Extracting BaseNetworkable decrypt chain...")
    if is_decompiler_available():
        bn_data = auto_extract_base_networkable()
    else:
        print("  [!] Decompiler not available — using defaults")
        bn_data = {'chain': ['184', '48'], 'decrypt_blk': '', 'func_ea': idc.BADADDR, 'sub_name': '???'}

    if not bn_data['chain']:
        bn_data['chain'] = ['184', '48']

    # Phase 4: Decrypt/Encrypt crypto functions
    print("\n[4/5] Extracting decrypt/encrypt functions...")
    crypto_data = extract_all_crypto()

    # Phase 5: Generate Offsets.h
    print("\n[5/5] Generating Offsets.h...")
    content = generate_offsets_h(static_addrs, bn_data, crypto_data, f_funcs)

    output_path = os.path.join(os.path.expanduser("~/Desktop"), "Offsets.h")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)

    # Summary
    auto_count = sum(
        1 for k, v in crypto_data.items()
        if v and v != FALLBACK_DECRYPTS.get(k)
    )
    total = len(CRYPTO_FIELDS)

    f_auto = sum(1 for v in f_funcs.values() if v != F_FUNC_DEFAULTS.get(
        next((k for k, dv in F_FUNC_DEFAULTS.items() if dv == v), None)
    ))

    print(f"\n{'='*60}")
    print(f"  DONE — Offsets.h saved to Desktop")
    print(f"  Chain:        {' -> '.join('0x'+v for v in bn_data['chain'])}")
    print(f"  Crypto:       {auto_count}/{total} auto  |  {total-auto_count}/{total} fallback")
    print(f"  F:: funcs:    {f_auto}/{len(f_funcs)} auto-found")
    print(f"  STypeInfo0-4: last known values used — UPDATE MANUALLY")
    print(f"{'='*60}")

    open_tester = ida_kernwin.ask_yn(
        1,
        "NEXUS+ v3.1 — Offsets.h fertig!\n\n"
        f"Chain:     {' -> '.join('0x'+v for v in bn_data['chain'])}\n"
        f"Crypto:    {auto_count}/{total} auto  |  {total-auto_count}/{total} fallback\n"
        f"F:: funcs: {f_auto}/{len(f_funcs)} auto-found\n\n"
        f"[!] STypeInfo0-4: prüfe manuell nach dem Update!\n\n"
        "Offset Tester jetzt öffnen?"
    )
    if open_tester == 1:
        launch_tester(output_path)

# ================================================================
# NULLKD TREIBER (für Offset Tester)
# ================================================================

class NullKD:
    """Kommunikation via NtQueryCompositionSurfaceStatistics Hook."""

    _CMD_PING        = 99
    _CMD_READ        = 1
    _CMD_WRITE       = 2
    _CMD_MODULE_BASE = 3
    _MAGIC           = 0x44524B4E  # "DRKN"

    class _REQ(ctypes.Structure):
        _fields_ = [
            ("magic",       ctypes.c_uint),
            ("command",     ctypes.c_uint),
            ("pid",         ctypes.c_uint64),
            ("address",     ctypes.c_uint64),
            ("buffer",      ctypes.c_uint64),
            ("size",        ctypes.c_uint64),
            ("result",      ctypes.c_uint64),
            ("protect",     ctypes.c_uint),
            ("module_name", ctypes.c_wchar * 64),
        ]

    def __init__(self):
        self.available = False
        try:
            import ctypes
            win32u   = ctypes.WinDLL("win32u.dll")
            self._fn = win32u.NtQueryCompositionSurfaceStatistics
            self._fn.restype  = ctypes.c_long
            self._fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
            self.available = True
        except Exception as e:
            print(f"[NullKD] Nicht verfügbar: {e}")

    def _send(self, req):
        if not self.available:
            return False
        return self._fn(ctypes.addressof(req), None, 0) == 0

    def ping(self):
        r = self._REQ(); r.magic = self._MAGIC; r.command = self._CMD_PING
        return self._send(r)

    def get_module_base(self, pid, module):
        r = self._REQ(); r.magic = self._MAGIC; r.command = self._CMD_MODULE_BASE
        r.pid = pid; r.module_name = module
        return r.result if self._send(r) else 0

    def read(self, pid, addr, size):
        buf = (ctypes.c_uint8 * size)()
        r = self._REQ(); r.magic = self._MAGIC; r.command = self._CMD_READ
        r.pid = pid; r.address = addr; r.buffer = ctypes.addressof(buf); r.size = size
        return bytes(buf) if self._send(r) else None

    def read_u32(self, pid, addr):
        d = self.read(pid, addr, 4)
        return struct.unpack_from("<I", d)[0] if d else None

    def read_u64(self, pid, addr):
        d = self.read(pid, addr, 8)
        return struct.unpack_from("<Q", d)[0] if d else None

    def read_float(self, pid, addr):
        d = self.read(pid, addr, 4)
        return struct.unpack_from("<f", d)[0] if d else None

    def write_u32(self, pid, addr, value):
        import struct as _s
        buf = (ctypes.c_uint8 * 4)(*_s.pack("<I", value & 0xFFFFFFFF))
        r = self._REQ(); r.magic = self._MAGIC; r.command = self._CMD_WRITE
        r.pid = pid; r.address = addr; r.buffer = ctypes.addressof(buf); r.size = 4
        return self._send(r)

    def write_float(self, pid, addr, value):
        import struct as _s
        return self.write_u32(pid, addr, _s.unpack("<I", _s.pack("<f", value))[0])


# ================================================================
# OFFSET TESTER — Qt FENSTER
# ================================================================

def _parse_offsets_for_tester(filepath):
    """Parst offsets.txt → dict { 'Namespace': { 'Field': 0xVAL } }"""
    offsets = {}
    current_ns = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return offsets
    for line in lines:
        s = line.strip()
        m = re.match(r'namespace\s+(\w+)\s*\{', s)
        if m:
            current_ns.append(m.group(1))
            offsets.setdefault('::'.join(current_ns), {})
            continue
        if s.startswith('}') and current_ns:
            current_ns.pop()
            continue
        m = re.match(r'constexpr\s+size_t\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;', s)
        if m and current_ns:
            key = '::'.join(current_ns)
            val = int(m.group(2), 16) if m.group(2).startswith('0x') else int(m.group(2))
            offsets.setdefault(key, {})[m.group(1)] = val
    return offsets

def _find_rust_pid():
    import subprocess
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq RustClient.exe", "/FO", "CSV", "/NH"],
            stderr=subprocess.DEVNULL
        ).decode(errors='ignore')
        for line in out.splitlines():
            parts = [p.strip('"') for p in line.split(',')]
            if len(parts) >= 2 and parts[0].lower() == 'rustclient.exe':
                return int(parts[1])
    except Exception:
        pass
    return None


class _OffsetTesterWidget:
    """Qt-Widget für den Offset-Tester. Wird nur erstellt wenn PyQt5 verfügbar."""

    def __init__(self, offsets, drv, output_path):
        from PyQt5 import QtWidgets, QtCore, QtGui
        self.Qt      = QtWidgets
        self.QtCore  = QtCore
        self.QtGui   = QtGui
        self.offsets = offsets
        self.drv     = drv
        self.pid     = None
        self.base    = 0
        self.output_path = output_path

        self.win = QtWidgets.QWidget()
        self.win.setWindowTitle("NEXUS+ Offset Tester")
        self.win.resize(900, 600)
        self._build(self.win)
        self._refresh()

    def _build(self, parent):
        Q = self.Qt
        root = Q.QVBoxLayout(parent)
        root.setSpacing(4)

        # Verbindungsleiste
        cb = Q.QGroupBox("Verbindung")
        cl = Q.QHBoxLayout(cb)
        self.lbl_drv  = Q.QLabel("Treiber: ?")
        self.lbl_pid  = Q.QLabel("PID: ?")
        self.lbl_base = Q.QLabel("Base: ?")
        btn_ref = Q.QPushButton("Neu verbinden")
        btn_ref.clicked.connect(self._refresh)
        for w in (self.lbl_drv, self.lbl_pid, self.lbl_base, btn_ref):
            cl.addWidget(w)
        cl.addStretch()
        root.addWidget(cb)

        # Filter
        fl = Q.QHBoxLayout()
        fl.addWidget(Q.QLabel("Filter:"))
        self.search = Q.QLineEdit()
        self.search.setPlaceholderText("z.B. AdminConvar, BasePlayer ...")
        self.search.textChanged.connect(self._fill)
        fl.addWidget(self.search)
        root.addLayout(fl)

        # Tabelle
        self.table = Q.QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["Namespace", "Feld", "Offset", "Live-Wert (hex)", "Als Float", "Test"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(Q.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(Q.QAbstractItemView.SelectRows)
        self.table.doubleClicked.connect(lambda i: self._jump(i.row()))
        root.addWidget(self.table)

        # Buttons
        bl = Q.QHBoxLayout()
        b1 = Q.QPushButton("Alle lesen")
        b1.clicked.connect(self._read_all)
        b2 = Q.QPushButton("In IDA springen")
        b2.clicked.connect(lambda: self._jump_sel())
        bl.addWidget(b1); bl.addWidget(b2); bl.addStretch()
        root.addLayout(bl)

        # Status
        self.status = Q.QLabel("Bereit.")
        self.status.setStyleSheet("color: gray; font-size: 11px;")
        root.addWidget(self.status)

        self._fill()

    def _fill(self, ftext=""):
        Q = self.Qt
        self.table.setRowCount(0)
        ft = ftext.lower() if isinstance(ftext, str) else self.search.text().lower()
        for ns_key, fields in sorted(self.offsets.items()):
            if not ns_key.startswith("Offsets::"):
                continue
            ns = ns_key.replace("Offsets::", "")
            for fname, fval in sorted(fields.items()):
                if ft and ft not in ns.lower() and ft not in fname.lower():
                    continue
                row = self.table.rowCount()
                self.table.insertRow(row)
                for col, txt in enumerate([ns, fname, hex(fval), "—", "—"]):
                    self.table.setItem(row, col, Q.QTableWidgetItem(txt))
                btn = Q.QPushButton("Lesen")
                btn.setFixedHeight(22)
                btn.clicked.connect(lambda _, r=row: self._read_row(r))
                self.table.setCellWidget(row, 5, btn)

    def _refresh(self):
        drv_ok = self.drv.ping()
        c = "green" if drv_ok else "red"
        t = "✓ OK" if drv_ok else "✗ Nicht aktiv"
        self.lbl_drv.setText(f"<span style='color:{c}'>Treiber: {t}</span>")
        self.lbl_drv.setTextFormat(self.QtCore.Qt.RichText)
        self.pid = _find_rust_pid()
        self.lbl_pid.setText(f"PID: {self.pid or 'nicht gefunden'}")
        if self.pid:
            self.base = self.drv.get_module_base(self.pid, "GameAssembly.dll")
            self.lbl_base.setText(f"Base: {hex(self.base) if self.base else '?'}")
            self.status.setText(f"PID={self.pid}  Base={hex(self.base)}")
        else:
            self.status.setText("Rust starten und neu verbinden.")

    def _read_row(self, row):
        if not self.pid or not self.base:
            self.status.setText("[!] Nicht verbunden!"); return
        ns    = self.table.item(row, 0).text()
        fname = self.table.item(row, 1).text()
        fval  = int(self.table.item(row, 2).text(), 16)
        top   = ns.split("::")[0]
        soff  = self.offsets.get("Offsets::Static", {}).get(top, 0)
        if soff:
            ptr  = self.drv.read_u64(self.pid, self.base + soff) or 0
            addr = ptr + fval
        else:
            addr = self.base + fval
        raw = self.drv.read_u64(self.pid, addr)
        if raw is None:
            self.table.item(row, 3).setText("Fehler")
            self.status.setText(f"[!] {ns}::{fname} — Lesen fehlgeschlagen"); return
        import struct as _s
        as_f = _s.unpack("<f", _s.pack("<I", raw & 0xFFFFFFFF))[0]
        self.table.item(row, 3).setText(f"0x{raw:016X}")
        self.table.item(row, 4).setText(f"{as_f:.5f}")
        color = self.QtGui.QColor(200, 255, 200) if raw else self.QtGui.QColor(255, 220, 220)
        for c in range(5):
            self.table.item(row, c).setBackground(color)
        self.status.setText(f"{ns}::{fname} @ {hex(addr)} = 0x{raw:X}  ({as_f:.5f})")

    def _read_all(self):
        from PyQt5 import QtWidgets
        self.status.setText("Lese alle Offsets...")
        for r in range(self.table.rowCount()):
            self._read_row(r)
            QtWidgets.QApplication.processEvents()
        self.status.setText("Fertig.")

    def _jump(self, row):
        fval = int(self.table.item(row, 2).text(), 16)
        if self.base:
            idc.jumpto(self.base + fval)
            self.status.setText(f"IDA → {hex(self.base + fval)}")

    def _jump_sel(self):
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self._jump(rows[0].row())

    def show(self):
        self.win.show()
        self.win.raise_()


class _TesterForm(ida_kernwin.PluginForm):
    def __init__(self, offsets, drv, output_path):
        super().__init__()
        self._offsets = offsets
        self._drv     = drv
        self._path    = output_path

    def OnCreate(self, form):
        try:
            from PyQt5 import QtWidgets
        except ImportError:
            return
        parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        self._widget = _OffsetTesterWidget(self._offsets, self._drv, self._path)
        layout.addWidget(self._widget.win)
        parent.setLayout(layout)

    def OnClose(self, form):
        pass


def launch_tester(output_path):
    """Öffnet den Offset Tester als IDA-Dock-Fenster."""
    try:
        from PyQt5 import QtWidgets
    except ImportError:
        print("[Tester] PyQt5 nicht verfügbar — Tester kann nicht geöffnet werden.")
        return

    offsets = _parse_offsets_for_tester(output_path)
    if not offsets:
        print(f"[Tester] Konnte {output_path} nicht laden.")
        return

    drv  = NullKD()
    form = _TesterForm(offsets, drv, output_path)
    form.Show(
        "NEXUS+ Offset Tester",
        options=(
            ida_kernwin.PluginForm.WOPN_TAB |
            ida_kernwin.PluginForm.WOPN_RESTORE
        )
    )
    print("[Tester] Fenster geöffnet.")


# ================================================================
# EINSTIEGSPUNKT + IDA PLUGIN (damit es unter Edit -> Plugins erscheint)
# ================================================================

class NEXUS_Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "NEXUS+ Auto-Offset Generator + Tester"
    help = "Generiert Offsets.h und oeffnet den Offset-Tester."
    wanted_name = "NEXUS+ Offset Generator"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        main()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return NEXUS_Plugin()


if __name__ == '__main__':
    main()
