import os
import sys
from struct import unpack, pack, pack_into, unpack_from


def read_byte(fobj):
    return unpack('B', fobj.read(1))[0]


def read_word(fobj):
    return unpack('<H', fobj.read(2))[0]


def read_dword(fobj):
    return unpack('<I', fobj.read(4))[0]


def read_blen_string(fobj):
    sl = read_byte(fobj)
    r = fobj.read(sl).decode()
    return r


def read_patch_info(fobj):
    ref = dict()
    tag_type = read_byte(fobj)

    if tag_type == 0:
        ref['val'] = read_dword(fobj)
        ref['type'] = 'val'
    elif tag_type == 2:
        ref['val'] = read_word(fobj)
        ref['type'] = 'imp'
    elif tag_type == 4:
        ref['val'] = read_word(fobj)
        ref['type'] = 'sbase'
    elif tag_type == 12:
        ref['val'] = read_word(fobj)
        ref['type'] = 'sstart'
    elif tag_type == 22:
        ref['val'] = read_word(fobj)
        ref['type'] = 'send'
    else:
        ref['val'] = list()

        add1 = read_patch_info(fobj)
        ref['val'].append(add1)

        if tag_type == 0x2C:
            ref['val'].append('+')
        elif tag_type == 0x2E:
            ref['val'].append('-')
        elif tag_type == 0x32:
            ref['val'].append('/')
        elif tag_type == 0x36:
            ref['val'].append('!')
        else:
            print('Unknown patch type: 0x%02X at offset 0x%08X' % (tag_type, fobj.tell()))
            return None

        add2 = read_patch_info(fobj)
        ref['val'].append(add2)

        type1 = add1['type']
        type2 = add2['type']

        if type1 in ['sbase', 'sstart', 'send']:
            ref['type'] = type1
        elif type2 in ['sbase', 'sstart', 'send']:
            ref['type'] = type2
        elif type1 == 'imp':
            ref['type'] = type1
        elif type2 == 'imp':
            ref['type'] = type2
        else:
            ref['type'] = type1

    return ref


def read_patch(fobj, patch_off):
    ptype = read_byte(fobj)
    offset = read_word(fobj)

    reference = read_patch_info(fobj)

    return {
        'type': ptype,
        'offset': offset + patch_off,
        'ref': reference
    }


def parse_obj(fobj):
    tag = fobj.read(3)

    if tag != b'LNK':
        return None

    ver = read_byte(fobj)

    if ver != 2:
        return None

    sections = dict()
    curr_sect = 0

    patches = list()

    xdefs = list()
    xrefs = dict()
    xbss = dict()
    symbols = dict()

    is_end = False

    while True:
        itype = read_byte(fobj)

        if itype == 0:
            is_end = True
        elif itype == 2:
            code_size = read_word(fobj)
            code_bytes = fobj.read(code_size)

            prev_bytes = sections[curr_sect].get('bytes', b'')
            sections[curr_sect]['patch_off'] = len(prev_bytes)
            sections[curr_sect]['bytes'] = prev_bytes + code_bytes
        elif itype == 4:
            start_sect = read_word(fobj)
            start_off = read_dword(fobj)

            # run_points
        elif itype == 6:
            curr_sect = read_word(fobj)
        elif itype == 8:
            code_size = read_dword(fobj)
            code_bytes = b'\x00' * code_size

            prev_bytes = sections[curr_sect].get('bytes', b'')
            sections[curr_sect]['patch_off'] = len(prev_bytes)
            sections[curr_sect]['bytes'] = prev_bytes + code_bytes
        elif itype == 10:
            patch_off = sections[curr_sect].get('patch_off', 0)

            patches.append({
                'sect': curr_sect,
                'data': read_patch(fobj, patch_off)
            })
        elif itype == 12:
            sym_index = read_word(fobj)
            sect_index = read_word(fobj)
            offset = read_dword(fobj)
            name = read_blen_string(fobj)

            xdef = {
                'index': sym_index,
                'name': name,
                'offset': offset,
                'sect': sect_index
            }

            xdefs.append(xdef)
            symbols[sym_index] = xdef
        elif itype == 14:
            sym_index = read_word(fobj)
            name = read_blen_string(fobj)

            sym = {
                'index': sym_index,
                'name': name,
                'offset': len(xrefs) * 4
            }

            xrefs[sym_index] = symbols[sym_index] = sym
        elif itype == 16:
            sym_index = read_word(fobj)
            group_index = read_word(fobj)
            align = read_byte(fobj)
            name = read_blen_string(fobj)

            sections[sym_index] = symbols[sym_index] = {
                'index': sym_index,
                'name': name,
                'group': group_index,
                'align': align
            }
        elif itype == 18:
            sect_index = read_word(fobj)
            offset = read_dword(fobj)
            name = read_blen_string(fobj)

            # put to locals
        elif itype == 20:
            group_index = read_word(fobj)
            group_type = read_byte(fobj)
            name = read_blen_string(fobj)

            # put to groups
        elif itype in [22, 24, 26, 42]:
            patch_off = sections[curr_sect]['patch_off']
            patch_data = read_patch(fobj, patch_off)
            offset = read_word(fobj)

            # put to regpatch
        elif itype == 28:
            file_index = read_word(fobj)
            name = read_blen_string(fobj)

            # put to deffiles
        elif itype == 30:
            file_index = read_word(fobj)
            line_index = read_dword(fobj)

            # put to filelines
        elif itype == 32:
            line_index = read_dword(fobj)
        elif itype == 34:
            pass
        elif itype == 36:
            incb = read_byte(fobj)
        elif itype == 38:
            incw = read_word(fobj)
        elif itype == 40:
            sect_index = read_word(fobj)
            offset = read_dword(fobj)
            name = read_blen_string(fobj)

            # put to vlocals
        elif itype == 44:
            val = read_byte(fobj)
            off = read_word(fobj)

            # put to mx infos
        elif itype == 46:
            read_byte(fobj)
        elif itype == 48:
            sym_index = read_word(fobj)
            sect_index = read_word(fobj)
            sym_size = read_dword(fobj)
            name = read_blen_string(fobj)

            sym = {
                'index': sym_index,
                'name': name,
                'offset': len(xbss) * 4,
                'size': sym_size,
                'sect': sect_index
            }

            prev = xbss.get(sect_index, list())
            prev.append(sym)
            xbss[sect_index] = prev
            symbols[sym_index] = sym
        elif itype == 50:
            read_word(fobj)
        elif itype == 52:
            read_word(fobj)
            read_byte(fobj)
        elif itype == 54:
            read_word(fobj)
            read_word(fobj)
        elif itype == 56:
            read_word(fobj)
            read_dword(fobj)
        elif itype == 58:
            read_word(fobj)
            read_dword(fobj)
            read_word(fobj)
        elif itype == 60:
            read_word(fobj)
        elif itype in [62, 64, 66, 72]:
            patch_off = sections[curr_sect]['patch_off']
            patch_data = read_patch(fobj, patch_off)
            count = read_dword(fobj)

            # put into repeated data
        elif itype in [68, 70]:
            pass
        elif itype == 74:
            section = read_word(fobj)
            offset = read_dword(fobj)
            file = read_word(fobj)
            start_line = read_dword(fobj)
            frame_reg = read_word(fobj)
            frame_size = read_dword(fobj)
            retn_pc_reg = read_word(fobj)
            mask = read_dword(fobj)
            mask_off = read_dword(fobj)
            name = read_blen_string(fobj)

            # put into funcs
        elif itype == 76:
            section = read_word(fobj)
            offset = read_dword(fobj)
            end_line = read_dword(fobj)

            # put into func ends
        elif itype == 78:
            section = read_word(fobj)
            offset = read_dword(fobj)
            start_line = read_dword(fobj)

            # put into block starts
        elif itype == 80:
            section = read_word(fobj)
            offset = read_dword(fobj)
            end_line = read_dword(fobj)

            # put into block ends
        elif itype == 82:
            section = read_word(fobj)
            value = read_dword(fobj)
            class_index = read_word(fobj)
            type_index = read_word(fobj)
            size = read_dword(fobj)
            name = read_blen_string(fobj)

            # put into defs
        elif itype == 84:
            section = read_word(fobj)
            value = read_dword(fobj)
            class_index = read_word(fobj)
            type_index = read_word(fobj)
            size = read_dword(fobj)
            dims = read_word(fobj)

            for i in range(dims):
                read_dword(fobj)

            tag = read_blen_string(fobj)
            tag2 = read_blen_string(fobj)

            # put into defs2
        else:
            print('Unknown tag 0x%02X at offset: 0x%08X' % (itype, fobj.tell()))
            return None

        if is_end:
            break

    c = list(filter(lambda x: x['name'] == '.text', sections.values()))
    s = list(filter(lambda x: x['name'] == '.sdata', sections.values()))
    return patches, xdefs, xrefs, c[0]['index'], c[0]['bytes'] + s[0]['bytes'], len(c[0]['bytes'])


def encode_jump(code, pos, val):
    prev_val = unpack_from('<I', code, pos)[0]
    code = bytearray(code)
    pack_into('<I', code, pos, (prev_val & 0xFC000000) | ((val & 0x3FFFFFF) >> 2))
    return bytes(code)


def encode_hi(code, pos, val):
    prev_val = unpack_from('<I', code, pos)[0]
    code = bytearray(code)
    pack_into('<I', code, pos, (prev_val & 0xFFFF0000) | ((val + 0x8000) >> 0x10))
    return bytes(code)


def encode_lo(code, pos, val):
    prev_val = unpack_from('<I', code, pos)[0]
    code = bytearray(code)
    pack_into('<I', code, pos, (prev_val & 0xFFFF0000) | (val & 0xFFFF))
    return bytes(code)


def encode_relative(relocs, code, code_end):
    encoded = b''

    for reloc in relocs:
        rdata = reloc['data']

        # from (0xFFFFFFFC) | type (0x03)
        t = rdata['type']
        off = rdata['offset']
        ref = rdata['ref']
        rtype = ref['type']
        rval = ref['val']

        if rtype == 'imp':  # dont encode imports here
            continue

        if t == ord('J'):  # jump
            code = encode_jump(code, off, rval[2]['val'])
            encoded += pack('<I', (off | 3))
        elif t == ord('R'):  # relative hi half
            code = encode_hi(code, off, rval[2]['val'])
            encoded += pack('<II', (off | 1), code_end)
        elif t == ord('T'):  # relative lo half
            code = encode_lo(code, off, code_end + rval[2]['val'])
            encoded += pack('<I', (off | 2))
        elif t == 0x1E:  # relative to fp
            print('Not implemented patch type')
            exit(-1)
        elif t == ord('d'):  # relative to gp
            print('Not implemented patch type')
            exit(-1)

    return code, encoded + pack('<I', 0xFFFFFFFF)


def encode_exports(xdefs, main_sect, sdata_off):
    encoded = b''
    names = b''

    strings_base = 4 + len(xdefs) * 8

    encoded += pack('<I', len(xdefs))

    for xdef in xdefs:
        if xdef['sect'] == main_sect:
            encoded += pack('<II', strings_base + len(names), xdef['offset'])
        else:
            encoded += pack('<II', strings_base + len(names), sdata_off + xdef['offset'])
        name = xdef['name'].encode() + b'\x00'
        names += name

    return encoded + names


def encode_name(name, term=b'\x00', val=b'\x00'):
    name = name.encode() + term

    name_align = len(name) % 4
    if name_align:
        name += val * (4 - name_align)

    return name


def encode_imports(xrefs, patches):
    encoded = b''

    encoded += pack('<I', len(xrefs))

    for xref in xrefs.values():
        name = encode_name(xref['name'])
        encoded += name

        plist = list()

        for patch in patches:
            pdata = patch['data']
            pref = pdata['ref']
            ptype = pref['type']
            pval = pref['val']

            if ptype != 'imp':
                continue

            if isinstance(pval, int) and pval != xref['index']:
                continue

            if isinstance(pval, list):
                p1 = pval[0]['type']
                p1v = pval[0]['val']
                p2 = pval[2]['type']
                p2v = pval[2]['val']

                if p1 in ['sbase', 'sstart', 'send']:
                    continue

                if p1 == 'imp' and p1v != xref['index']:
                    continue

                if p2 == 'imp' and p2v != xref['index']:
                    continue

            plist.append(pdata)

        encoded += pack('<I', len(plist))

        for patch in plist:
            t = patch['type']
            off = patch['offset']
            rval = patch['ref']['val']

            if t == ord('J'):  # jump
                encoded += pack('<I', (off | 3))
            elif t == ord('T'):  # relative lo half
                encoded += pack('<II', (off | 1), rval[0]['val'])
            elif t == ord('R'):  # relative hi half
                encoded += pack('<I', (off | 2))
            elif t == 0x1E:  # relative to fp
                print('Not implemented import patch type')
                exit(-1)
            elif t == ord('d'):  # relative to gp
                print('Not implemented import patch type')
                exit(-1)

    return encoded


def create_mod(obj_name, patches, xdefs, xrefs, main_sect, code, sdata_off):
    offset = 5 * 4  # header size actually

    mod = pack('<I', offset)
    offset += len(code)

    mod += pack('<I', offset)
    code, encoded_relocs = encode_relative(patches, code, sdata_off)
    offset += len(encoded_relocs)

    mod += pack('<I', offset)
    encoded_exports = encode_exports(xdefs, main_sect, sdata_off)
    offset += len(encoded_exports)

    mod += pack('<I', offset)
    encoded_imports = encode_imports(xrefs, patches)
    offset += len(encoded_imports)

    mod += pack('<I', offset)

    encoded_name = '%s.sym*\r\n' % obj_name
    encoded_name = encode_name(encoded_name, term=b'', val=b'\xFD')

    return mod + code + encoded_relocs + encoded_exports + encoded_imports + encoded_name


def main(path):
    name, ext = os.path.splitext(path)
    f = open(path, 'rb')
    patches, xdefs, xrefs, main_sect, code, sdata_off = parse_obj(f)
    f.close()

    encoded = create_mod(os.path.basename(name), patches, xdefs, xrefs, main_sect, code, sdata_off)

    w = open(os.path.basename(name) + '.mod', 'wb')
    w.write(encoded)
    w.close()


if __name__ == '__main__':
    main(sys.argv[1])
