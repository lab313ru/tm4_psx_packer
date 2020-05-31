import json
import os
import re
import struct
import sys
import zlib


MAGIC = b'\x67\x00'
MIN_SIZE = 16


HDR_FMT = '<BBH'
NAME_HDR_OFF = struct.calcsize(HDR_FMT)
BLOCK_FMT = '<BBHII'
NAME_BLOCK_OFF = struct.calcsize(BLOCK_FMT)

BLOCK_TYPES = [
    ('REG_FILE_TYPE_BASE', -1),
    ('REG_FILE_TYPE_OUTPUT_FILENAME', -1),
    ('REG_FILE_TYPE_STRING', -1),
    ('REG_FILE_TYPE_BINARY', -1),
    ('REG_FILE_TYPE_LONG', 4),
    ('REG_FILE_TYPE_LOCATION_3D', 8),
    ('REG_FILE_TYPE_RELMOD', -1),
    ('REG_FILE_TYPE_GEO_VISIBLE', -1),
    ('REG_FILE_TYPE_GEO_VISIBLE_REF', 4),
    ('REG_FILE_TYPE_GEO_COLLIDE', -1),
    ('REG_FILE_TYPE_GEO_COLLIDE_REF', 4),
    ('REG_FILE_TYPE_BOOLEAN', 4),
    ('REG_FILE_TYPE_TEXTURE', -1),
    ('REG_FILE_TYPE_FIXED_POINT', 4),
    ('REG_FILE_TYPE_COLOR', 4),
    ('REG_FILE_TYPE_LOCATION_DIR_3D', 16),
    ('REG_FILE_TYPE_SOUND_VAB', -1),
    ('REG_FILE_TYPE_AI_WORLD', -1),
    ('REG_FILE_TYPE_BYTE_ARRAY', -1),
    ('REG_FILE_TYPE_SHORT_ARRAY', -1),
    ('REG_FILE_TYPE_LONG_ARRAY', -1),
    ('REG_FILE_TYPE_FIXED_POINT_ARRAY', -1),
    ('REG_FILE_TYPE_STRING_ARRAY', -1),
    ('REG_FILE_TYPE_BYTE', 4),
    ('REG_FILE_TYPE_SHORT', 4),
    ('REG_FILE_TYPE_LOCATION_3D_ARRAY', -1),
    ('REG_FILE_TYPE_LOCATION_DIR_3D_ARRAY', -1),
    ('REG_FILE_TYPE_LOCATION_2D', 4),
    ('REG_FILE_TYPE_LOCATION_2D_ARRAY', -1),
    ('REG_FILE_TYPE_LOCATION_ORIENT_3D', 4),
    ('REG_FILE_TYPE_LOCATION_ORIENT_3D_ARRAY', -1),
    ('REG_FILE_TYPE_LOCATION_ORIENT_SPEED_3D', 4),
    ('REG_FILE_TYPE_LOCATION_ORIENT_SPEED_3D_', -1),
    ('REG_FILE_TYPE_LOCATION_SPEED_3D', 8),
    ('REG_FILE_TYPE_LOCATION_SPEED_3D_ARRAY', -1),
    ('REG_FILE_TYPE_LOCATION_DIR_SPEED_3D', 16),
    ('REG_FILE_TYPE_LOCATION_DIR_SPEED_3D_ARR', -1),
    ('REG_FILE_TYPE_PAD_VIBRATE', 16),
    ('REG_FILE_TYPE_PAD_VIBRATE_ARRAY', -1),
]


def unpack_block(packed_size, unpacked_size, zdata):
    zdata = zdata[:packed_size]
    return zlib.decompress(zdata, bufsize=unpacked_size) if unpacked_size != 0 else zdata


def create_dir(d):
    try:
        os.makedirs(d, exist_ok=True)
    except (FileExistsError, NotADirectoryError):
        name = os.path.basename(d)
        name = '__%s__' % name
        d = os.path.join(os.path.dirname(d), name)
    finally:
        os.makedirs(d, exist_ok=True)
        return d


def unpack_data(stream, offset, root=''):
    name_len, sub_count, count = struct.unpack_from(HDR_FMT, stream, offset[0])
    name = stream[offset[0]+NAME_HDR_OFF:offset[0]+NAME_HDR_OFF+name_len]
    real_name_len = name.find(b'\x00')
    name = name[:real_name_len].decode()

    if name.startswith('C:\\'):
        name = 'Root'

    funcs_dict = None
    if root == 'Root' and name == 'os':
        funcs_dict = {}

    curr_root = os.path.join(root, name)

    curr_root = create_dir(curr_root)

    print('Dir: %s' % curr_root)

    block_off = offset[0] + NAME_HDR_OFF + name_len

    for i in range(count):
        block_name_len, block_type, h1, p_size, u_size = struct.unpack_from(BLOCK_FMT, stream, block_off)

        block_name = stream[block_off+NAME_BLOCK_OFF:block_off+NAME_BLOCK_OFF+block_name_len]
        block_name = re.sub(b'[^\\w\\d_.()#@ ]+', b'', block_name)
        block_name = block_name.decode()

        fname = os.path.join(curr_root, block_name)

        data_off = block_off + NAME_BLOCK_OFF + block_name_len

        unpacked_data = unpack_block(p_size, u_size, stream[data_off:])

        try:
            open(fname, 'wb')
        except PermissionError:
            block_name = '__%s__' % block_name
            fname = os.path.join(curr_root, block_name)

        w = open(fname, 'wb')
        w.write(unpacked_data)
        w.close()

        if funcs_dict is not None:
            funcs_dict[block_name] = struct.unpack('<I', unpacked_data)[0]

        print('[%d] (%s%s) unpacked to \'%s\' (%s)' % (i + 1,
                                                       BLOCK_TYPES[block_type][0],
                                                       '' if h1 == 0xFFFF else ('[%d]' % h1), block_name,
                                                       ('%d -> %d bytes' % (p_size, u_size)) if u_size > 0 else
                                                       ('%d bytes' % p_size)
                                                       ))

        block_off += NAME_BLOCK_OFF + p_size + block_name_len

    if funcs_dict is not None:
        with open('os_funcs.json', 'w') as os_funcs_f:
            json.dump(funcs_dict, os_funcs_f, indent=4)

    print()
    offset[0] = block_off

    for i in range(sub_count):
        unpack_data(stream, offset, root=curr_root)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(-1)

    f = open(sys.argv[1], 'rb')
    data = f.read()
    f.close()

    tag = data[:2]

    if tag != MAGIC or len(data) < MIN_SIZE:
        print('Wrong file type!')
        sys.exit(-2)

    # print('WORD2: %04X' % struct.unpack('<H', data[2:2+2]))
    off = [4]
    unpack_data(data, off)
