import os
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


def unpack_data(stream, root=''):
    name_len, sub_count, count = struct.unpack_from(HDR_FMT, stream, 0)
    name = stream[NAME_HDR_OFF:NAME_HDR_OFF+name_len]
    real_name_len = name.find(b'\x00')
    name = name[:real_name_len].decode()

    print('Dir: %s' % root)

    try:
        os.mkdir(os.path.join(root, name))
    except FileExistsError:
        pass

    block_off = NAME_HDR_OFF + name_len

    for i in range(count):
        block_name_len, block_type, h1, p_size, u_size = struct.unpack_from(BLOCK_FMT, stream, block_off)

        block_name = stream[block_off+NAME_BLOCK_OFF:block_off+NAME_BLOCK_OFF+block_name_len]
        real_block_name_len = block_name.find(b'\x00')
        block_name = block_name[:real_block_name_len].decode()

        data_off = block_off + NAME_BLOCK_OFF + block_name_len

        unpacked_data = unpack_block(p_size, u_size, stream[data_off:])

        sub_name = os.path.join(name, block_name)
        fname = os.path.join(root, sub_name)
        with open(fname, 'wb') as w:
            w.write(unpacked_data)

        print('[%d] (%s%s) unpacked to \'%s\' (%s)' % (i + 1,
                                                       BLOCK_TYPES[block_type][0],
                                                       '' if h1 == 0xFFFF else ('[%d]' % h1), sub_name,
                                                       ('%d -> %d bytes' % (p_size, u_size)) if u_size > 0 else
                                                       ('%d bytes' % p_size)
                                                       ))

        block_off += NAME_BLOCK_OFF + p_size + block_name_len

    print()

    for i in range(sub_count):
        unpack_data(stream[block_off:], root=os.path.join(root, name))


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

    print('WORD2: %04X' % struct.unpack('<H', data[2:2+2]))
    unpack_data(data[4:])
