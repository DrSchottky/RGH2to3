import sys
import struct
import io
import sys

BLOCK_TYPE_SMALL = 0x0
BLOCK_TYPE_BIG_ON_SMALL = 0x1
BLOCK_TYPE_BIG = 0x02

def calcecc(data):
    assert len(data) == 0x210
    val = 0
    for i in range(0x1066):
        if not i & 31:
            v = ~struct.unpack("<L", data[i//8:i//8+4])[0]
        val ^= v & 1
        v >>= 1
        if val & 1:
            val ^= 0x6954559
        val >>= 1
    val = ~val
    return data[:-4] + struct.pack("<L", (val << 6) & 0xFFFFFFFF)

def addecc(data, block = 0, off_8 = b"\x00" * 4, block_type=BLOCK_TYPE_BIG_ON_SMALL):
    res = b""
    while len(data):
        d = (data[:0x200] + b"\x00" * 0x200)[:0x200]
        data = data[0x200:]
        
        if block_type == BLOCK_TYPE_BIG_ON_SMALL:
            d += struct.pack("<BL3B4s4s", 0, block // 32, 0xFF, 0, 0, off_8, b"\0\0\0\0")
        elif block_type == BLOCK_TYPE_BIG:
            d += struct.pack("<BL3B4s4s", 0xFF, block // 256, 0, 0, 0, off_8, b"\0\0\0\0")
        elif block_type == BLOCK_TYPE_SMALL:
            d += struct.pack("<L4B4s4s", block // 32, 0, 0xFF, 0, 0, off_8, b"\0\0\0\0")
        else:
            raise ValueError("Block type not supported")
        d = calcecc(d)
        block += 1
        res += d
    return res

def unecc(image):
    res = b""
    for s in range(0, len(image), 528):
        res += image[s:s+512]
    return res

def unecc_fast(image):
    return b''.join([image[s:s+512] for s in range(0, len(image), 528)])
    
def verify(data, block = 0, off_8 = b"\x00" * 4):
    while len(data):
        d = (data[:0x200] + b"\x00" * 0x200)[:0x200]
        d += struct.pack("<L4B4s4s", block // 32, 0, 0xFF, 0, 0, off_8, b"\0\0\0\0")
        d = calcecc(d)
        calc_ecc = d[0x200:]
        file_ecc = data[0x200:0x210]
        if calc_ecc != file_ecc:
            print("Ecc mismatch on page 0x{:02X} (0x{:02X})".format(block, (block + 1) * 0x210 - 0x10))
            print(file_ecc)
            print(calc_ecc)
        block += 1
        data = data[0x210:]

def help():
    print("Usage: {} [-u][-e][-v] file".format(sys.argv[0]))

def main():
    if len(sys.argv) < 3:
        help()
        return

    with open(sys.argv[2], "rb") as f:
        image = f.read()

    if sys.argv[1] == "-u":
        image = unecc(image)
        with open(sys.argv[2]+".unecc", "wb") as f:
            f.write(image)
    elif sys.argv[1] == "-e":
        image = addecc(image)
        with open(sys.argv[2]+".ecc", "wb") as f:
            f.write(image)
    elif sys.argv[1] == "-v":
        verify(image)
    else:
        help()
        return

if __name__ == "__main__":
    main()