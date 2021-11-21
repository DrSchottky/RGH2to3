import sys
import struct
import ecc_utils
import hmac
import hashlib
import os
import Crypto.Cipher.ARC4 as RC4

def decrypt_CB(CB, key):
    key = hmac.new(key, CB[0x10:0x20], hashlib.sha1).digest()[0:0x10]
    CB = CB[0:0x10] + key + RC4.new(key).decrypt(CB[0x20:])
    return CB

def decrypt_CB_B(cbb, cba, cpukey):
    secret = cba[0x10:0x20]
    h = hmac.new(secret,None, hashlib.sha1)
    h.update(cbb[0x10:0x20])
    h.update(cpukey)
    key = h.digest()[0:0x10]
    CB = cbb[0:0x10] + key + RC4.new(key).decrypt(cbb[0x20:])
    return CB

print("*RGH2 to 3 by DrSchottky*\n")

if len(sys.argv) != 5 or not os.path.isfile(sys.argv[1]) or not os.path.isfile(sys.argv[2]):
    print("Usage: {} RGH3_ECC.bin updflash.bin CPUKEY outfile.bin".format(sys.argv[0]))
    sys.exit(0)

cpukey = bytearray.fromhex(sys.argv[3])
if len(cpukey) != 16:
    print("Unexpected CPU key length. Aborting")
    sys.exit(0)

print("Loading ECC")
with open(sys.argv[1], "rb") as f:
	ecc = f.read()

if len(ecc) == 1351680:
    print("ECC contains spare data")
    ecc = ecc_utils.unecc(ecc)
elif len(ecc) == 1310720:
    print("ECC does not contain spare data")
else:
    print("Unexpected ECC length. Aborting")
    sys.exit(0)

print("\nExtracting RGH3 SMC")
(rgh3_smc_len, rgh3_smc_start) = struct.unpack(">LL", ecc[0x78:0x80])
rgh3_smc = ecc[rgh3_smc_start:rgh3_smc_len+rgh3_smc_start]
loader_start = struct.unpack("!L", ecc[0x8:0xC])[0]

print("\nExtracting RGH3 Bootloaders")
(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = struct.unpack("!2sHLLL", ecc[loader_start:loader_start+16])
print("Found {} {} with size 0x{:08X} at 0x{:08X}" .format(loader_name.decode(), loader_ver, loader_size, loader_start))
rgh3_cba = ecc[loader_start:loader_start+loader_size]
loader_start += loader_size

(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = struct.unpack("!2sHLLL", ecc[loader_start:loader_start+16])
print("Found {} {} with size 0x{:08X} at 0x{:08X}" .format(loader_name.decode(), loader_ver, loader_size, loader_start))
rgh3_payload = ecc[loader_start:loader_start+loader_size]

if not rgh3_payload or not rgh3_cba:
    print("\nMissing ECC bootloaders. Aborting")
    sys.exit(0)

print("\nLoading FB")
with open(sys.argv[2], "rb") as f:
	fb = f.read()
fb_with_ecc = False

if len(fb) == 17301504 or len(fb) == 69206016:
    print("FB image contains spare data")
    xell_start = 0x73800
    patchable_fb = fb[:xell_start]
    patchable_fb = ecc_utils.unecc(patchable_fb)
    fb_with_ecc = True
elif len(fb) == 50331648:
    print("FB image does not contain spare data")
    xell_start = 0x70000
    patchable_fb = fb[:xell_start]
else:
    print("Unexpected FB image length. Aborting")
    sys.exit(0)

if fb_with_ecc:
    spare_sample = fb[0x4400:0x4410]
    if spare_sample[0] == b"\xff":
        print("Detected 256/512MB Big Block Flash")
        block_type=ecc_utils.BLOCK_TYPE_BIG
    elif spare_sample[5] == b"\xff":
        if spare_sample[0:2] == b"\x01\x00":
            print("Detected 16/64MB Small Block Flash")
            block_type=ecc_utils.BLOCK_TYPE_SMALL
        elif spare_sample[0:2] == b"\x00\x01":
            print("Detected 16/64MB Big on Small Flash")
            block_type=ecc_utils.BLOCK_TYPE_BIG_ON_SMALL
        else:
            print("Can't detect Flash type. Aborting")
            sys.exit(0)
    else:
        print("Can't detect Flash type. Aborting")
        sys.exit(0)
else:
    print("Detected 4GB Flash")

if fb[xell_start:xell_start + 0x10] != b"\x48\x00\x00\x20\x48\x00\x00\xEC\x48\x00\x00\x00\x48\x00\x00\x00":
    print("Xell header not found. Aborting")
    print()
    sys.exit(0)

print("\nPatching SMC")
patchable_fb = patchable_fb[:rgh3_smc_start] + rgh3_smc + patchable_fb[rgh3_smc_start+rgh3_smc_len:]


print("\nExtracting FB bootloaders")

loader_start = struct.unpack("!L", patchable_fb[0x8:0xC])[0]

(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = struct.unpack("!2sHLLL", patchable_fb[loader_start:loader_start+16])
print("Found {} {} with size 0x{:08X} at 0x{:08X}" .format(loader_name.decode(), loader_ver, loader_size, loader_start))
fb_cba = patchable_fb[loader_start:loader_start+loader_size]
fb_cba_start = loader_start
loader_start += loader_size

(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = struct.unpack("!2sHLLL", patchable_fb[loader_start:loader_start+16])
print("Found {} {} with size 0x{:08X} at 0x{:08X}" .format(loader_name.decode(), loader_ver, loader_size, loader_start))
fb_cbb = patchable_fb[loader_start:loader_start+loader_size]
fb_cbb_start = loader_start

print("\nDecrypting CB")
key_1bl = b"\xDD\x88\xAD\x0C\x9E\xD6\x69\xE7\xB5\x67\x94\xFB\x68\x56\x3E\xFA"
plain_fb_cba = decrypt_CB(fb_cba, key_1bl)
fb_cbb = decrypt_CB_B(fb_cbb, plain_fb_cba, cpukey)
if fb_cbb[0x392:0x39a] != b"\x58\x42\x4F\x58\x5F\x52\x4F\x4D":
    print("CB_B decryption error (wrong CPU key?). Aborting")
    sys.exit(0)

print("\nPatching CB")
original_size = len(patchable_fb)
new_cbb = rgh3_payload + fb_cbb
patchable_fb = patchable_fb[:fb_cba_start] + rgh3_cba + new_cbb + patchable_fb[fb_cbb_start+len(fb_cbb):]
new_size = len(patchable_fb)
print("I had to remove 0x{:02X} bytes after CE to make it fit.".format(new_size - original_size))
patchable_fb = patchable_fb[:original_size]

print("\nMerging image")
if fb_with_ecc:
    patchable_fb = ecc_utils.addecc(patchable_fb, block_type=block_type)
fb = patchable_fb + fb[len(patchable_fb):]
with open(sys.argv[4], "wb") as f:
    f.write(fb)
print("\nDone!")
