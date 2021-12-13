#!/usr/bin/env python3

import re
import hmac
from hashlib import sha1
from struct import unpack
from os.path import isfile
from argparse import ArgumentParser, FileType, ArgumentTypeError

# ecc_utils.py
import ecc_utils
# rc4.py
from rc4 import RC4

_1BL_KEY = bytes.fromhex("DD88AD0C9ED669E7B56794FB68563EFA")
_SW_VER = "v1.1.0"

CPUKEY_EXP = re.compile(r"^[0-9a-fA-F]{32}$")

def decrypt_cba(cba: bytes, key: bytes) -> bytes:
	key = hmac.new(key, cba[0x10:0x20], sha1).digest()[0:0x10]
	# cb = cb[0:0x10] + key + RC4.new(key).decrypt(cb[0x20:])
	cba = cba[:0x10] + key + RC4(key).crypt(cba[0x20:])
	return cba

def decrypt_cbb(cbb: bytes, cba: bytes, cpukey: bytes, key: bytes = b"") -> bytes:
	secret = cba[0x10:0x20]
	h = hmac.new(secret, digestmod=sha1)
	h.update(cbb[0x10:0x20])
	h.update(cpukey)
	if not key:
		key = h.digest()[:0x10]
	# cb = cbb[0:0x10] + key + RC4.new(key).decrypt(cbb[0x20:])
	cbb = cbb[:0x10] + key + RC4(key).crypt(cbb[0x20:])
	return cbb

def cpukey_type(key: str) -> bytes:
	matches = CPUKEY_EXP.match(key)
	if matches:
		return bytes.fromhex(key)
	raise ArgumentTypeError("CPU key isn't a 32 character hex string")

def main() -> None:
	parser = ArgumentParser(description=f"RGH2 to RGH3 by DrSchottky {_SW_VER}")
	parser.add_argument("eccfile", type=FileType("rb"), help="The ECC file to apply")
	parser.add_argument("infile", type=FileType("rb"), help="The flash image to convert to RGH3")
	parser.add_argument("outfile", type=FileType("wb"), help="The flash image to output to")
	parser.add_argument("-k", "--cpukey", type=cpukey_type, help="The CPU key for the given flash image")
	args = parser.parse_args()

	if args.cpukey:
		cpukey = args.cpukey
	elif isfile("cpukey.bin"):
		with open("cpukey.bin", "rb") as f:
			cpukey = f.read()
	elif isfile("cpukey.txt"):
		with open("cpukey.txt", "r") as f:
			cpukey = bytes.fromhex(f.read().strip())
	else:
		print("No CPU key found, aborting...")
		return

	print("Loading ECC")
	ecc = args.eccfile.read()
	args.eccfile.close()

	if len(ecc) == 1351680:
		print("ECC contains spare data")
		ecc = ecc_utils.unecc(ecc)
	elif len(ecc) == 1310720:
		print("ECC does not contain spare data")
	else:
		print("Unexpected ECC length, aborting...")
		return

	print("\nExtracting RGH3 SMC")
	(rgh3_smc_len, rgh3_smc_start) = unpack(">LL", ecc[0x78:0x80])
	rgh3_smc = ecc[rgh3_smc_start:rgh3_smc_len + rgh3_smc_start]
	loader_start = unpack(">L", ecc[0x8:0xC])[0]

	print("\nExtracting RGH3 Bootloaders")
	(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack(">2sHLLL", ecc[loader_start:loader_start + 16])
	print(f"Found {loader_name.decode()} {loader_ver} with size 0x{loader_size:08X} at 0x{loader_start:08X}")
	rgh3_cba = ecc[loader_start:loader_start + loader_size]
	loader_start += loader_size

	(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack(">2sHLLL", ecc[loader_start:loader_start + 16])
	print(f"Found {loader_name.decode()} {loader_ver} with size 0x{loader_size:08X} at 0x{loader_start:08X}")
	rgh3_payload = ecc[loader_start:loader_start + loader_size]

	if not rgh3_payload or not rgh3_cba:
		print("\nMissing ECC bootloaders, aborting...")
		return

	rgh3_cba_dec = decrypt_cba(rgh3_cba, _1BL_KEY)
	rgh3_payload_dec = bytearray(decrypt_cbb(rgh3_payload, rgh3_cba_dec, b"\x00"*16))
	if rgh3_payload_dec[0x354:0x358] == b"\x64\x6A\x00\x02":
		print("Patching fake CB_B (RHG3 payload)")
		rgh3_payload_dec[0x354:0x358] = b"\x64\x69\x00\x02"
		rgh3_payload_dec[0x368:0x36c] = b"\x7d\x8c\x48\x2a"
		rgh3_payload_dec[0x370:0x374] = b"\x64\x69\x00\x06"
		rgh3_payload_dec[0x37c:0x380] = b"\xf8\x49\x10\x10"
		rgh3_payload = decrypt_cbb(rgh3_payload_dec, rgh3_cba_dec, b"\x00"*16, rgh3_payload_dec[0x10:0x20])
		rgh3_payload[0x10:0x20] = b"\x00"*16

	print("\nLoading FB")
	fb = args.infile.read()
	args.infile.close()
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
		print("Unexpected FB image length, aborting...")
		return

	print("\nDetecting Flash type")
	if fb_with_ecc:
		page_20_ecc = fb[0x4400:0x4410]
		block_type = ecc_utils.get_block_type(page_20_spare_data=page_20_ecc)
		if block_type == ecc_utils.BLOCK_TYPE.UNKNOWN:
			print("aborting...")
			return
	else:
		print("Detected 4GB Flash")

	xell_not_found = False
	if fb[xell_start:xell_start + 0x10] != bytes.fromhex("48000020480000EC4800000048000000"):
		print("XeLL header not found")
		xell_not_found = True

	print("\nExtracting FB bootloaders")

	loader_start = unpack(">L", patchable_fb[0x8:0xC])[0]

	(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack(">2sHLLL", patchable_fb[loader_start:loader_start + 16])
	print(f"Found {loader_name.decode()} {loader_ver} with size 0x{loader_size:08X} at 0x{loader_start:08X}")
	fb_cba = patchable_fb[loader_start:loader_start + loader_size]
	fb_cba_start = loader_start
	loader_start += loader_size

	(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack(">2sHLLL", patchable_fb[loader_start:loader_start + 16])
	print(f"Found {loader_name.decode()} {loader_ver} with size 0x{loader_size:08X} at 0x{loader_start:08X}")
	fb_cbb = patchable_fb[loader_start:loader_start + loader_size]
	fb_cbb_start = loader_start
	loader_start += loader_size

	if xell_not_found:
		print("Looking for XDK BL")
		(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack(">2sHLLL", patchable_fb[loader_start:loader_start + 16])
		loader_start += loader_size
		if loader_name.decode() != "SC":
			print("Not an XDK image, aborting...")
			return
		print("XDK image found, changing patching method")
		#Get SD
		(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack(">2sHLLL", patchable_fb[loader_start:loader_start + 16])
		loader_start += loader_size
		#Get SE
		(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack(">2sHLLL", patchable_fb[loader_start:loader_start + 16])
		loader_start += loader_size
		new_page = loader_start // 0x200
		if (loader_start % 0x200 != 0):
			new_page += 1
		#Adding 4 pages
		new_page += 4
		if fb_with_ecc:
			new_address = new_page * 0x210
			patchable_fb = fb[:new_address]
			patchable_fb = ecc_utils.unecc(patchable_fb)
		else:
			new_address = new_page * 0x200
			patchable_fb = fb[:new_address]

	print("\nPatching SMC")
	patchable_fb = patchable_fb[:rgh3_smc_start] + rgh3_smc + patchable_fb[rgh3_smc_start + rgh3_smc_len:]


	print("\nDecrypting CB")
	plain_fb_cba = decrypt_cba(fb_cba, _1BL_KEY)
	fb_cbb = decrypt_cbb(fb_cbb, plain_fb_cba, cpukey)
	if fb_cbb[0x392:0x39A] not in [b"XBOX_ROM", b"\x00" * 8]:
		print("CB_B decryption error (wrong CPU key?), aborting...")
		return

	print("\nPatching CB")
	original_size = len(patchable_fb)
	new_cbb = rgh3_payload + fb_cbb
	patchable_fb = patchable_fb[:fb_cba_start] + rgh3_cba + new_cbb + patchable_fb[fb_cbb_start + len(fb_cbb):]
	new_size = len(patchable_fb)
	print(f"I had to remove 0x{new_size - original_size:02X} bytes after CE to make it fit.")
	patchable_fb = patchable_fb[:original_size]

	print("\nMerging image")
	if fb_with_ecc:
		patchable_fb = ecc_utils.addecc(patchable_fb, block_type=block_type)
	fb = patchable_fb + fb[len(patchable_fb):]

	args.outfile.write(fb)
	args.outfile.close()

	print("\nDone!")

if __name__ == "__main__":
	main()