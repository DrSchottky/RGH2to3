#!/usr/bin/env python3

from enum import Enum
from io import BytesIO
from struct import pack, unpack
from argparse import ArgumentParser

class BLOCK_TYPE(Enum):
	SMALL = 0x0
	BIG_ON_SMALL = 0x1
	BIG = 0x02

def calcecc(data: bytes | bytearray) -> bytes:
	assert len(data) == 0x210
	val = 0
	for i in range(0x1066):
		if not i & 31:
			v = ~unpack("<L", data[i // 8:(i // 8) + 4])[0]
		val ^= v & 1
		v >>= 1
		if val & 1:
			val ^= 0x6954559
		val >>= 1
	val = ~val
	return data[:-4] + pack("<L", (val << 6) & 0xFFFFFFFF)

def addecc(data: bytes | bytearray, block: int = 0, off_8: bytes | bytearray = b"\x00" * 4, block_type: BLOCK_TYPE = BLOCK_TYPE.BIG_ON_SMALL):
	res = b""
	while len(data):
		d = (data[:0x200] + b"\x00" * 0x200)[:0x200]
		data = data[0x200:]

		if block_type == BLOCK_TYPE.BIG_ON_SMALL:
			d += pack("<BL3B4s4s", 0, block // 32, 0xFF, 0, 0, off_8, b"\x00" * 4)
		elif block_type == BLOCK_TYPE.BIG:
			d += pack("<BL3B4s4s", 0xFF, block // 256, 0, 0, 0, off_8, b"\x00" * 4)
		elif block_type == BLOCK_TYPE.SMALL:
			d += pack("<L4B4s4s", block // 32, 0, 0xFF, 0, 0, off_8, b"\x00" * 4)
		else:
			raise ValueError("Block type not supported")
		d = calcecc(d)
		block += 1
		res += d
	return res

def unecc(image: bytes | bytearray) -> bytes:
	with (
		BytesIO(image) as rbio,
		BytesIO() as wbio
	):
		for i in range(len(image) // 528):
			wbio.write(rbio.read(512))
			rbio.seek(16, 1)  # skip 16 bytes
		return wbio.getvalue()

def verify(data: bytes | bytearray, block: int = 0, off_8: bytes | bytearray = b"\x00" * 4):
	while len(data):
		d = (data[:0x200] + b"\x00" * 0x200)[:0x200]
		d += pack("<L4B4s4s", block // 32, 0, 0xFF, 0, 0, off_8, b"\x00" * 4)
		d = calcecc(d)
		calc_ecc = d[0x200:]
		file_ecc = data[0x200:0x210]
		if calc_ecc != file_ecc:
			print(f"ECC mismatch on page 0x{block:02X} (0x{(block + 1) * 0x210 - 0x10:02X})")
			print(file_ecc)
			print(calc_ecc)
		block += 1
		data = data[0x210:]

def main() -> None:
	parser = ArgumentParser(description="", add_help=False)
	parser.add_argument("-u", "--unecc", action="store_true", help="UnECC an image")
	parser.add_argument("-e", "--ecc", action="store_true", help="ECC an image")
	parser.add_argument("-v", "--verify", action="store_true", help="Verify an image")
	parser.add_argument("infile", type=str, help="The image to work with")
	args = parser.parse_args()

	with open(args.infile, "rb") as f:
		image = f.read()

	if args.unecc:
		image = unecc(image)
		with open(args.infile + ".unecc", "wb") as f:
			f.write(image)
	elif args.ecc:
		image = addecc(image)
		with open(args.infile + ".ecc", "wb") as f:
			f.write(image)
	elif args.verify:
		verify(image)
	else:
		help()
		return

if __name__ == "__main__":
	main()