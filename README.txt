RGH2 to 3 by DrSchottky

Usage: 2to3.exe RGH3_ECC.bin updflash.bin CPUKEY outfile.bin

Known limitations:
- Bad Blocks before Xell (addr 0x70000, blocks 0x0-0x3 on BB, blocks 0x0-0x1B on SB) have to be manually remapped
- Misc


Credits:
- 15432 for RGH3
- build.py creators for ECC code


python.exe 2to3.py RGH3_ECC.bin updflash.bin CPUKEY outfile.bin