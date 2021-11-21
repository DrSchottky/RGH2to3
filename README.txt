RGH2 to 3 by DrSchottky

Usage: 2to3.exe RGH3_ECC.bin updflash.bin CPUKEY outfile.bin

Known bugs:
- Xell is broken
- Bad blocks <= 0x580 have to be manually remapped
- Supports only BBoS Spare data format
- Misc

Credits:
- 15432 for RGH3
- build.py creators for ECC code


python.exe 2to3.py RGH3_ECC.bin updflash.bin CPUKEY outfile.bin