#!/usr/bin/env python3

# pip install PyInstaller
import PyInstaller.__main__

def main() -> None:
	PyInstaller.__main__.run([
		"2to3.py",
		"--onefile"
	])

if __name__ == "__main__":
	main()