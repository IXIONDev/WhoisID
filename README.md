# Whois ID

A simple Windows tool to get hardware information, generate a HWID, and export encrypted `.db` files.

## Features

- Get motherboard, CPU, RAM, GPU, and disk information
- Generate a SHA-256-based HWID
- Copy HWID to clipboard
- Save hardware information as a `.txt` report
- Export encrypted `.db` files using AES-256-GCM
- Compare a saved database with the current system
- Preview `.db` files
- Simple Tkinter GUI

## Requirements

- Windows 10 / 11
- Python 3.10+

Install dependencies:

```bash
pip install wmi pywin32 cryptography
```

## Run

```bash
python whoisid.py
```

## Build

The project includes a PyInstaller spec file.

```bash
pyinstaller whoisid.spec
```

## Files

- `whoisid.py` — Main application
- `whoisid.spec` — PyInstaller build configuration

## How it works

Whois ID collects hardware information and uses selected hardware identifiers to generate a HWID.

The collected information includes:

- Motherboard: Manufacturer, product, version, serial
- CPU: Name, processor ID, cores, threads
- RAM: Slot, manufacturer, part number, serial, capacity, speed
- GPU: Name, PNP device ID
- Disks: Model, serial, size, PNP device ID

The HWID is designed to remain the same after reinstalling Windows, provided the hardware identifiers remain unchanged and available. Hardware changes or missing identifiers may change the result.

## Developer

**IXION Team**

Telegram: https://t.me/IXIONTeam

## Disclaimer

This tool is intended for hardware identification and system verification.