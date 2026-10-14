import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import hashlib
import json
import os
import platform
import datetime
import webbrowser
import ctypes
import pythoncom
import wmi

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# App settings
APP_SECRET = "MySuperSecretKey_ChangeMe_2024_HWID"
APP_NAME = "Whois ID"
APP_VERSION = "1.0.0"
APP_DEVELOPER = "t.me/IXIONTeam"


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# Hardware information
def get_wmi():
    return wmi.WMI()


def get_motherboard_info(c):
    mb = c.Win32_BaseBoard()[0]
    bios = c.Win32_BIOS()[0]
    return {
        "manufacturer": (mb.Manufacturer or "").strip(),
        "product": (mb.Product or "").strip(),
        "version": (mb.Version or "").strip(),
        "serial": (mb.SerialNumber or "").strip(),
        "bios_serial": (bios.SerialNumber or "").strip(),
    }


def get_cpu_info(c):
    cpu = c.Win32_Processor()[0]
    return {
        "name": (cpu.Name or "").strip(),
        "id": (cpu.ProcessorId or "").strip(),
        "cores": cpu.NumberOfCores,
        "threads": cpu.NumberOfLogicalProcessors,
        "max_clock": cpu.MaxClockSpeed,
    }


def get_ram_info(c):
    rams = []
    total = 0
    for ram in c.Win32_PhysicalMemory():
        size = int(ram.Capacity) if ram.Capacity else 0
        total += size
        rams.append({
            "manufacturer": (ram.Manufacturer or "").strip(),
            "part_number": (ram.PartNumber or "").strip(),
            "serial": (ram.SerialNumber or "").strip(),
            "capacity_gb": round(size / (1024 ** 3), 2),
            "speed": ram.Speed,
            "slot": (ram.DeviceLocator or "").strip(),
        })
    return {"modules": rams, "total_gb": round(total / (1024 ** 3), 2)}


def get_gpu_info(c):
    gpus = []
    for gpu in c.Win32_VideoController():
        gpus.append({
            "name": (gpu.Name or "").strip(),
            "driver": (gpu.DriverVersion or "").strip(),
            "vram_mb": round(int(gpu.AdapterRAM) / (1024 ** 2), 2) if gpu.AdapterRAM else None,
            "pnp_id": (gpu.PNPDeviceID or "").strip(),
        })
    return gpus


def get_disk_info(c):
    disks = []
    for disk in c.Win32_DiskDrive():
        disks.append({
            "model": (disk.Model or "").strip(),
            "serial": (disk.SerialNumber or "").strip(),
            "size_gb": round(int(disk.Size) / (1024 ** 3), 2) if disk.Size else None,
            "interface": (disk.InterfaceType or "").strip(),
            "pnp_id": (disk.PNPDeviceID or "").strip(),
        })
    return disks


# Build HWID from all major components
def build_hwid(cpu, ram, gpu, disks, mb):
    parts = []
    parts.append(
        f"MB|{mb['manufacturer']}:{mb['product']}:{mb.get('version', '')}:{mb['serial']}"
    )
    parts.append(f"CPU|{cpu['name']}|{cpu['id']}|{cpu['cores']}|{cpu['threads']}")

    ram_sig = sorted(
        f"{m['slot']}={m['manufacturer']}:{m['part_number']}:"
        f"{m['serial']}:{m['capacity_gb']}GB:{m['speed']}"
        for m in ram["modules"]
    )
    parts.append("RAM|" + "||".join(ram_sig) + f"|TOTAL={ram['total_gb']}")

    gpu_sig = sorted(f"{g['name']}:{g['pnp_id']}" for g in gpu)
    parts.append("GPU|" + "||".join(gpu_sig))

    disk_sig = sorted(
        f"{d['model']}:{d['serial']}:{d['size_gb']}GB:{d['pnp_id']}"
        for d in disks
    )
    parts.append("DISK|" + "||".join(disk_sig))

    raw = "#".join(parts)
    full = hashlib.sha256(raw.encode("utf-8")).hexdigest().upper()
    short = "-".join(full[i:i + 4] for i in range(0, 16, 4))
    return short, full, raw


def collect_hardware():
    c = get_wmi()
    mb = get_motherboard_info(c)
    cpu = get_cpu_info(c)
    ram = get_ram_info(c)
    gpu = get_gpu_info(c)
    disks = get_disk_info(c)
    short, full, raw = build_hwid(cpu, ram, gpu, disks, mb)
    return {
        "cpu": cpu, "ram": ram, "gpu": gpu,
        "disks": disks, "mb": mb,
        "hwid_short": short, "hwid_full": full, "raw": raw,
    }


# AES-256-GCM encryption for .db files
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_db(plaintext, password=APP_SECRET):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return salt + nonce + ciphertext


def decrypt_db(blob, password=APP_SECRET):
    if len(blob) < 28:
        raise ValueError("Invalid file")
    salt, nonce, ciphertext = blob[:16], blob[16:28], blob[28:]
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")


# Build rows for comparison table (motherboard first)
def build_comparison_rows(db_data, cur_data):
    rows = []

    def add(section, field, db_v, cur_v):
        match = (str(db_v) == str(cur_v))
        rows.append((section, field,
                     str(db_v) if db_v is not None else "-",
                     str(cur_v) if cur_v is not None else "-",
                     match))

    db_mb = db_data.get("mb") or {}
    cur_mb = cur_data.get("mb") or {}
    for f in ["manufacturer", "product", "version", "serial", "bios_serial"]:
        add("MB", f, db_mb.get(f), cur_mb.get(f))

    db_cpu = db_data.get("cpu") or {}
    cur_cpu = cur_data.get("cpu") or {}
    for f in ["name", "id", "cores", "threads", "max_clock"]:
        add("CPU", f, db_cpu.get(f), cur_cpu.get(f))

    db_ram = db_data.get("ram") or {}
    cur_ram = cur_data.get("ram") or {}
    add("RAM", "total_gb", db_ram.get("total_gb"), cur_ram.get("total_gb"))
    db_mods = sorted(db_ram.get("modules", []), key=lambda x: x.get("slot", ""))
    cur_mods = sorted(cur_ram.get("modules", []), key=lambda x: x.get("slot", ""))
    for i in range(max(len(db_mods), len(cur_mods))):
        db_m = db_mods[i] if i < len(db_mods) else {}
        cur_m = cur_mods[i] if i < len(cur_mods) else {}
        for f in ["slot", "manufacturer", "part_number", "serial", "capacity_gb", "speed"]:
            add(f"RAM[{i}]", f, db_m.get(f), cur_m.get(f))

    db_gpus = sorted(db_data.get("gpu") or [], key=lambda x: str(x.get("name", "")))
    cur_gpus = sorted(cur_data.get("gpu") or [], key=lambda x: str(x.get("name", "")))
    for i in range(max(len(db_gpus), len(cur_gpus))):
        db_g = db_gpus[i] if i < len(db_gpus) else {}
        cur_g = cur_gpus[i] if i < len(cur_gpus) else {}
        for f in ["name", "driver", "vram_mb", "pnp_id"]:
            add(f"GPU[{i}]", f, db_g.get(f), cur_g.get(f))

    db_disks = sorted(db_data.get("disks") or [], key=lambda x: str(x.get("model", "")))
    cur_disks = sorted(cur_data.get("disks") or [], key=lambda x: str(x.get("model", "")))
    for i in range(max(len(db_disks), len(cur_disks))):
        db_d = db_disks[i] if i < len(db_disks) else {}
        cur_d = cur_disks[i] if i < len(cur_disks) else {}
        for f in ["model", "serial", "size_gb", "interface", "pnp_id"]:
            add(f"DISK[{i}]", f, db_d.get(f), cur_d.get(f))

    add("HWID", "short", db_data.get("hwid_short"), cur_data.get("hwid_short"))
    add("HWID", "full", db_data.get("hwid_full"), cur_data.get("hwid_full"))

    return rows


# Build single-column rows for preview table
def build_preview_rows(db_data):
    rows = []

    def add(section, field, value):
        rows.append((section, field, str(value) if value is not None else "-"))

    mb = db_data.get("mb") or {}
    for f in ["manufacturer", "product", "version", "serial", "bios_serial"]:
        add("MB", f, mb.get(f))

    cpu = db_data.get("cpu") or {}
    for f in ["name", "id", "cores", "threads", "max_clock"]:
        add("CPU", f, cpu.get(f))

    ram = db_data.get("ram") or {}
    add("RAM", "total_gb", ram.get("total_gb"))
    for i, m in enumerate(ram.get("modules", [])):
        for f in ["slot", "manufacturer", "part_number", "serial", "capacity_gb", "speed"]:
            add(f"RAM[{i}]", f, m.get(f))

    for i, g in enumerate(db_data.get("gpu") or []):
        for f in ["name", "driver", "vram_mb", "pnp_id"]:
            add(f"GPU[{i}]", f, g.get(f))

    for i, d in enumerate(db_data.get("disks") or []):
        for f in ["model", "serial", "size_gb", "interface", "pnp_id"]:
            add(f"DISK[{i}]", f, d.get(f))

    add("HWID", "short", db_data.get("hwid_short"))
    add("HWID", "full", db_data.get("hwid_full"))

    return rows


# Apply consistent classic style to a Treeview
def setup_tree_style(name):
    style = ttk.Style()
    try:
        style.theme_use("winnative")
    except Exception:
        style.theme_use("clam")

    style.configure(
        f"{name}.Treeview",
        background="#FFFFFF",
        foreground="#000000",
        fieldbackground="#FFFFFF",
        rowheight=24,
        borderwidth=1,
        font=("Tahoma", 9),
    )
    style.configure(
        f"{name}.Treeview.Heading",
        background="#E0E0E0",
        foreground="#000000",
        font=("Tahoma", 9, "bold"),
        relief="raised",
    )
    style.map(f"{name}.Treeview.Heading", background=[("active", "#D0D0D0")])
    style.map(
        f"{name}.Treeview",
        background=[("selected", "#000080")],
        foreground=[("selected", "#FFFFFF")],
    )


class ComparisonWindow(tk.Toplevel):
    def __init__(self, parent, rows, db_info, cur_info):
        super().__init__(parent)
        self.title("Sync Report")
        self.geometry("1000x640")
        self.configure(bg="#F0F0F0")
        self.minsize(850, 480)

        tk.Label(
            self, text="System vs Database Comparison",
            font=("Tahoma", 11, "bold"),
            bg="#F0F0F0", fg="#000000"
        ).pack(pady=(10, 4))

        matches = sum(1 for r in rows if r[4])
        total = len(rows)
        diffs = total - matches

        summary = tk.Frame(self, bg="#F0F0F0", relief="groove", bd=1)
        summary.pack(fill="x", padx=10, pady=6)
        info = tk.Frame(summary, bg="#F0F0F0")
        info.pack(fill="x", padx=10, pady=6)

        tk.Label(
            info, text=f"Database HWID : {db_info.get('hwid_short', '?')}",
            font=("Tahoma", 9), bg="#F0F0F0", fg="#000000"
        ).pack(anchor="w")
        tk.Label(
            info, text=f"System HWID   : {cur_info.get('hwid_short', '?')}",
            font=("Tahoma", 9), bg="#F0F0F0", fg="#000000"
        ).pack(anchor="w")
        tk.Label(
            info, text=f"Matched: {matches} of {total}   |   Differences: {diffs}",
            font=("Tahoma", 9, "bold"), bg="#F0F0F0",
            fg="#006600" if diffs == 0 else "#990000"
        ).pack(anchor="w", pady=(4, 0))

        table = tk.Frame(self, bg="#F0F0F0")
        table.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        setup_tree_style("Classic")
        self.tree = ttk.Treeview(
            table, columns=("section", "field", "db_value", "sys_value"),
            show="headings", style="Classic.Treeview"
        )
        for col, txt, w in [
            ("section", "Section", 100),
            ("field", "Field", 140),
            ("db_value", "Database Value", 370),
            ("sys_value", "System Value", 370),
        ]:
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w,
                             anchor="center" if col in ("section", "field") else "w")

        vsb = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(0, weight=1)

        self.tree.tag_configure("match", background="#E8F5E8", foreground="#004400")
        self.tree.tag_configure("diff", background="#FFE8E8", foreground="#880000")
        self.tree.tag_configure(
            "section_header", background="#D4D0C8",
            foreground="#000080", font=("Tahoma", 9, "bold")
        )

        current_section = None
        for section, field, db_v, sys_v, match in rows:
            if section != current_section:
                self.tree.insert("", "end", values=(section, "", "", ""),
                                 tags=("section_header",))
                current_section = section
            self.tree.insert("", "end", values=(section, field, db_v, sys_v),
                             tags=("match" if match else "diff",))

        bottom = tk.Frame(self, bg="#F0F0F0")
        bottom.pack(fill="x", side="bottom", pady=8)

        overall_ok = (diffs == 0)
        tk.Label(
            bottom,
            text="This system MATCHES the database." if overall_ok
            else f"This system does NOT match - {diffs} differences.",
            font=("Tahoma", 10, "bold"),
            bg="#F0F0F0", fg="#006600" if overall_ok else "#990000"
        ).pack(side="left", padx=15)

        tk.Button(
            bottom, text="Close", font=("Tahoma", 10),
            bg="#D4D0C8", fg="#000000", activebackground="#C0C0C0",
            relief="raised", bd=2, padx=30, pady=6,
            cursor="hand2", command=self.destroy
        ).pack(side="right", padx=15)


class PreviewWindow(tk.Toplevel):
    def __init__(self, parent, rows, db_info, file_path):
        super().__init__(parent)
        self.title("Database Preview")
        self.geometry("900x640")
        self.configure(bg="#F0F0F0")
        self.minsize(760, 480)

        tk.Label(
            self, text="Database File Preview",
            font=("Tahoma", 11, "bold"),
            bg="#F0F0F0", fg="#000000"
        ).pack(pady=(10, 4))

        summary = tk.Frame(self, bg="#F0F0F0", relief="groove", bd=1)
        summary.pack(fill="x", padx=10, pady=6)
        info = tk.Frame(summary, bg="#F0F0F0")
        info.pack(fill="x", padx=10, pady=6)

        for text, font, fg in [
            (f"File       : {os.path.basename(file_path)}", ("Tahoma", 9), "#000000"),
            (f"Version    : {db_info.get('version', '?')}", ("Tahoma", 9), "#000000"),
            (f"HWID Short : {db_info.get('hwid_short', '?')}", ("Tahoma", 9, "bold"), "#000080"),
            (f"HWID Full  : {db_info.get('hwid_full', '?')}", ("Tahoma", 8), "#404040"),
            (f"Created At : {db_info.get('created_at', '?')}", ("Tahoma", 9), "#000000"),
            (f"Total fields: {len(rows)}", ("Tahoma", 9, "bold"), "#006600"),
        ]:
            tk.Label(info, text=text, font=font,
                     bg="#F0F0F0", fg=fg).pack(anchor="w")

        table = tk.Frame(self, bg="#F0F0F0")
        table.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        setup_tree_style("Preview")
        self.tree = ttk.Treeview(
            table, columns=("section", "field", "value"),
            show="headings", style="Preview.Treeview"
        )
        for col, txt, w in [
            ("section", "Section", 120),
            ("field", "Field", 170),
            ("value", "Value", 560),
        ]:
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w,
                             anchor="center" if col in ("section", "field") else "w")

        vsb = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(0, weight=1)

        self.tree.tag_configure("row_even", background="#FFFFFF", foreground="#000000")
        self.tree.tag_configure("row_odd", background="#F8F8F8", foreground="#000000")
        self.tree.tag_configure(
            "section_header", background="#D4D0C8",
            foreground="#000080", font=("Tahoma", 9, "bold")
        )

        current_section = None
        row_idx = 0
        for section, field, value in rows:
            if section != current_section:
                self.tree.insert("", "end", values=(section, "", ""),
                                 tags=("section_header",))
                current_section = section
                row_idx = 0
            self.tree.insert("", "end", values=(section, field, value),
                             tags=("row_even" if row_idx % 2 == 0 else "row_odd",))
            row_idx += 1

        bottom = tk.Frame(self, bg="#F0F0F0")
        bottom.pack(fill="x", side="bottom", pady=8)
        tk.Button(
            bottom, text="Close", font=("Tahoma", 10),
            bg="#D4D0C8", fg="#000000", activebackground="#C0C0C0",
            relief="raised", bd=2, padx=30, pady=6,
            cursor="hand2", command=self.destroy
        ).pack(side="right", padx=15)


class AboutWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("About")
        self.configure(bg="#F0F0F0")
        self.resizable(False, False)
        self.transient(parent)

        w, h = 260, 180
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - w) // 2
        y = parent.winfo_y() + (parent.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

        tk.Label(
            self, text=APP_NAME,
            font=("Tahoma", 11, "bold"),
            bg="#F0F0F0", fg="#000080"
        ).pack(pady=(18, 4))

        tk.Label(
            self, text=f"Version {APP_VERSION}",
            font=("Tahoma", 9), bg="#F0F0F0", fg="#404040"
        ).pack()

        tk.Frame(self, bg="#A0A0A0", height=1).pack(fill="x", padx=20, pady=10)

        tk.Label(
            self, text="Developed by",
            font=("Tahoma", 8), bg="#F0F0F0", fg="#606060"
        ).pack()

        link = tk.Label(
            self, text=APP_DEVELOPER,
            font=("Tahoma", 9, "bold", "underline"),
            bg="#F0F0F0", fg="#006600", cursor="hand2"
        )
        link.pack(pady=(1, 0))
        link.bind("<Button-1>", lambda e: self.open_link())

        tk.Button(
            self, text="Close", font=("Tahoma", 8),
            bg="#D4D0C8", fg="#000000", activebackground="#C0C0C0",
            relief="raised", bd=2, padx=20, pady=2,
            cursor="hand2", command=self.destroy
        ).pack(pady=(14, 0))

    def open_link(self):
        url = APP_DEVELOPER.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        webbrowser.open(url)


class App:
    def __init__(self, root):
        self.root = root

        title = APP_NAME
        if is_admin():
            title += "  [Administrator]"
        self.root.title(title)
        self.root.geometry("1240x720")
        self.root.configure(bg="#F0F0F0")
        self.root.minsize(1180, 620)

        self.hwid_short = ""
        self.hardware_data = None

        # Top toolbar: action buttons + info button
        top = tk.Frame(root, bg="#F0F0F0")
        top.pack(fill="x", padx=10, pady=(12, 10))

        btns = tk.Frame(top, bg="#F0F0F0")
        btns.pack(side="left", fill="x", expand=True)

        self.scan_btn = self._btn(btns, "Scan Hardware", self.scan)
        self.copy_btn = self._btn(btns, "Copy HWID", self.copy_hwid, state="disabled")
        self.save_btn = self._btn(btns, "Save Report", self.save_file, state="disabled")
        self.export_btn = self._btn(btns, "Export DB", self.export_db, state="disabled")
        self.sync_btn = self._btn(btns, "Sync DB", self.sync_db)
        self.preview_btn = self._btn(btns, "Preview DB", self.preview_db)

        tk.Button(
            top, text="i", font=("Tahoma", 10, "bold"),
            bg="#D4D0C8", fg="#000080",
            activebackground="#C0C0C0", activeforeground="#000080",
            relief="raised", bd=2, width=3, pady=6,
            cursor="hand2", command=lambda: AboutWindow(self.root)
        ).pack(side="right", padx=(8, 0))

        # HWID display box
        hwid_frame = tk.Frame(root, bg="#F0F0F0", relief="groove", bd=1)
        hwid_frame.pack(fill="x", padx=10, pady=4)

        tk.Label(
            hwid_frame, text="HWID:",
            font=("Tahoma", 11, "bold"),
            bg="#F0F0F0", fg="#000000"
        ).pack(side="left", padx=(14, 8), pady=12)

        self.hwid_var = tk.StringVar(value="-")
        tk.Label(
            hwid_frame, textvariable=self.hwid_var,
            font=("Courier New", 13, "bold"),
            bg="#F0F0F0", fg="#000080"
        ).pack(side="left", padx=4, pady=12)

        # Output console
        text_frame = tk.Frame(root, bg="#F0F0F0")
        text_frame.pack(fill="both", expand=True, padx=10, pady=(4, 8))

        box = tk.Frame(text_frame, relief="sunken", bd=2, bg="#FFFFFF")
        box.pack(fill="both", expand=True)

        self.output = scrolledtext.ScrolledText(
            box, font=("Courier New", 10),
            bg="#FFFFFF", fg="#000000",
            insertbackground="#000000",
            relief="flat", bd=0,
            padx=8, pady=8, wrap="word"
        )
        self.output.pack(fill="both", expand=True)

        self.output.tag_config("title", foreground="#000080",
                               font=("Courier New", 10, "bold"))
        self.output.tag_config("key", foreground="#404040")
        self.output.tag_config("value", foreground="#000000")
        self.output.tag_config("hwid", foreground="#006600",
                               font=("Courier New", 11, "bold"))
        self.output.tag_config("ok", foreground="#006600",
                               font=("Courier New", 10, "bold"))
        self.output.tag_config("fail", foreground="#990000",
                               font=("Courier New", 10, "bold"))
        self.output.tag_config("warn", foreground="#806000")

        # Status bar
        status_frame = tk.Frame(root, relief="sunken", bd=1, bg="#F0F0F0")
        status_frame.pack(fill="x", side="bottom")

        initial_status = "Ready" + ("  (Running as Administrator)" if is_admin() else "")
        self.status_var = tk.StringVar(value=initial_status)
        tk.Label(
            status_frame, textvariable=self.status_var,
            font=("Tahoma", 9), bg="#F0F0F0", fg="#000000",
            anchor="w", padx=8
        ).pack(fill="x", ipady=3)

    def _btn(self, parent, text, command, state="normal"):
        btn = tk.Button(
            parent, text=text, font=("Tahoma", 10, "bold"),
            bg="#D4D0C8", fg="#000000",
            activebackground="#C0C0C0", activeforeground="#000000",
            relief="raised", bd=2, padx=16, pady=8,
            state=state, cursor="hand2", command=command
        )
        btn.pack(side="left", padx=3)
        return btn

    def line(self, text, tag=None):
        self.output.insert("end", text + "\n", tag)

    def scan(self):
        self.scan_btn.config(state="disabled", text="Scanning...")
        self.status_var.set("Reading hardware information...")
        self.output.delete("1.0", "end")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        # WMI requires COM initialization in this thread
        pythoncom.CoInitialize()
        try:
            data = collect_hardware()
            self.hardware_data = data
            self.root.after(0, lambda: self.show_results(data))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror(
                "Error", f"Failed to read hardware info:\n{e}"))
            self.root.after(0, lambda: self.scan_btn.config(
                state="normal", text="Scan Hardware"))
        finally:
            pythoncom.CoUninitialize()

    def show_results(self, d):
        self.output.delete("1.0", "end")
        cpu, ram, gpu, disks, mb = d["cpu"], d["ram"], d["gpu"], d["disks"], d["mb"]

        self.line("===  Motherboard  ===", "title")
        self.line(f"  Manufacturer : {mb['manufacturer']}", "value")
        self.line(f"  Model        : {mb['product']}", "value")
        self.line(f"  Version      : {mb.get('version', '-')}", "value")
        self.line(f"  Serial       : {mb['serial']}", "key")
        self.line(f"  BIOS Serial  : {mb['bios_serial']}", "key")
        self.line("")

        self.line("===  CPU  ===", "title")
        self.line(f"  Name     : {cpu['name']}", "value")
        self.line(f"  CPU ID   : {cpu['id']}", "value")
        self.line(f"  Cores    : {cpu['cores']}   Threads: {cpu['threads']}", "value")
        self.line(f"  Max MHz  : {cpu['max_clock']}", "value")
        self.line("")

        self.line("===  RAM  ===", "title")
        self.line(f"  Total    : {ram['total_gb']} GB  ({len(ram['modules'])} module(s))", "value")
        for i, m in enumerate(ram["modules"], 1):
            self.line(f"  [{i}] {m['slot']}: {m['manufacturer']} {m['part_number']}", "value")
            self.line(f"       {m['capacity_gb']}GB @ {m['speed']}MHz  SN: {m['serial']}", "key")
        self.line("")

        self.line("===  GPU  ===", "title")
        for i, g in enumerate(gpu, 1):
            self.line(f"  [{i}] {g['name']}", "value")
            self.line(f"       Driver: {g['driver']}  VRAM: {g['vram_mb']}MB", "key")
        self.line("")

        self.line("===  Disks  ===", "title")
        for i, dk in enumerate(disks, 1):
            self.line(f"  [{i}] {dk['model']}", "value")
            self.line(f"       {dk['size_gb']}GB  {dk['interface']}  SN: {dk['serial']}", "key")
        self.line("")

        self.line("===  HWID  ===", "title")
        self.line(f"  {d['hwid_short']}", "hwid")
        self.line(f"  Full: {d['hwid_full']}", "key")
        self.line("")
        self.line(f"  OS: {platform.system()} {platform.release()} ({platform.version()})", "key")
        if is_admin():
            self.line("  Access: Administrator", "ok")
        else:
            self.line("  Access: Standard User", "warn")

        self.hwid_short = d["hwid_short"]
        self.hwid_var.set(d["hwid_short"])
        self.copy_btn.config(state="normal")
        self.save_btn.config(state="normal")
        self.export_btn.config(state="normal")
        self.scan_btn.config(state="normal", text="Rescan")
        self.status_var.set(
            "Scan completed successfully" +
            ("  (Running as Administrator)" if is_admin() else "")
        )

    def copy_hwid(self):
        if not self.hwid_short:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.hwid_short)
        self.status_var.set("HWID copied to clipboard")
        messagebox.showinfo("Copied", f"HWID copied:\n\n{self.hwid_short}")

    def save_file(self):
        if not self.hwid_short:
            messagebox.showwarning("Warning", "Please scan first!")
            return

        path = filedialog.asksaveasfilename(
            title="Save Report",
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            initialfile=f"hwid_report_{self.hwid_short.replace('-', '')}.txt"
        )
        if not path:
            self.status_var.set("Save cancelled")
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"HWID: {self.hwid_short}\n")
                f.write("=" * 60 + "\n\n")
                f.write(self.output.get("1.0", "end"))
            messagebox.showinfo("Saved", f"Report saved to:\n\n{path}")
            self.status_var.set(f"Report saved: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Save failed:\n{e}")
            self.status_var.set("Save error")

    def export_db(self):
        if not self.hardware_data:
            messagebox.showwarning("Warning", "Please scan first!")
            return

        path = filedialog.asksaveasfilename(
            title="Save Database File",
            defaultextension=".db",
            filetypes=[("HWID Database", "*.db"), ("All files", "*.*")],
            initialfile=f"hwid_{self.hwid_short.replace('-', '')}.db"
        )
        if not path:
            self.status_var.set("Export cancelled")
            return

        try:
            payload = {
                "version": 1,
                "hwid_short": self.hardware_data["hwid_short"],
                "hwid_full": self.hardware_data["hwid_full"],
                "raw_signature": self.hardware_data["raw"],
                "mb": self.hardware_data["mb"],
                "cpu": self.hardware_data["cpu"],
                "ram": self.hardware_data["ram"],
                "gpu": self.hardware_data["gpu"],
                "disks": self.hardware_data["disks"],
                "created_at": datetime.datetime.now().isoformat(),
            }
            blob = encrypt_db(json.dumps(payload, ensure_ascii=False, indent=2))

            with open(path, "wb") as f:
                f.write(blob)

            messagebox.showinfo(
                "Success",
                f"Encrypted database file created:\n\n{path}\n\n"
                f"HWID: {self.hardware_data['hwid_short']}"
            )
            self.status_var.set(f"Export created: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create file:\n{e}")

    def sync_db(self):
        path = filedialog.askopenfilename(
            title="Select Database File",
            filetypes=[("HWID Database", "*.db"), ("All files", "*.*")]
        )
        if not path:
            return

        self.output.delete("1.0", "end")
        self.line("Syncing...", "title")
        self.line(f"  File: {path}", "key")
        self.line("")

        try:
            with open(path, "rb") as f:
                db_data = json.loads(decrypt_db(f.read()))
        except Exception as e:
            self.line("File cannot be read or decrypted!", "fail")
            self.line(f"   Reason: {e}", "warn")
            messagebox.showerror("Error", f"Invalid file or wrong key:\n{e}")
            return

        self.line(f"  DB HWID : {db_data.get('hwid_short', '?')}", "key")
        self.line(f"  DB Date : {db_data.get('created_at', '?')}", "key")
        self.line("")

        self.status_var.set("Scanning current system for comparison...")
        self.root.update()

        pythoncom.CoInitialize()
        try:
            current = collect_hardware()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan current system:\n{e}")
            return
        finally:
            pythoncom.CoUninitialize()

        self.line(f"  Sys HWID: {current['hwid_short']}", "key")
        self.line("")

        rows = build_comparison_rows(db_data, current)
        matches = sum(1 for r in rows if r[4])
        diffs = len(rows) - matches

        self.line("===  Comparison Result  ===", "title")
        self.line(f"  Matched: {matches}", "ok")
        self.line(f"  Different: {diffs}", "fail" if diffs else "ok")
        self.line("")
        self.line("  Comparison table opened in new window.", "key")

        ComparisonWindow(self.root, rows, db_data, current)
        self.status_var.set("Full match" if diffs == 0 else f"{diffs} difference(s)")

    def preview_db(self):
        path = filedialog.askopenfilename(
            title="Select Database File for Preview",
            filetypes=[("HWID Database", "*.db"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            with open(path, "rb") as f:
                db_data = json.loads(decrypt_db(f.read()))
        except Exception as e:
            messagebox.showerror("Error", f"Invalid file or wrong key:\n{e}")
            return

        self.output.delete("1.0", "end")
        self.line("Database Preview", "title")
        self.line(f"  File: {path}", "key")
        self.line(f"  HWID: {db_data.get('hwid_short', '?')}", "hwid")
        self.line("")
        self.line("  Preview table opened in new window.", "key")

        PreviewWindow(self.root, build_preview_rows(db_data), db_data, path)
        self.status_var.set(f"Preview loaded: {os.path.basename(path)}")


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()