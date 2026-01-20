# SecLite

**SecLite** adalah *Lightweight Network Security Scanner* berbasis Python yang digunakan untuk melakukan **port scanning**, **service enumeration**, dan **deteksi kerentanan dasar** menggunakan Nmap dan Scapy.

> ⚠️ **Peringatan**: Gunakan tool ini **hanya pada jaringan milik sendiri atau dengan izin resmi**.

---

## ✨ Fitur Utama

* 🔍 Port scanning (TCP)
* 🧭 Service & version detection
* 🚨 Real-time alert (severity: INFO – CRITICAL)
* 🛡 Deteksi vulnerability dasar (FTP, Telnet)
* 📄 Report otomatis dalam format JSON
* 🐧 Optimal di Linux (Ubuntu / Kali / Parrot)

---

## 🛠️ Requirement

### Sistem

* Linux (disarankan)
* Python 3.8+
* Nmap
* Akses `sudo` (untuk ARP scan & OS detection)

### Python Dependencies

* `python-nmap`
* `scapy`

---

## 📦 Instalasi

### 1️⃣ Install Nmap (System)

```bash
sudo apt update
sudo apt install nmap
```

Cek:

```bash
nmap --version
```

---

### 2️⃣ Install Python Dependencies

```bash
pip3 install python-nmap scapy
```

Atau (jika permission error):

```bash
sudo pip3 install python-nmap scapy
```

---

### 3️⃣ Download / Buat File

Simpan source code sebagai:

```bash
seclite.py
```

Beri permission executable (opsional):

```bash
chmod +x seclite.py
```

---

## 🚀 Cara Menjalankan

> ⚠️ **Disarankan menggunakan `sudo`**

### 🔹 Scan Basic (Single Host)

```bash
sudo python3 seclite.py -t 192.168.1.1
```

atau:

```bash
sudo ./seclite.py -t 192.168.1.1
```

---

### 🔹 Scan dengan Custom Port Range

```bash
sudo python3 seclite.py -t 192.168.1.1 -p 1-65535
```

---

### 🔹 Scan Network Range (LAN)

```bash
sudo python3 seclite.py -t 192.168.1.0/24
```

---

### 🔹 Custom Output File

```bash
sudo python3 seclite.py -t scanme.nmap.org -o my_report.json
```

---

## 📄 Output

### Terminal

* Alert real-time dengan level severity
* Informasi open port & service

### File Report (JSON)

Contoh:

```json
{
  "scan_info": {
    "target": "192.168.1.1",
    "timestamp": "2026-01-20T14:22:33"
  },
  "open_ports": [],
  "services": [],
  "vulnerabilities": [],
  "alerts": []
}
```

---

## ❗ Troubleshooting

### ❌ `nmap program was not found in path`

Pastikan Nmap terinstall:

```bash
which nmap
```

Jika perlu:

```bash
sudo apt install nmap
```

---

### ❌ `ModuleNotFoundError: No module named 'nmap'`

```bash
pip3 install python-nmap
```

---

### ❌ Permission Error

Gunakan `sudo`:

```bash
sudo python3 seclite.py -t <target>
```

---

## 🔐 Catatan Keamanan

* Jangan scan jaringan publik tanpa izin
* Gunakan untuk:

  * Lab sendiri
  * VM (Metasploitable, DVWA)
  * Jaringan internal

---

## 📌 Roadmap (Pengembangan)

* [ ] Multi-threading scan
* [ ] HTML Report
* [ ] CVE-based vulnerability detection
* [ ] Export ke CSV / PDF
* [ ] SSH brute-force detection (passive)

---

## 👨‍💻 Author

**SecLite** – Educational Network Security Tool

---

> 🚀 Cocok untuk belajar **Network Security**, **NOC**, dan **Pentesting dasar**
