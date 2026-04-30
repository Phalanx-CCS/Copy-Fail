# CVE-2026-31431 – "Copy Fail" Reachability Checker

A simple, safe Python script that determines whether a Linux system is vulnerable to **CVE-2026-31431** ("Copy Fail"), a local privilege escalation that affects all major distributions since kernel 4.14.

---

## ⚠️ What is Copy Fail?

CVE-2026-31431 is a straight-line logic bug in the Linux kernel's `algif_aead` cryptographic socket module. By using `AF_ALG` sockets in combination with `splice()`, an unprivileged attacker can overwrite 4 bytes in the page cache of a setuid binary and gain root.

| Property | Detail |
|---|---|
| Race condition required | ❌ No – exploitation is deterministic |
| Kernel offsets required | ❌ No – no version-specific offsets needed |
| Exploit complexity | Single 732-byte Python script sufficient for root |
| This checker | Passive diagnostic only – does **not** trigger the vulnerability |

---

## 🔍 How This Checker Works

The script attempts to create and bind an `AF_ALG` socket using the exact algorithm template the vulnerability relies on:

```
authencesn(hmac(sha256),cbc(aes))
```

| Result | Meaning |
|---|---|
| Socket created and bound | Vulnerable code path **is reachable** – patch immediately |
| `EAFNOSUPPORT` (errno 97) | Module not loaded – attack surface **unavailable** |
| `Permission denied` | MAC policy (SELinux/AppArmor) blocks access – **safe** |

The script **does not** trigger the vulnerability in any way. It is completely passive and safe to run.

---

## 📦 Requirements

- **Python 3** (standard library only – no external modules required)
- Linux kernel (the check is meaningless on other platforms)
- **No root privileges required**

---

## 🚀 Usage

Clone the repository or download `check_copyfail.py`, then run:

```bash
python3 check_copyfail.py
```

### Example output

```
  ____                   _____     _ _
 / ___|___  _ __  _   _|  ___|_ _(_) |
| |   / _ \| '_ \| | | | |_ / _` | | |
| |__| (_) | |_) | |_| |  _| (_| | | |
 \____\___/| .__/ \__, |_|  \__,_|_|_|
           |_|    |___/

CVE-2026-31431 "Copy Fail" – Reachability Checker
Phalanx CCS / d_0_4  |  Defensive use only
-------------------------------------------------------

Kernel release:  6.1.0-28-amd64
Version range :  Potentially affected range
AF_ALG target :  authencesn(hmac(sha256),cbc(aes))

  [!!!] VULNERABLE ATTACK SURFACE REACHABLE
        Socket created and bound – AF_ALG reachable

  Immediate mitigation:
    echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif-aead.conf
    sudo rmmod algif_aead 2>/dev/null

  Then update your kernel as soon as patches are available.
  Upstream fix: commit a664bf3d603d
```

The script exits with code **`1`** if the attack surface is reachable, and **`0`** if the system is safe — making it suitable for use in shell scripts, Ansible playbooks, and CI pipelines.

---

## 🛡️ Immediate Mitigation

Until a kernel update is available, disable the vulnerable module:

```bash
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead.conf
sudo rmmod algif_aead 2>/dev/null
```

The official fix is commit **`a664bf3d603d`** in the mainline kernel. Update via your distribution's package manager as soon as patches are available.

---

## 📱 Android / Termux Note

This checker will always report safe on modern Android devices (including Termux). The `AF_ALG` socket is unavailable to unprivileged apps due to mandatory SELinux policies, so the vulnerability is not exploitable on standard Android builds.

---

## 📜 License

This project is licensed under the **MIT License** – see [`LICENSE`](LICENSE) for details. Feel free to use, modify, and distribute.

---

> **Disclaimer:** This tool is for defensive diagnostic purposes only.  
> Do not use it on systems you do not own or without explicit written permission.
