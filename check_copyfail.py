#!/usr/bin/env python3
"""
check_copyfail.py – CVE-2026-31431 ("Copy Fail") Reachability Checker
----------------------------------------------------------------------
Passively determines whether the algif_aead AF_ALG attack surface
is reachable on this kernel. Does NOT trigger or exploit the vulnerability.

Author  : Phalanx CCS / Grendel
License : MIT
"""

import sys
import socket
import errno
import platform

# ---------------------------------------------------------------------------
# AF_ALG constants (not exposed in Python's socket module by default)
# ---------------------------------------------------------------------------
AF_ALG = 38

# The exact algorithm template the vulnerability relies on.
# CVE-2026-31431 abuses the in-place AEAD optimization introduced in the
# algif_aead module (commit merged August 2017) to land a 4-byte controlled
# write into the page cache of any readable file without owning it.
VULNERABLE_SALG_TYPE = "aead"
VULNERABLE_SALG_NAME = "authencesn(hmac(sha256),cbc(aes))"

# ---------------------------------------------------------------------------
# Colour helpers (degrade gracefully if stdout is not a tty)
# ---------------------------------------------------------------------------
_USE_COLOUR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

RED    = lambda t: _c("31;1", t)
GREEN  = lambda t: _c("32;1", t)
YELLOW = lambda t: _c("33;1", t)
CYAN   = lambda t: _c("36;1", t)
BOLD   = lambda t: _c("1",    t)

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def check_platform() -> None:
    """Abort early on non-Linux systems."""
    if platform.system() != "Linux":
        print(YELLOW("[~] Non-Linux platform detected – this check is Linux-only."))
        sys.exit(0)

def get_kernel_version() -> str:
    return platform.release()

def parse_kernel_version(release: str):
    """Return (major, minor, patch) integers from a kernel release string."""
    parts = release.split("-")[0].split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return major, minor, patch
    except ValueError:
        return 0, 0, 0

def check_kernel_range(release: str) -> bool:
    """
    CVE-2026-31431 affects kernels >= 4.14 (algif_aead in-place opt introduced
    August 2017) up to but not including the patched versions.
    Patch commit: a664bf3d603d (targeting 6.8.x / 6.6.x LTS / 6.1.x LTS).
    Returns True if the kernel falls in the potentially affected range.
    """
    major, minor, _ = parse_kernel_version(release)
    return (major, minor) >= (4, 14)

# ---------------------------------------------------------------------------
# Core reachability probe
# ---------------------------------------------------------------------------

def probe_af_alg() -> dict:
    """
    Attempt to create an AF_ALG socket and bind it to the specific algorithm
    template that CVE-2026-31431 relies on.

    CPython's AF_ALG socket.bind() expects a 4-tuple:
        (type: str, name: str, feat: int, mask: int)
    It handles sockaddr_alg struct packing internally.

    Returns a result dict:
        reachable  (bool)     – True if the attack surface is accessible
        reason     (str)      – Human-readable explanation
        errno_val  (int|None) – errno from the failing syscall, if any
    """
    result = {"reachable": False, "reason": "", "errno_val": None}

    # --- Step 1: create the AF_ALG socket ---
    try:
        fd = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    except OSError as e:
        result["errno_val"] = e.errno
        if e.errno == errno.EAFNOSUPPORT:
            result["reason"] = "AF_ALG not supported – kernel module not loaded"
        elif e.errno == errno.EPERM:
            result["reason"] = "Permission denied creating AF_ALG socket (MAC policy active)"
        else:
            result["reason"] = f"Socket creation failed (errno {e.errno}: {e.strerror})"
        return result

    # --- Step 2: bind to the vulnerable algorithm template ---
    try:
        fd.bind((VULNERABLE_SALG_TYPE, VULNERABLE_SALG_NAME, 0, 0))
        result["reachable"] = True
        result["reason"] = (
            f"Bound to {VULNERABLE_SALG_TYPE}/{VULNERABLE_SALG_NAME} – "
            "vulnerable algorithm reachable by unprivileged user"
        )
    except OSError as e:
        result["errno_val"] = e.errno
        if e.errno in (errno.ENOENT, errno.ENODEV, errno.EINVAL):
            result["reason"] = f"Algorithm unavailable on bind (errno {e.errno}: {e.strerror})"
        elif e.errno == errno.EACCES:
            result["reason"] = "Bind denied by MAC policy (SELinux/AppArmor)"
        else:
            result["reason"] = f"Bind failed (errno {e.errno}: {e.strerror})"
    finally:
        try:
            fd.close()
        except Exception:
            pass

    return result

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

BANNER = r"""
  ____                   _____     _ _ 
 / ___|___  _ __  _   _|  ___|_ _(_) |
| |   / _ \| '_ \| | | | |_ / _` | | |
| |__| (_) | |_) | |_| |  _| (_| | | |
 \____\___/| .__/ \__, |_|  \__,_|_|_|
           |_|    |___/                
"""

def print_banner() -> None:
    print(CYAN(BANNER))
    print(BOLD("CVE-2026-31431 \"Copy Fail\" – Reachability Checker"))
    print(BOLD("Phalanx CCS / d_0_4  |  Defensive use only"))
    print("-" * 55)

def print_report(kernel: str, in_range: bool, probe: dict) -> None:
    print(f"\n{BOLD('Kernel release:')} {kernel}")
    range_label = (
        YELLOW("Potentially affected range")
        if in_range
        else GREEN("Outside documented affected range")
    )
    print(f"{BOLD('Version range : ')} {range_label}")
    print(f"{BOLD('AF_ALG target : ')} {VULNERABLE_SALG_NAME}")
    print()

    if probe["reachable"]:
        print(RED("  [!!!] VULNERABLE ATTACK SURFACE REACHABLE"))
        print(f"        {probe['reason']}")
        print()
        print(YELLOW("  Immediate mitigation:"))
        print("    echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif-aead.conf")
        print("    sudo rmmod algif_aead 2>/dev/null")
        print()
        print(YELLOW("  Then update your kernel as soon as patches are available."))
        print(YELLOW("  Upstream fix: commit a664bf3d603d"))
    else:
        print(GREEN("  [OK] AF_ALG attack surface NOT reachable"))
        print(f"       Reason : {probe['reason']}")
        if probe["errno_val"] is not None:
            print(f"       errno  : {probe['errno_val']}")
        print()
        print(GREEN("  System appears SAFE from CVE-2026-31431 via this vector."))

    print()
    print("-" * 55)
    print(BOLD("Disclaimer:") + " Diagnostic only. Run only on systems you own or")
    print("have explicit written permission to test.")
    print()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    print_banner()
    check_platform()

    kernel   = get_kernel_version()
    in_range = check_kernel_range(kernel)
    probe    = probe_af_alg()

    print_report(kernel, in_range, probe)

    # Exit code 1 = reachable (useful for CI/scripting integration), 0 = safe
    return 1 if probe["reachable"] else 0

if __name__ == "__main__":
    sys.exit(main())
