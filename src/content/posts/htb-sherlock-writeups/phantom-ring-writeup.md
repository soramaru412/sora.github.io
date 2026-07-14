---
title: "RE 101 — HTB Sherlock: Phantom Ring"
published: 2026-07-14
description: "Static analysis of a Linux post-exploitation implant using strings and objdump. First writeup in my RE 101 series."
tags: [HTB, Sherlock, Malware Analysis, Reverse Engineering, Linux]
category: CTF Writeups
draft: false
---

| | |
|---|---|
| **Category** | Static Analysis / Malware Analysis / Reverse Engineering |
| **Difficulty** | Beginner–Intermediate |
| **Platform** | Linux x86-64 |
| **Tools** | `strings` `objdump` `sha256sum` `file` |
| **Status** | Solved ✅ |

**📁 Category:** Static Analysis / Malware Analysis / Reverse Engineering
**🎯 Difficulty:** Beginner–Intermediate
**🧰 Skills tested:** ELF binary analysis, `strings`, `objdump`, x86-64 assembly reading, calling convention, Linux syscall/procfs knowledge

:::note[About this writeup]
This is my first hands-on writeup in reverse engineering / malware analysis. I'm starting a "RE 101" series on this blog to document my learning journey from scratch — no prior RE background going in, just `strings`, `objdump`, and a lot of patient reading of assembly. If you're also just getting started, I hope walking through my reasoning (including the mistakes) is useful. If you're an experienced RE person and spot something I got right for the wrong reason, I'd genuinely love to hear about it.
:::

---

## 📜 Scenario

> Your organization's SOC team intercepted a suspicious binary during a routine threat hunting operation on a Linux server. The file was found in `/var/tmp` with an unusual name and was attempting to establish outbound connections. Initial analysis suggests this could be a post-exploitation agent. Your task is to perform static analysis on the binary to identify its capabilities, extract indicators of compromise, and understand the threat actor's infrastructure.

The challenge provides a single ELF binary (`agent`) — not stripped, dynamically linked against `libc` and `liburing`.

```
$ file agent
agent: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1f617f2ea259a7ec724d7bbc01627982dc2f0495,
for GNU/Linux 3.2.0, not stripped
```

The fact that the binary is **not stripped** means all function and symbol names are intact — a huge advantage for static analysis, since we can read function names like `cmd_get`, `cmd_recv`, `process_cmd`, etc. directly instead of reverse-engineering unnamed `sub_XXXX` blocks.

Tooling used throughout: `sha256sum`, `strings`, `file`, `objdump`.

---

## 🧬 Malware Overview: What Is This Thing?

Before diving into the task-by-task walkthrough, it's worth stepping back and describing what `agent` actually *is*, based on everything static analysis revealed.

`agent` is a **lightweight, single-binary post-exploitation implant** written in C for Linux x86-64. It's the kind of tool a threat actor would drop on a compromised host *after* initial access, to maintain a foothold, gather recon, and give the operator hands-on-keyboard-style control over the box via a simple text-based C2 protocol. It has no persistence mechanism of its own visible in this binary (no cron entry, no systemd unit, no LD_PRELOAD hijack) — its job is to sit, phone home, wait for commands, and clean up after itself when told to.

### 🏗️ High-level architecture

```
 ┌─────────────┐        TCP 192.168.56.1:4445        ┌─────────────┐
 │   Victim     │ <───────────────────────────────── │   Attacker   │
 │   (agent)    │ ─────────────────────────────────> │   (C2)       │
 └─────────────┘        io_uring-based socket          └─────────────┘
        │
        │  main() loop:
        │  1. io_uring_queue_init()
        │  2. io_uring_prep_connect() -> C2 IP:port
        │  3. on success: loop reading commands from socket
        │  4. process_cmd() dispatches to one of 11 cmd_* handlers
        │  5. on failure: sleep(120) and retry
        └────────────────────────────────────────────
```

At startup, the agent doesn't call `connect()` directly — it initializes an `io_uring` instance (`io_uring_queue_init`) and submits a *connect request* (`io_uring_prep_connect`) into the ring, then waits for the kernel to complete it asynchronously (`io_uring_wait_cqe`). This is the first and most distinctive design choice in the sample, and it runs through every network/file operation the agent performs.

Once connected, the agent enters a simple **read-command / dispatch / respond** loop. Input arriving over the socket is cleaned up (`sanitize_cmd` / `trim_leading`), then handed to `process_cmd`, which does a series of string comparisons against known command keywords and calls the matching `cmd_*` handler. If nothing matches, it prints `[*] 404 Command not found [*]` and waits for the next command.

### 🗂️ Capability breakdown

Grouping the 11 supported commands (see Task 5) by *intent* paints a clear picture of what the operator can do with this implant:

| Category | Commands | Purpose |
|---|---|---|
| **File transfer** | `get`, `recv` | Pull files off the victim / receive a file over the socket |
| **Host & user recon** | `users`, `me`, `ps` | Enumerate logged-in sessions, current process identity, running processes |
| **Network recon** | `ss` (aka `netstat`) | Enumerate active TCP connections from `/proc/net/tcp` |
| **Active response / interference** | `kick`, `killbpf` | Terminate arbitrary processes; specifically hunt and kill eBPF-based monitoring tools |
| **Privilege escalation recon** | `privesc` | Scan `/usr/bin` for SUID binaries as potential escalation paths |
| **Anti-forensics / cleanup** | `sdestruct`, `exit` | Delete its own binary and disconnect cleanly |

Put together, this isn't just a reverse shell — it's a small **recon-and-response toolkit**: gather info about the box and its defenses, escalate if possible, actively fight back against security tooling it can detect, move files in/out, and erase itself on command.

### 🛡️ Defense evasion, in two layers

The sample doesn't rely on a single evasion trick — it stacks two distinct techniques against two distinct classes of Linux monitoring:

1. **`io_uring` instead of direct syscalls** — evades EDR/tools that hook traditional syscalls (`connect`, `read`, `write`, `openat`, `unlink`, ...) via `ptrace`, seccomp-BPF, or syscall-level eBPF tracepoints. See Task 6 for the mechanics.
2. **Active hunting of eBPF tools and ftrace** — rather than just hiding from monitoring, `killbpf` actively scans every process's `/proc/[pid]/maps` for the `anon_inode:bpf-map` signature and kills matches (Task 9), while another routine writes to `/sys/kernel/debug/tracing/tracing_on` and friends to shut off ftrace-based tracing (Task 10), and cleans up pinned BPF objects under `/sys/fs/bpf`.

This two-pronged approach — *evade what you can't kill, kill what you can find* — is a good real-world illustration of why modern Linux EDR increasingly needs multiple independent telemetry sources rather than relying on any single one.

---

## 🔎 Task 1 — SHA256 hash of the binary

```bash
sha256sum agent
```

:::tip[Answer]
`2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5`
:::

Standard first step for any malware sample — establishes a unique fingerprint for IOC tracking and cross-referencing against threat intel feeds (VirusTotal, MISP, etc.).

---

## 🌐 Task 2 — Hardcoded C2 IP address

A quick pass with `strings` filtered for IPv4-looking patterns immediately surfaces it:

```bash
strings -a agent | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
```

```
192.168.56.1
```

:::tip[Answer]
`192.168.56.1`
:::

This is a private/lab-range IP (VirtualBox Host-Only default range), consistent with a Sherlock built for a simulated environment.

---

## 🔌 Task 3 — C2 port

The IP string alone doesn't give us the port — no `IP:PORT` string exists in `.rodata`, so we go to disassembly and look for how the socket connection is prepared.

Since this binary uses `htons()` (host-to-network-short) to convert the port to network byte order, we grep for calls to it and inspect the immediate value passed in the argument register right before the call:

```bash
objdump -d agent | grep -B5 "call.*htons"
```

```asm
41f7:  66 c7 85 00 ff fe ff 02 00     movw   $0x2,-0x10100(%rbp)     ; sin_family = AF_INET
4200:  bf 5d 11 00 00                 mov    $0x115d,%edi            ; arg1 = port
4205:  e8 46 d1 ff ff                  call   1350 <htons@plt>
420a:  66 89 85 02 ff fe ff            mov    %ax,-0x100fe(%rbp)      ; store into sin_port
```

Under the System V AMD64 calling convention, the first integer argument to a function is passed in `%rdi`/`%edi`. So `0x115d` is the raw port value being handed to `htons()`.

```
0x115d = 4445 (decimal)
```

:::tip[Answer]
`4445`
:::

**Key takeaway:** whenever you see `htons()` called in a binary, the value loaded into `%edi` right before the call is almost always a network port — a very reliable pattern for locating C2 ports in unstripped or lightly-obfuscated malware.

---

## ⏱️ Task 4 — Reconnect delay after failed connection

Same technique, different function: find calls to `sleep()` and read the argument set immediately before it.

```bash
objdump -d agent | grep -B15 "call.*sleep"
```

```asm
4342:  bf 78 00 00 00     mov    $0x78,%edi
4347:  e8 94 d1 ff ff     call   14e0 <sleep@plt>
```

`sleep(seconds)` takes its argument directly in seconds (unlike `usleep`/`nanosleep`, no unit conversion needed).

```
0x78 = 120 (decimal)
```

:::tip[Answer]
`120` seconds
:::

The same `mov $0x78,%edi` / `call sleep@plt` pair appears twice in the binary — once for a failed `connect()` retry path, and once after the connection is closed/cleaned up — indicating a consistent reconnect-loop delay used throughout the agent's networking logic.

---

## 🧮 Task 5 — Number of supported commands

This required a bit more care than the previous tasks. A naive `strings` pass suggested command names like `get`, `recv`, `users`, `netstat`, `kick`, `privesc`, `sdestruct`, `killbpf`, `exit` — but this list turned out to be **incomplete**.

:::warning[Gotcha]
`strings` by default only prints strings **4 characters or longer**. Two-character command names (`ss`, `ps`, `me`) were silently dropped. Re-running with a lower minimum length caught them:
:::

```bash
strings -a -n 2 agent | grep -E "^[a-z]{2,10}$"
```

This revealed the missing `ss`, `ps`, `me` strings.

To get an authoritative count (not just a string-based guess), the binary's symbol table was checked for `cmd_*` handler functions, and the dispatcher function `process_cmd` was inspected to confirm each one is actually invoked:

```bash
objdump -d agent | grep -A 2000 "<process_cmd>:" | grep -B1 "call.*cmd_"
```

```
call   23da <cmd_get>
call   2635 <cmd_recv>
call   1e49 <cmd_users>
call   20a3 <cmd_ss>
call   2a86 <cmd_ps>
call   29b0 <cmd_me>
call   2cfc <cmd_kick>
call   32d8 <cmd_privesc>
call   3546 <cmd_selfdestruct>
call   37a2 <cmd_killbpf>
call   36ea <cmd_exit>
```

That's **11 distinct handler functions** called from the dispatcher.

:::tip[Answer]
`11`
:::

**Why not count other symbols?**
- `process_cmd` is the *dispatcher* itself — the function that decides *which* command handler to invoke, not a command.
- `sanitize_cmd` is a string-cleanup helper shared across all commands, not command-specific logic.
- `netstat` appears as a string in `.rodata` but has **no dedicated `cmd_netstat` handler** — it's likely just cosmetic output text used inside `cmd_ss`, not an independently dispatched command.
- Helper functions like `send_all`, `recv_all`, `read_file_uring`, `trim_leading` are shared utilities used by multiple `cmd_*` handlers, not commands in their own right.

---

## 🥷 Task 6 — Kernel interface abused to evade EDR syscall monitoring

:::tip[Answer]
`io_uring`
:::

The binary is linked against `liburing.so.2` and makes heavy use of `io_uring_prep_*` wrapper functions instead of calling standard I/O syscalls directly:

```
io_uring_queue_init / io_uring_queue_exit
io_uring_submit
io_uring_get_sqe
io_uring_wait_cqe / io_uring_cqe_seen
io_uring_prep_connect   (replaces connect())
io_uring_prep_read      (replaces read())
io_uring_prep_write     (replaces write())
io_uring_prep_send      (replaces send())
io_uring_prep_recv      (replaces recv())
io_uring_prep_openat    (replaces openat())
io_uring_prep_unlinkat  (replaces unlink())
```

**Why this evades EDR:** most Linux EDR/monitoring tools hook traditional syscalls (`connect`, `read`, `write`, `execve`, etc.) via `ptrace`, seccomp-BPF, or eBPF tracepoints/kprobes. `io_uring` moves the actual I/O work into the kernel through a shared submission/completion queue mechanism, funneled through a small number of `io_uring_enter` calls rather than the syscalls being monitored. As a result, an EDR watching for `connect()`/`read()`/`write()` calls may never see them.

---

## 👥 Task 7 — File read to enumerate logged-in users

:::tip[Answer]
`/var/run/utmp`
:::

```
/var/run/utmp
Error reading /var/run/utmp
Logged users:
%-8s %-8s
```

`/var/run/utmp` is the standard Linux file tracking currently active login sessions (the same source used by `who`/`w`/`users`). This is read inside `cmd_users`, one of the 11 supported commands identified in Task 5.

---

## 🚪 Task 8 — Directory scanned for SUID binaries

:::tip[Answer]
`/usr/bin`
:::

```
/usr/bin
Failed to open /usr/bin
Potential SUID binaries:
/usr/bin/%s
```

This corresponds to `cmd_privesc`: the agent iterates over files in `/usr/bin`, checking each for the SUID bit and reports candidates that could be leveraged for privilege escalation.

---

## 🎯 Task 9 — String searched for in `/proc/[pid]/maps` to detect eBPF-based tools

:::tip[Answer]
`anon_inode:bpf-map`
:::

```
/proc/%s/maps
anon_inode:bpf-map
[+] Killed PID using BPF: %d
```

When a process loads an eBPF map, the kernel exposes it as an anonymous inode mapping visible in that process's `/proc/[pid]/maps`, tagged `anon_inode:bpf-map`. The agent iterates all PIDs under `/proc`, reads each `/proc/[pid]/maps`, and flags — then kills — any process containing this string, effectively hunting down and terminating eBPF-based security tooling.

---

## 🔕 Task 10 — First tracing file the agent attempts to disable

:::tip[Answer]
`/sys/kernel/debug/tracing/tracing_on`
:::

```
/sys/kernel/debug/tracing/tracing_on
/sys/kernel/debug/tracing/set_event
/sys/kernel/debug/tracing/current_tracer
[*] Tracing disabled: %s
```

Beyond eBPF, the agent also targets the older **ftrace** subsystem. `tracing_on` is a control file that globally enables/disables trace output when written; disabling it neutralizes `ftrace`-based monitoring regardless of what tracer or events are configured.

---

## 💣 Task 11 — Procfs path used to locate its own executable before self-destruction

:::tip[Answer]
`/proc/self/exe`
:::

```
Agent will self-destruct
/proc/self/exe
Unlink failed: %s
```

`/proc/self/exe` is a symlink that always resolves to the currently running process's own executable path, regardless of its actual location or name on disk. The agent reads this via `readlink()` to determine its own file path at runtime, then deletes itself using `io_uring_prep_unlinkat` — a self-locating anti-forensics technique that works correctly even if the binary was renamed or moved after being dropped.

---

## 🗑️ Task 12 — Command string that triggers self-deletion

:::tip[Answer]
`sdestruct`
:::

From the command list identified in Task 5, `sdestruct` is the string compared against user input to invoke `cmd_selfdestruct`, which performs the `/proc/self/exe` lookup (Task 11) and subsequent `unlink()` of the agent's own binary.

---

## 📋 Summary of Indicators of Compromise (IOCs)

| Indicator | Value |
|---|---|
| 🔑 SHA256 | `2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5` |
| 🌐 C2 IP | `192.168.56.1` |
| 🔌 C2 Port | `4445` |
| ⏱️ Reconnect interval | `120` seconds |
| 📂 Drop location | `/var/tmp` |
| 🗑️ Self-delete trigger | `sdestruct` command → `/proc/self/exe` → `unlinkat` |

## ⚙️ Behavioral Summary

| Capability | Mechanism |
|---|---|
| 📡 C2 communication | Raw TCP socket via `io_uring_prep_connect`, `192.168.56.1:4445` |
| 🥷 Syscall/EDR evasion | `io_uring` async I/O interface instead of direct syscalls |
| 👥 User enumeration | `/var/run/utmp` |
| 🌐 Network connection enumeration | `/proc/net/tcp` (via `cmd_ss`/`netstat`) |
| 🚪 Privilege escalation recon | SUID binary scan of `/usr/bin` |
| 🎯 Active eBPF tool hunting | Scans `/proc/[pid]/maps` for `anon_inode:bpf-map`, kills matches |
| 🔕 ftrace evasion | Disables `/sys/kernel/debug/tracing/{tracing_on,set_event,current_tracer}` |
| 🧹 BPF pin cleanup | Deletes files under `/sys/fs/bpf` |
| 💣 Anti-forensics | Self-locates via `/proc/self/exe`, self-deletes via `unlinkat` |
| 🧾 Supported commands (11) | `get`, `recv`, `users`, `ss`, `ps`, `me`, `kick`, `privesc`, `sdestruct`, `killbpf`, `exit` |

---

## 💡 Lessons Learned & Useful Takeaways

### 1️⃣ Deep dive: why `io_uring` is such an interesting evasion primitive

`io_uring` was introduced in Linux 5.1 (2019) as a high-performance **asynchronous I/O interface**. Instead of a program calling `read()`, `write()`, `connect()`, `send()`, `openat()`, etc. one at a time and blocking on each, it works through two ring buffers shared between userspace and the kernel:

- **Submission Queue (SQ)** — userspace writes a small struct describing an I/O operation ("please connect this fd to this address") and pushes it into the ring.
- **Completion Queue (CQ)** — the kernel processes the operation asynchronously and pushes the result back for userspace to collect.

The program only needs a couple of actual syscalls to drive this whole mechanism — `io_uring_setup`, `io_uring_enter`, and `io_uring_register` — no matter how many "logical" I/O operations are queued up inside the ring.

**Why that matters for evasion:** most Linux security tooling watches for specific syscalls by name or number. When a program instead issues the *equivalent* operation through `io_uring_prep_connect()` + `io_uring_enter()`, the *observable syscall* is just "enter the ring" — a generic call that doesn't reveal *what* operation was requested. A monitoring rule written specifically for `connect()` never fires, even though a TCP connection is absolutely being made.

**How to spot it in future samples:**
- Check the dynamic symbol table / imports for `liburing` — its presence at all is a strong signal.
- Look for the `io_uring_prep_*` function family — each one maps 1:1 to a "normal" syscall it's replacing.
- If a binary looks like it does networking/file I/O but you *can't* find `connect@plt`, `read@plt`, etc. in its import table, that absence itself is a clue.

### 2️⃣ `strings` has a default minimum length of 4

Always re-run with `-n 2` or `-n 1` when hunting for short command keywords or flags — don't assume the default output is complete. This is what caused the initial undercount in Task 5 (`ss`, `ps`, `me` were invisible at the default threshold).

### 3️⃣ Calling convention is the single most useful fact in x86-64 static RE

Under the System V AMD64 ABI, the first integer/pointer argument to any function call sits in `%rdi`/`%edi` immediately before the `call` instruction. This one pattern — `mov $imm, %edi` → `call func@plt` — was enough to recover the C2 port and the reconnect delay directly from `objdump` output, with no decompiler needed at all.

### 4️⃣ Recognize evasion by *library and function names*, not just runtime behavior

Seeing `io_uring_prep_*` functions instead of `connect`/`read`/`write` directly is itself a strong static signal of syscall-monitoring evasion — you don't need a sandbox or dynamic trace to notice it, it's sitting right there in the import table.

### 5️⃣ Verify against the dispatcher, not just `strings`

When counting "how many commands" a binary supports, don't trust a string list alone — cross-reference against the actual dispatch logic to avoid over- or under-counting due to shared helper functions or leftover/cosmetic strings.

### 6️⃣ Unstripped binaries are a gift — use it, but don't depend on it

Symbol names like `cmd_privesc`, `cmd_killbpf`, `process_cmd` turned what would otherwise be a slow function-by-function decompilation exercise into a fast, targeted read. But it's worth remembering *why* each answer was actually correct — not because a function was named `cmd_X`, but because the dispatcher genuinely called it in response to a specific input string.

### 7️⃣ Defense-in-depth applies to defenders too

The malware's two-layer evasion is a good reminder that no single Linux telemetry source is sufficient on its own. Syscall hooks, eBPF, and ftrace can each be evaded or disabled individually — robust detection needs redundant, cross-checking data sources.

---

## 🚀 What's Next

This Sherlock was solved entirely with `strings` and `objdump` — no decompiler, no dynamic analysis, no debugger. Things I want to try next:

- **Load this same binary into Ghidra** and compare its decompiled pseudo-C against the raw assembly reasoning in this writeup.
- **Actually run it in an isolated VM** and trace it with `strace`/`ltrace` to see firsthand that `connect()` etc. don't show up the way they normally would.
- **Try a stripped version of a similar sample** to practice the "find the dispatcher without symbol names" muscle.
- **Set up a minimal eBPF-based monitor** (e.g. a simple Tetragon/bpftrace rule watching `connect`) and confirm this technique really does slip past it in practice.

If you're following along and have suggestions for the next Sherlock or malware sample to dig into, feel free to reach out.
