<div align="center">

# netwatch

**Which program is using your connection, and how much.**

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust&logoColor=white)](https://rust-lang.org)
[![Windows](https://img.shields.io/badge/Windows-10%2B-0078D6?logo=windows&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

Windows will not tell you this. Task Manager gives one number for the whole
machine. Resource Monitor shows a live list and forgets it the moment you close
the window — no totals, no history, no answer to "what was downloading while I
was asleep". The tools that do it properly cost money.

The information exists. The Windows kernel reports **every** send and receive
with the process that caused it and the byte count already attached. netwatch
reads that, and nothing else.

```
netwatch          # live, full screen
netwatch top      # watch for ten seconds, print what happened, exit
```

## What it looks like

```
 netwatch  ↓ 863.6 KB/s  ↑ 94.4 KB/s   3 programs · 958.1 KB in 0m42s · sorted by rate
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ PROGRAM                      PID         DOWN           UP     TOTAL ↓   TOTAL ↑  PEERS│
│▌firefox.exe                 6124   831.2 KB/s    86.1 KB/s    831.2 KB   86.1 KB      2│
│ backup-agent.exe            4852    32.4 KB/s     3.9 KB/s     32.4 KB    3.9 KB      1│
│ telemetry.exe               2628            —     4.5 KB/s         0 B    4.5 KB      1│
└────────────────────────────────────────────────────────────────────────────────────────┘
 Enter who it talks to   t sort by rate/total   j k move   q quit
```

`Enter` opens where one program has been talking:

```
┌ firefox.exe — 2 peers, Esc closes ───────────────────────────────┐
│PEER                              PROTO        DOWN            UP │
│185.184.222.3:443                   TCP    626.2 KB       86.1 KB │
│140.82.114.25:443                   TCP    205.1 KB           0 B │
└──────────────────────────────────────────────────────────────────┘
```

## Rates and totals are different questions

"What is using my connection **right now**" and "what has used it **today**" have
different answers, and a tool that only keeps one of them cannot answer the
other. netwatch keeps both: totals accumulate for the life of the run, rates are
the delta over the last second and nothing more.

The default sort is by rate, because that is the question you open it to ask —
a process that downloaded a gigabyte an hour ago is not the answer, and putting
it on top would bury the one that is. `t` switches.

## How it works

One source: the `Microsoft-Windows-Kernel-Network` provider, over ETW.

That choice is the whole design. Every alternative solves the *attribution*
problem — which program sent this byte — the hard way:

| | what it costs |
|---|---|
| **ETW** (what netwatch uses) | nothing to install; the kernel attaches the pid itself |
| WinDivert / a capture driver | a driver to install, and the pid still has to be guessed by matching packets against the connection table |
| Polling the connection table | no byte counts exist there at all |

By the time bytes reach a network card the process is gone from the picture, so
a packet sniffer has to work backwards to a pid and will be wrong for anything
short-lived. The kernel does not have to work backwards. It knows.

**netwatch needs Administrator.** A real-time ETW session is a privileged thing
to open, and that is not a limitation worth apologising for: reading which
process sent a packet is a kernel-level question and Windows only answers it for
an elevated session. Without it the session refuses to start and says so.

## Install

```powershell
irm https://github.com/FalconTechDev/netwatch/releases/latest/download/install.ps1 | iex
```

Or from source:

```sh
cargo build --release
```

One binary. No driver, no service, no runtime.

## Correctness

The failure mode that matters here is not a crash — it is a number that is
quietly wrong, in a display whose whole purpose is being believed. The tests are
built around that:

- **Direction is tested end to end.** Swapping sent and received would make
  every "downloaded" figure an upload and nothing would look broken.
- **Every transfer opcode is pinned, and every non-transfer one.** The provider
  also reports connection attempts and disconnects; counting those as traffic
  would inflate every total, and missing the IPv6 opcodes would silently
  under-report exactly the traffic that is growing.
- **A rate is the delta over the interval that actually passed**, not over an
  assumed one — the interval is handed in rather than measured separately, so
  the caller's tick and the arithmetic cannot disagree.
- **A rate falls back to zero when nothing moves**, rather than keeping the last
  burst on screen.
- **The screen is rendered to a text buffer in a test**, so the layout is
  checked on every run: no column truncated away, nothing spilling past the
  terminal width, peers of one process never shown under another.

```sh
cargo test
```

## Known limits

| Limit | Consequence |
|---|---|
| Windows only | The provider this reads is a Windows kernel provider; there is no equivalent to fall back to |
| Needs Administrator | A real-time ETW session cannot be opened without it |
| Peers are addresses, not names | The transfer events carry no hostname, and attaching one by reverse lookup would name something the traffic never mentioned |
| Nothing is kept between runs | Totals start at zero each time, so "what happened overnight" needs the process to have been running overnight |
| Loopback traffic is included | Two programs on this machine talking to each other counts as traffic, because to the kernel it is |

## Roadmap

1. History on disk, so totals survive a restart and "what ran overnight" can be
   asked the next morning.
2. Alerts — a threshold per program, and a note when one crosses it.
3. Hostnames, taken from the machine's own DNS activity rather than from reverse
   lookups, so a name shown is a name that was actually asked for.
4. Per-program history, drawn.

## License

MIT
