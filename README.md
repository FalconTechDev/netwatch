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
netwatch                    # live, full screen
netwatch service install    # record from every boot, in the background
netwatch report --hours 12  # what used the connection while you were away
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

`Enter` opens what one program actually is, and where it has been talking:

```
┌ Mozilla Firefox — Esc closes ────────────────────────────────────────────┐
│described Mozilla Firefox                                                 │
│publisher Mozilla Corporation                                             │
│path      C:\Program Files\Mozilla Firefox\firefox.exe                    │
│traffic   831.2 KB down · 86.1 KB up · pid 6124 · 2 peers                 │
│                                                                          │
│PEER                                       PROTO        DOWN          UP  │
│185.184.222.3:443                            TCP    626.2 KB     86.1 KB  │
│140.82.114.25:443                            TCP    205.1 KB         0 B  │
└──────────────────────────────────────────────────────────────────────────┘
```

The path is the point. `svchost.exe` in `System32`, published by Microsoft, is
the operating system. The same name from a temp directory, claiming nothing
about itself, is the single most useful thing this screen can show — and the
absence is shown as an absence rather than as a blank line:

```
┌ mystery.exe — Esc closes ────────────────────────────────────────────────┐
│described no description in the file                                      │
│publisher no publisher named in the file                                  │
│path      C:\Users\you\AppData\Local\Temp\mystery.exe                     │
└──────────────────────────────────────────────────────────────────────────┘
```

None of that is a verdict. The description and the publisher are strings the
file claims about itself and nothing verifies them; a familiar path is a
statement about tidiness, never about trust. They are shown because they are
what a person needs in order to start asking the right question.

## What was downloading while you slept

A live view can only tell you about the time you spent looking at it, which is
never the time you want to ask about. So netwatch records.

```
netwatch service install
```

That registers a scheduled task which starts at boot, under SYSTEM, before
anyone logs in and with no window — a Run key would start it after login,
unelevated, which is too late and not enough rights. Nothing is installed by
merely running netwatch; this is a separate, deliberate command, because a
program that quietly arranges to run forever on someone's machine is the
behaviour of something else entirely. `netwatch service uninstall` removes it.

From then on:

```
$ netwatch report --hours 12
Last 12 h — 41.7 GB moved by 23 programs, 09-08 22:14 to 09-09 10:02 UTC

PROGRAM                           DOWN          UP       TOTAL   ACTIVE  BUSIEST MINUTE
backup-agent.exe               38.2 GB    412.0 MB     38.6 GB     184m  09-09 03:12 (2.1 GB)
firefox.exe                     2.1 GB    140.2 MB      2.2 GB      47m  09-08 23:40 (410.2 MB)
telemetry.exe                  12.0 MB    881.4 MB    893.4 MB     712m  09-09 04:00 (14.1 MB)
```

`ACTIVE` is how many minutes it moved anything, which is what separates one big
transfer from a steady trickle — 184 minutes of backup is a backup, 712 minutes
of telemetry is something else. `BUSIEST MINUTE` turns "38 GB overnight" into
"38 GB starting at 03:12", which is the part that identifies what happened.

Then one program in detail, with where it went:

```
$ netwatch report --program backup-agent --hours 12
backup-agent.exe — last 12 h: 38.2 GB down, 412.0 MB up, over 184 minutes

WHERE THE BULK WENT                                 BYTES
52.216.18.11:443                                   31.4 GB
52.216.140.99:443                                   7.2 GB
```

The same in the reports, where it matters more — by then the process is gone
and cannot be asked:

```
$ netwatch report --program backup-agent --hours 12
backup-agent.exe — last 12 h: 38.2 GB down, 412.0 MB up, over 184 minutes
  ran from C:\Users\you\AppData\Roaming\backup\backup-agent.exe
```

In the summary a path is printed only when it is somewhere other than the
ordinary places — a line under every Windows component saying `System32` is
noise, and the point is the one that does not belong.

### The log

Tab-separated text, one file a day, in `C:\ProgramData\netwatch`. One line per
minute per program, with the busiest three destinations of that minute.

That format is a decision, not a shortcut: it can be read by anything, tailed
while it is being written, and inspected with a text editor. A binary format
would be smaller and would make a year of your own data hostage to this program
still existing and still being able to parse it. Files older than thirty days
are deleted — `--keep-days` changes that.

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

One binary. No driver and no runtime; the only thing it can add to your
machine is the startup task, and only if you ask for it.

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
| The record starts when you install it | netwatch cannot report on traffic from before it was recording — there is nothing kept anywhere else to read |
| Times are UTC | The log and the reports use one clock, so a time printed matches a time in the file, wherever the file is read |
| Loopback traffic is included | Two programs on this machine talking to each other counts as traffic, because to the kernel it is |

## Roadmap

1. Alerts — a threshold per program, and a note when one crosses it.
2. Hostnames, taken from the machine's own DNS activity rather than from reverse
   lookups, so a name shown is a name that was actually asked for.
3. Per-program history over time, drawn.
4. A report that compares today against the usual, so "unusual" needs no
   threshold to be set by hand.

## License

MIT
