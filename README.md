<div align="center">

# netwatch

**Which program is using your connection, and how much.**

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust&logoColor=white)](https://rust-lang.org)
[![Windows](https://img.shields.io/badge/Windows-10%2B-0078D6?logo=windows&logoColor=white)](#)
[![Linux](https://img.shields.io/badge/Linux-eBPF-FCC624?logo=linux&logoColor=black)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

Your system will not tell you this. Task Manager gives one number for the whole
machine. Resource Monitor shows a live list and forgets it the moment you close
the window — no totals, no history, no answer to "what was downloading while I
was asleep". The tools that do it properly cost money.

The information exists. The kernel already knows which process caused every
send and receive, and how many bytes it was. netwatch asks it, and does nothing
else.

It runs on **Windows and Linux**, and asks each one in its own language: ETW on
Windows, **eBPF** on Linux. That is the only part that differs. Both produce the
same stream of events, and everything above it — the aggregation, the log, the
reports, the live view — is one body of code that does not know which kernel is
underneath it.

```
netwatch                    # live, full screen
netwatch service install    # record from every boot, in the background
netwatch report --hours 12  # what used the connection while you were away
```

In the live view: `Enter` for what a program is and where it talks, `h` to hide
one, `x` to stop one, `q` to quit.

## What it looks like

```
 netwatch  ↓ 633.0 KB/s  ↑ 94.4 KB/s   3 programs · 9.8 MB in 4m12s · by rate
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│ PROGRAM                 PID LAST MINUTE                 DOWN           UP   TOTAL ↓  PEERS │
│▌firefox.exe            6124 ▂▂▂▂▃▃▃▃▃▄▄▄▄▄▅▅▅▅▅   603.5 KB/s    86.1 KB/s    8.1 MB      2 │
│ backup-agent.exe       4852 ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄    29.3 KB/s     3.9 KB/s  735.5 KB      1 │
│ mystery.exe            2628 ▁▁▁▁▁█▁▁▁▁▁▁▁▁▁▁▁▁▁      200 B/s            —  883.4 KB      1 │
└────────────────────────────────────────────────────────────────────────────────────────────┘
 / find  space hold  a active  ↵ details  h hide  H hidden  x stop  t sort  j k move  q quit
```

The shape in `LAST MINUTE` says what a number cannot: `firefox` is ramping up,
`backup-agent` has been steady, and `mystery.exe` sent one burst and went quiet.
All three could report the same average. Each is drawn against its own peak, so
a small program is not flattened by a loud one.

`Enter` opens what one program actually is, and where it has been talking:

```
┌ Mozilla Firefox — Esc closes ────────────────────────────────────────────┐
│described Mozilla Firefox                                                 │
│publisher Mozilla Corporation                                             │
│path      C:\Program Files\Mozilla Firefox\firefox.exe                    │
│traffic   831.2 KB down · 86.1 KB up · pid 6124 · 2 peers                 │
│                                                                          │
│PEER  (address)                            PROTO        DOWN          UP  │
│api.github.com  140.82.121.5:443             TCP    626.2 KB     86.1 KB  │
│185.184.222.3:443                            TCP    205.1 KB         0 B  │
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

Peers carry the name **this machine asked for**, next to the address it got.
Not a reverse lookup — that invents a name the traffic never mentioned, and for
anything behind a CDN returns something like
`ec2-52-216-18-11.compute-1.amazonaws.com`, which is worse than the address it
replaced. netwatch reads the machine's own DNS answers instead, so a name on
screen is one a program here actually resolved. An address nobody looked up —
hard-coded, or cached from before netwatch started — stays an address, which is
the honest outcome.

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
unelevated, which is too late and not enough rights.

The task is defined from XML rather than from `schtasks` switches, because three
of its defaults are wrong for something meant to run forever, and all three fail
silently: a task is killed after 72 hours, will not start while the machine is
on battery, and stops if it goes onto battery. On a laptop that leaves a gap in
the log exactly where the answer should be, with nothing anywhere to say why. Nothing is installed by
merely running netwatch; this is a separate, deliberate command, because a
program that quietly arranges to run forever on someone's machine is the
behaviour of something else entirely. `netwatch service uninstall` removes it.

The same command also puts an icon by the clock. The recorder is SYSTEM in
session 0, which has no desktop and so can show nothing; the icon is a second,
unelevated program registered to start at your logon, in your own session,
reading the same log the recorder writes. It shows the totals since boot in its
tooltip and offers the live view, a 12-hour report, and the log folder from its
menu. Quitting it leaves recording untouched.

That icon is its own executable, `netwatch-tray.exe`, and that is deliberate.
Windows decides whether a program gets a console window from a flag inside the
executable, not from how it is started — so a console program launched at logon
flashes a black window, and one that runs for as long as the tray does keeps it
open the whole time. `netwatch-tray.exe` is built for the windows subsystem
instead: it has no console, so nothing appears on screen when it starts. The
console `netwatch.exe` is still what you type at a terminal.

## Everything since the machine came up

Type `netwatch` with no arguments and the live view opens already holding the
whole history since boot — not a blank screen that starts counting from the
moment you looked. It seeds itself from the recorder's log, folds those totals
into what each program has moved, and then keeps counting live on top of them.
The header says **since boot** when it is showing seeded history, and turns red
with `NOT RECORDING` when there is no log to seed from, so an empty screen can
never be mistaken for a quiet network. The warning names the command that
starts recording *on the system you are on* — they differ — and it sits at the
front of the line, because the end of a line is what a narrow terminal cuts off
and a warning only visible on wide screens is not a warning.

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
backup-agent.exe — last 12 h: 38.2 GB down, 412.0 MB up
  active   184 minutes, 09-09 03:12 → 09-09 06:16 UTC
  peak     2.1 GB in one minute  (35.8 MB/s)
  pid      4852, 7714 — it restarted
  ran from C:\Users\you\AppData\Roaming\backup\backup-agent.exe
```

Every line there answers a different question. **When** narrows an overnight
total to a window. **Peak** says whether it saturated the link or trickled.
**Pid**, when there is more than one, explains a total no single run could
account for — it restarted. And **where it ran from** is the only place that
answer still exists, since the process is long gone by the time anyone reads it.

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

## Finding one program among forty

`/` — or `Ctrl+F` — narrows the list as you type. It matches the program's name,
what the file says it is, its publisher, its pid, **and every host it has talked
to** — so `github` finds the program that went there, which is usually the
question. The program's own name never contains that answer.

`space` holds the order. A list that re-sorts every second cannot be aimed at:
the row you were about to press `Enter` on has already moved. Holding freezes
the order while the numbers keep updating, and anything new that turns up is
appended rather than hidden — a list that quietly omitted the present while
"paused" would be worse than one that jumps.

`a` leaves out everything that is not moving right now.

All three narrow the **view** and nothing else, the same promise hiding makes:
everything is still measured, still logged, still in every report.

## Hiding, and stopping

A machine has a dozen programs that talk constantly and tell you nothing. Once
they are on screen every time, the screen stops being read — so `h` takes the
selected one out of the list.

**Hiding changes the view and nothing else.** A hidden program is still
measured, still written to the log, still in every report. That distinction is
the whole point: a filter that quietly stopped recording would turn "I did not
want to look at it" into "I have no idea what it did", which is the opposite of
what this is for. The header always says how many are hidden, `H` shows them
again inline, and `netwatch hidden` lists them from the command line.

`x` stops the selected program — after a question, never on the keystroke:

```
┌ Stop this program? ──────────────────────────────────────┐
│lsass.exe  (pid 900)                                      │
│C:\Windows\System32\lsass.exe                             │
│                                                          │
│It will be killed immediately. Anything it had not        │
│saved is lost, and this cannot be undone.                 │
│                                                          │
│This is a core Windows process. Stopping it will          │
│very likely crash the machine.                            │
│                                                          │
│  y  stop it        any other key  leave it alone         │
└──────────────────────────────────────────────────────────┘
```

The red warning is not decoration. `TerminateProcess` gives a program no chance
to save anything, and for `lsass`, `csrss` and their kind the honest description
of what happens next is a crashed machine — "are you sure" does not carry that
on its own.

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

### Windows

From an **elevated** PowerShell:

```powershell
irm https://github.com/FalconTechDev/netwatch/releases/latest/download/install.ps1 | iex
```

That installs the binary, puts it on `PATH`, **and starts recording** — at every
boot from then on, and immediately, so there is no wait for a reboot before the
log has anything in it.

Read that second part twice: it arranges for a program to run forever on this
machine, as SYSTEM, starting before anyone logs in. That is what a traffic
recorder has to do in order to answer "what happened overnight", and the
installer says so rather than doing it quietly.

- `NETWATCH_NO_AUTOSTART=1` installs the binary alone
- `netwatch service uninstall` removes the task afterwards
- `netwatch service status` says whether it is actually running

Without elevation the installer still works — binary and `PATH` — and says
plainly that recording was **not** set up, rather than leaving you believing it
was. netwatch needs an elevated terminal to run at all: reading which process
sent a packet is a kernel-level question.

Or from source:

```sh
cargo build --release
```

One binary. No driver and no runtime; the only thing it adds to the machine is
the startup task.

### Linux

```sh
curl -fsSL https://github.com/FalconTechDev/netwatch/releases/latest/download/install.sh | sh
```

That installs the binary and grants it `CAP_BPF` and `CAP_PERFMON`, so
**netwatch runs without sudo afterwards**. Reading which process sent a packet
means loading a program into the kernel, which is privileged; these are the two
narrow rights that replaced blanket `CAP_SYS_ADMIN` in kernel 5.8, and asking
for them rather than for root is asking for the least that works. If the
filesystem cannot carry capabilities the installer says so and tells you to use
`sudo`, rather than leaving you to discover it as a permission error.

`netwatch service install` arranges recording from every boot here too, as a
systemd unit. It asks for `CAP_BPF` and `CAP_PERFMON` rather than running as
root outright, and is restarted if it ever stops — a recorder that died in the
night leaves a gap exactly where the answer should have been.

That confinement has a sharp edge worth knowing about: dropping everything but
those two capabilities takes `CAP_DAC_OVERRIDE` away from root, so the service
can only write a directory it owns. The unit therefore lets systemd create and
hand over `/var/log/netwatch`. The first version did not, and it started,
reported itself active and enabled, and logged "Permission denied" once a
minute while recording nothing at all.

Needs a kernel with BTF (`CONFIG_DEBUG_INFO_BTF`), which every current
distribution ships. The installer checks and warns before it installs anything.

### Standalone, with nothing to download

Each release also carries a **standalone installer**: one file with netwatch
already inside it, which installs without reaching the network at all. Useful
on a machine with no route to GitHub, behind a proxy that will not pass it, or
anywhere the one-liner above is not wanted.

```sh
sh netwatch-standalone-installer.sh            # Linux
```
```powershell
powershell -ExecutionPolicy Bypass -File netwatch-standalone-installer.ps1   # Windows, elevated
```

It is the same installer as above with the archive appended to it, not a second
implementation — an offline path written separately is the one nobody would
notice had stopped working. `tools/make-standalone.sh` and
`tools/make-standalone.ps1` build them from a compiled binary.

The Linux one must be run **as a file**, not piped into `sh`: it reads its own
payload out of `$0`, and a pipe has no `$0` to read.

## How Linux is asked

ETW has no equivalent here, so the question is put to the kernel directly, with
a small program loaded into it:

* **`tcp_sendmsg`** is called once per send, with the byte count as an
  argument.
* **`tcp_cleanup_rbuf`** is the receive side — not `tcp_recvmsg`, which is
  entered *before* it knows how much it will return. The count only exists on
  the way out.
* **`udp_sendmsg`** and **`udpv6_sendmsg`** are the same for UDP, which needs
  both because the two families have separate send paths, and
  **`skb_consume_udp`** is its receive side, chosen over `udp_recvmsg` for the
  same reason: it is handed the socket and the length together.

The far end of each transfer is read out of `struct sock`, and where those
fields sit differs between kernel builds — a config option flipped, a distro
patch, and a field moves. Offsets compiled in would read whatever now lives at
the old address and report it as an answer. So netwatch parses the kernel's own
`/sys/kernel/btf/vmlinux` at startup, finds the offsets on the machine it is
about to run on, and passes them to the program through a map. That is the same
idea as libbpf's CO-RE, done by hand and only as far as it needs to go.

A socket with no far end recorded on it — an unconnected UDP socket — is
reported as having no peer, rather than as `0.0.0.0:0`. The bytes are real and
stay counted against the program; where they went is simply not something this
saw.

Both are entry probes in the kernel's hot path, so the work done there is a few
loads and a write into a ring buffer; anything slower would be felt by every
connection on the machine. The ring buffer is shared across CPUs, so events
keep their order — which is what lets a name be recorded before the traffic it
belongs to. When it fills, the kernel drops the event rather than waiting:
losing a sample is better than stalling a send.

Process ids are reported **in the namespace you are in**. The kernel counts
processes in the namespace it booted in, so inside a container — and WSL is one
— its numbers name nothing that `/proc` or `ps` can find. They look perfectly
reasonable and refer to other processes entirely, which is worse than no answer
at all, so the program asks for ids in the caller's namespace and falls back to
the kernel's own only when a process is not in it.

Names come from `/proc/<pid>/exe` rather than from `comm`: the kernel truncates
`comm` to fifteen characters, and two different programs would quietly become
the same one.

Peer **names** are read where the lookup happens, with a pair of probes on the
C library's `getaddrinfo` — the name going in, the addresses coming out. That
is the same promise the Windows side makes by reading the machine's own DNS
answers: a name on screen is one a program here actually asked for, never a
reverse lookup. A program that carries its own resolver instead of using the C
library — a statically linked Go binary, most obviously — is not seen, and its
peers stay addresses rather than acquiring a name from somewhere else.

Those two probes read `struct addrinfo`, and its offsets *are* hard-coded,
which looks inconsistent next to the trouble taken over `struct sock`. The
difference is the point: `struct sock` is internal to a kernel build and moves
between them, while `struct addrinfo` is part of the C library's published ABI.
If it moved, every binary on the system would break, not just this one.

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
| Needs privilege | An ETW session needs Administrator; loading an eBPF program needs `CAP_BPF` and `CAP_PERFMON`. Neither question can be asked without them |
| Only looked-up names are shown | A peer is named when a program here resolved it. On Linux that means through the C library; a statically linked Go binary carries its own resolver and is not seen |
| Only looked-up names are shown | A peer is named when this machine resolved it. Hard-coded addresses, and answers cached before netwatch started, stay addresses |
| The record starts when you install it | netwatch cannot report on traffic from before it was recording — there is nothing kept anywhere else to read |
| Times are UTC | The log and the reports use one clock, so a time printed matches a time in the file, wherever the file is read |
| Loopback traffic is included | Two programs on this machine talking to each other counts as traffic, because to the kernel it is |

## Roadmap

1. Alerts — a threshold per program, and a note when one crosses it.
3. A report that compares today against the usual, so "unusual" needs no
   threshold set by hand.
4. History drawn over hours, not just the last minute.

## License

MIT
