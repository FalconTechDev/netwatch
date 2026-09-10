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
unelevated program (`netwatch tray`) registered to start at your logon, in your
own session, reading the same log the recorder writes. It shows the totals since
boot in its tooltip and offers the live view, a 12-hour report, and the log
folder from its menu. Quitting it leaves recording untouched.

## Everything since the machine came up

Type `netwatch` with no arguments and the live view opens already holding the
whole history since boot — not a blank screen that starts counting from the
moment you looked. It seeds itself from the recorder's log, folds those totals
into what each program has moved, and then keeps counting live on top of them.
The header says **since boot** when it is showing seeded history, and turns red
with `NOT RECORDING — run: netwatch service install` when there is no log to
seed from, so an empty screen can never be mistaken for a quiet network.

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
| Only looked-up names are shown | A peer is named when this machine resolved it. Hard-coded addresses, and answers cached before netwatch started, stay addresses |
| The record starts when you install it | netwatch cannot report on traffic from before it was recording — there is nothing kept anywhere else to read |
| Times are UTC | The log and the reports use one clock, so a time printed matches a time in the file, wherever the file is read |
| Loopback traffic is included | Two programs on this machine talking to each other counts as traffic, because to the kernel it is |

## Roadmap

1. Alerts — a threshold per program, and a note when one crosses it.
2. A report that compares today against the usual, so "unusual" needs no
   threshold set by hand.
3. History drawn over hours, not just the last minute.

## License

MIT
