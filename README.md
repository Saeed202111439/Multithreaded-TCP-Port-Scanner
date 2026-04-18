# Multithreaded TCP Port Scanner
**Course:** 605346 - Information & Network Security Programming
**University of Petra - Faculty of Information Technology**
**Academic Year:** 2025-2026, Semester 2

---

## Requirements

- Python 3.8 or higher
- No external libraries required (standard library only)

---

## Usage

```bash
python scanner.py [OPTIONS]
```

| Argument | Default | Description |
|---|---|---|
| `-t`, `--target` | `scanme.nmap.org` | Target IP or hostname |
| `-p`, `--ports` | `1-1024` | Port(s) to scan |
| `-n`, `--threads` | `100` | Number of concurrent threads |
| `--timeout` | `1.0` | Socket timeout per port (seconds) |
| `--benchmark` | off | Run with 10/50/100/200 threads and print comparison table |

### Port Format Options

```
-p 80               # Single port
-p 22,80,443        # Comma-separated
-p 1-1024           # Range
-p 22,80,1000-1010  # Mixed
```

### Examples

```bash
# Default scan (scanme.nmap.org, ports 1-1024, 100 threads)
python scanner.py

# Custom target and ports
python scanner.py -t 192.168.1.1 -p 22,80,443 -n 150

# Run benchmark (compares 10, 50, 100, 200 threads)
python scanner.py -t scanme.nmap.org -p 1-1024 --benchmark
```

---

## Output

Results are printed to the terminal in real time. A full log is saved automatically to `logs/scan_<timestamp>.log`.

```
[*] Resolved scanme.nmap.org -> 45.33.32.156
[*] Target   : 45.33.32.156
[*] Ports    : 1-1024 (1024 ports)
[*] Threads  : 100
--------------------------------------------------
  [OPEN]  Port 22/TCP
  [OPEN]  Port 80/TCP

[*] Completed in 11.13s
  Open  : 2
  Closed: 1022
```

---

## Design Decisions

**ThreadPoolExecutor** was chosen over manual thread creation because it manages a reusable pool automatically and avoids the overhead of creating/destroying threads per port. `as_completed()` lets results be processed as soon as each thread finishes.

**threading.Lock** protects all log file writes. Without it, concurrent threads writing to the same file would produce interleaved or corrupted entries. The lock is acquired before each write and released immediately after.

**Timestamped log files** are created using `os.makedirs()` so each scan gets its own file and previous results are never overwritten.

**Daemon threads** are used by default in ThreadPoolExecutor, so the tool exits cleanly on Ctrl+C without threads blocking shutdown.

---

## Thread-Safety Rationale

The only shared mutable resource in this tool is the log file. A single global `threading.Lock()` (`log_lock`) ensures only one thread writes at a time. There are no shared counters or lists mutated by threads, so no additional synchronization is needed beyond the file lock.

---

## File Structure

```
phase-1/
├── scanner.py       # Main tool
├── README.md        # This file
└── logs/            # Auto-created on first run
    └── scan_<timestamp>.log
```

---

## Team Members

| Name | Student ID |
|---|---|
| سعيد أبو سورد | 202111439 |
| قصي العبسي | 202120415 |
| محمد الحرازنه | 202411149 |

**Instructor:** Dr. Mohammad Arafah
