# port-scan-ids

A packet sniffer and intrusion detection tool that detects port scans.

> **Authorized use only.** Run this only on networks and systems you own
> or have explicit permission to test.

# Port Scan Detector

A small intrusion detection tool in Python that watches network traffic and prints an alert when it spots a port scan.

## How it works

The detector watches TCP SYN packets. If one IP address touches more than 15 different ports within 10 seconds, it prints an ALERT. After an alert, the same IP is not reported again for 30 seconds, so one scan produces one alert, and a new scan later is reported again.

A slow scan isn't flagged because ports older than 10 seconds are dropped from the window, so at one port per second the count never gets above about 10.

## Settings

| Name | Value | Meaning |
|------|-------|---------|
| `WINDOW` | 10 | How many seconds of activity to remember |
| `THRESHOLD` | 15 | How many different ports trigger an alert |
| `COOLDOWN` | 30 | Seconds before the same IP can alert again |

## Run it

```bash
sudo venv/bin/python sniffer.py
```

In another terminal, run a fast scan:

```bash
sudo nmap -sS -p 1-50 --max-rate 10 127.0.0.1
```

A sample capture of this scan is included as `scan.pcap`.

## Limitations

Scans slower than about one port every 0.67 seconds stay under the threshold and are not detected. Raising `WINDOW` or lowering `THRESHOLD` catches slower scans, but increases false alarms from normal traffic.

