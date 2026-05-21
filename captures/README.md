# Capture Evidence

Place local `.pcap`, `.pcapng`, and Wireshark screenshots here when preparing reports or presentations.

By default, packet capture files and screenshots in this folder are ignored by Git to avoid committing large or sensitive evidence files.

Recommended command:

```bash
sudo tcpdump -i any port 8000 -w captures/ascon-demo.pcap
```
