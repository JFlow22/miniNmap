# miniNmap
A Python script doing a bit of Nmap functionality. Can be used for slow scanning and with multiple port choices.

A port scanner which preform a SYN scan

options:
-h, --help                show this help message and exit
--ip IP                   The target IP (required)
-f FILE, --file FILE      File containing port numbers
-p PORTS, --ports PORTS   Ports range to scan
--exclude-ports EXCLUDE   Ports to exclude from scan (default is the top scanned ports)
-t0                       Setting a timeout for the scan (Paranoid: 300 seconds)
-t1                       Setting a timeout for the scan (Sneaky: 15 seconds)
-t2                       Setting a timeout for the scan (Normal: 1 seconds)
-t3                       Setting a timeout for the scan (Aggressive: 0.5 seconds)
-t4                       Setting a timeout for the scan (Insane: 0.25 seconds)
