# logcc
```
A TOOL FOR AUTO MITRE ADVERSARY RUNNING AND CAPTURING SYSTEM EVENTS

It is a command log correlation analyzer,
combining different tools such as auditd for tracking command executions,
ebpf bcc lttng -> for system level log correlation.
LogMine for log correlation with pattern matching.

Easy dataset preparation for cve with logs.


```
# IDS
```
This tool contain 2 scripts for collecting  logs and analysing log based on mitre attacks.
run make-logc.sh for virtual environment creation.
```




# main log structure for logc
```
/var/log/caldera_attacks/YYYYMMDD_HHMMSS/

auth_initial.log

syslog_initial.log

kern_initial.log

audit_initial.log

network_capture.pcap

collector.log

[updated log files with timestamps]
```

# Usage

use logc for .log genertaions
Use clogcsv for create csv of logs.

