# logc
```
A Mitre based log analysis tool for linux systems.

This tool contain 2 scripts for collecting  logs and analysing log based on mitre attacks.
run make-logc.sh for virtual environment creation.
```

# mitre
```
Also added a quick installation script for mitre also.
run make-mitre.sh
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

