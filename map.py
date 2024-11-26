#!/usr/bin/env python3

import os
import re
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class MITRELogAnalyzer:
    def __init__(self):
        self.log_files = {
            'auth': '/var/log/auth.log',
            'syslog': '/var/log/syslog',
            'audit': '/var/log/audit/audit.log'
        }
        
        self.mitre_patterns = {
            'Initial Access': [
                r'\b(ssh.*failed|invalid user|failed password|unauthorized)\b',
                r'\b(exploit|remote access attempt|malicious|drive-by)\b'
            ],
            'Execution': [
                r'\b(COMMAND|USER_CMD|executed|spawn|exec)\b',
                r'\b(script|shell|powershell|cmd.exe)\b'
            ],
            'Persistence': [
                r'\b(cron|scheduled task|startup|service created)\b',
                r'\b(new service|daemon|systemctl)\b'
            ],
            'Privilege Escalation': [
                r'\b(sudo|su |root|administrator|privilege)\b',
                r'\b(setuid|setgid|chmod.*\+s)\b'
            ],
            'Defense Evasion': [
                r'\b(cleared|deleted|removed|disabled.*logging)\b',
                r'\b(tamper|modify|corrupt|disable)\b'
            ],
            'Credential Access': [
                r'\b(password|credential|hash|kerberos|ticket)\b',
                r'\b(dump|extract|harvest|steal)\b'
            ],
            'Discovery': [
                r'\b(enumerate|scan|query|list|discovery)\b',
                r'\b(network connection|process list|user list)\b'
            ],
            'Lateral Movement': [
                r'\b(remote|lateral|movement|spread)\b',
                r'\b(rdp|winrm|psexec|ssh)\b'
            ],
            'Collection': [
                r'\b(collect|gather|capture|dump|archive)\b',
                r'\b(data.*extraction|screen.*capture)\b'
            ],
            'Command and Control': [
                r'\b(beacon|callback|c2|command.*control)\b',
                r'\b(reverse.*shell|remote.*access)\b'
            ],
            'Exfiltration': [
                r'\b(exfil|transfer|upload|download)\b',
                r'\b(compress|encrypt|stage|copy)\b'
            ],
            'Impact': [
                r'\b(encrypt|corrupt|delete|destroy|wipe)\b',
                r'\b(ransom|denial|service.*stop)\b'
            ]
        }
        
        self.output_file = os.path.expanduser('map.txt')
        self.ensure_output_directory()

    def ensure_output_directory(self):
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

    def write_mapping(self, timestamp, log_file, technique, log_entry):
        with open(self.output_file, 'a') as f:
            f.write(f"[{timestamp}] {log_file} - {technique}\n")
            f.write(f"Log Entry: {log_entry}\n")
            f.write("-" * 80 + "\n")

    def analyze_line(self, log_file, line):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        for technique, patterns in self.mitre_patterns.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.write_mapping(timestamp, log_file, technique, line.strip())
                    return True
        return False

class LogEventHandler(FileSystemEventHandler):
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.file_positions = {}
        self.initialize_file_positions()

    def initialize_file_positions(self):
        for log_name, log_path in self.analyzer.log_files.items():
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    f.seek(0, 2)  # Seek to end
                    self.file_positions[log_path] = f.tell()

    def on_modified(self, event):
        if event.src_path in self.analyzer.log_files.values():
            self.process_new_lines(event.src_path)

    def process_new_lines(self, file_path):
        try:
            with open(file_path, 'r') as f:
                if file_path in self.file_positions:
                    f.seek(self.file_positions[file_path])
                
                new_lines = f.readlines()
                self.file_positions[file_path] = f.tell()

                for line in new_lines:
                    self.analyzer.analyze_line(file_path, line)
        except Exception as e:
            print(f"Error processing {file_path}: {str(e)}")

def main():
    analyzer = MITRELogAnalyzer()
    event_handler = LogEventHandler(analyzer)
    observer = Observer()

    # Monitor each log file
    for log_path in analyzer.log_files.values():
        if os.path.exists(log_path):
            observer.schedule(event_handler, os.path.dirname(log_path), recursive=False)

    observer.start()
    print(f"Started monitoring logs. Mappings will be saved to {analyzer.output_file}")
    print("Press Ctrl+C to stop...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopping log analysis...")
    
    observer.join()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root!")
        exit(1)
    main()
