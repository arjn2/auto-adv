import psutil
import time
import csv
import threading
import queue
import os
import subprocess
from datetime import datetime
from collections import defaultdict
import re

class AuditLogCollector:
    def __init__(self):
        self.audit_log = "/var/log/audit/audit.log"
        
    def get_command_events(self):
        command_logs = {}
        try:
            process = subprocess.Popen(['ausearch', '-m', 'execve'], stdout=subprocess.PIPE)
            output = process.communicate()[0].decode('utf-8')
            for line in output.splitlines():
                if 'exe=' in line:
                    parts = line.split()
                    pid = next((p.split('=')[1] for p in parts if p.startswith('pid=')), None)
                    exe = next((p.split('=')[1] for p in parts if p.startswith('exe=')), None)
                    if pid and exe:
                        command_logs[pid] = {'command': exe, 'log': line}
        except Exception as e:
            print(f"Error collecting audit logs: {e}")
        return command_logs

class LogCollector:
    def __init__(self):
        self.log_sources = [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/kern.log"
        ]
        
    def collect_logs(self):
        logs = defaultdict(list)
        for source in self.log_sources:
            try:
                with open(source, 'r') as f:
                    logs[source] = f.readlines()
            except FileNotFoundError:
                print(f"Log source {source} not found.")
        return logs

class LogMineCorrelator:
    def __init__(self):
        self.pattern_cache = {}
        
    def get_log_pattern(self, log_line):
        if log_line in self.pattern_cache:
            return self.pattern_cache[log_line]
            
        # Remove timestamps and variable data
        pattern = re.sub(r'\d+', '*', log_line)
        pattern = re.sub(r'([a-zA-Z]+)=([^ ]+)', r'\1=*', pattern)
        
        self.pattern_cache[log_line] = pattern
        return pattern
        
    def correlate_logs(self, command_events, system_logs):
        correlated_data = []
        
        for pid, event in command_events.items():
            correlated_entry = {
                'command': event['command'],
                'audit_log': event['log'],
                'correlated_logs': defaultdict(list)
            }
            
            cmd_pattern = self.get_log_pattern(event['command'])
            
            for source, logs in system_logs.items():
                for log in logs:
                    log_pattern = self.get_log_pattern(log)
                    
                    # Check for pattern similarity or command presence
                    if (cmd_pattern in log_pattern or 
                        event['command'] in log or 
                        pid in log):
                        correlated_entry['correlated_logs'][source].append(log.strip())
                        
            correlated_data.append(correlated_entry)
            
        return correlated_data

class ProcessTracker:
    def __init__(self):
        self.tracked_processes = set()
        
    def track_new_processes(self):
        new_processes = set()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.pid not in self.tracked_processes:
                    new_processes.add(proc.pid)
                    self.tracked_processes.add(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return new_processes

class CSVWriter:
    def write_correlation_csv(self, correlated_data, log_sources):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}.csv"
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Command', 'Audit_Log'] + log_sources)
            
            for entry in correlated_data:
                row = [
                    entry['command'],
                    entry['audit_log']
                ]
                for source in log_sources:
                    row.append(','.join(entry['correlated_logs'][source]))
                writer.writerow(row)
                
        print(f"Correlated logs written to {filename}")

class LogCorrelator:
    def __init__(self):
        self.audit_collector = AuditLogCollector()
        self.log_collector = LogCollector()
        self.correlator = LogMineCorrelator()
        self.csv_writer = CSVWriter()
        self.process_tracker = ProcessTracker()
        self.running = True
        
    def correlate_logs(self):
        while self.running:
            # Track new processes
            new_processes = self.process_tracker.track_new_processes()
            
            if new_processes:
                # Collect and correlate logs
                command_events = self.audit_collector.get_command_events()
                system_logs = self.log_collector.collect_logs()
                correlated_data = self.correlator.correlate_logs(command_events, system_logs)
                
                # Write results
                self.csv_writer.write_correlation_csv(
                    correlated_data, 
                    self.log_collector.log_sources
                )
            
            time.sleep(1)
    
    def stop(self):
        self.running = False

if __name__ == "__main__":
    try:
        log_correlator = LogCorrelator()
        log_correlator.correlate_logs()
    except KeyboardInterrupt:
        log_correlator.stop()
        print("\nStopping log correlation...")
