import threading
import subprocess
import csv
from datetime import datetime
import time
from queue import Queue, Empty
import os
import re

class LogMonitor:
    def __init__(self):
        self.log_queue = Queue()
        self.command_queue = Queue()
        self.running = True
        self.csv_filename = f"log_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.recent_commands = []
        
    def monitor_kernel(self):
        try:
            process = subprocess.Popen(['dmesg', '-w'], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     text=True)
            while self.running:
                line = process.stdout.readline()
                if line:
                    message = line.strip()
                    trigger = self.get_trigger("kernel", message)
                    self.log_queue.put({
                        "source": "kernel",
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "message": message,
                        "trigger": trigger
                    })
        except Exception as e:
            print(f"Kernel monitoring error: {e}")

    def monitor_pam(self):
        try:
            process = subprocess.Popen(['journalctl', '-f'], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     text=True)
            while self.running:
                line = process.stdout.readline()
                if line and 'pam' in line.lower():
                    message = line.strip()
                    trigger = self.get_trigger("pam", message)
                    self.log_queue.put({
                        "source": "pam",
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "message": message,
                        "trigger": trigger
                    })
        except Exception as e:
            print(f"PAM monitoring error: {e}")

    def monitor_commands(self):
        try:
            process = subprocess.Popen(['ausearch', '-m', 'execve', '-i', '-ts', 'recent'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True)
            while self.running:
                line = process.stdout.readline()
                if line:
                    command = self.extract_command(line)
                    if command:
                        self.recent_commands.append({
                            'command': command,
                            'timestamp': datetime.now(),
                            'pid': self.extract_pid(line)
                        })
                        self.recent_commands = self.recent_commands[-100:]
                        self.log_queue.put({
                            "source": "command",
                            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "message": f"Command executed: {command}",
                            "trigger": f"User Command: {command}"
                        })
        except Exception as e:
            print(f"Command monitoring error: {e}")

    def extract_command(self, line):
        match = re.search(r'exe="([^"]+)"', line)
        return match.group(1) if match else None

    def extract_pid(self, line):
        match = re.search(r'pid=(\d+)', line)
        return match.group(1) if match else None

    def get_trigger(self, source, message):
        # Check recent commands first
        for cmd in reversed(self.recent_commands):
            if (datetime.now() - cmd['timestamp']).seconds < 5:
                if cmd['command'] in message or cmd['pid'] in message:
                    return f"Command Execution: {cmd['command']}"

        # Default triggers based on message content
        triggers = {
            'kernel': {
                'Linux version': 'System Event: Kernel initialization',
                'Command line': 'System Event: Boot sequence',
                'BIOS': 'Hardware Event: BIOS initialization',
                'memory': 'Hardware Event: Memory operation',
                'CPU': 'Hardware Event: CPU operation',
                'USB': 'Hardware Event: USB activity'
            },
            'pam': {
                'authentication': 'Authentication Event',
                'session': 'Session Event',
                'sudo': 'Privileged Command Execution',
                'login': 'Login Attempt'
            },
            'command': {
                'execve': 'Command Execution',
                'open': 'File Access',
                'connect': 'Network Connection'
            }
        }

        for keyword, trigger in triggers.get(source, {}).items():
            if keyword.lower() in message.lower():
                return trigger

        return "System Event"

    def write_logs(self):
        with open(self.csv_filename, 'w', newline='') as csvfile:
            fieldnames = ["Source", "Timestamp", "Message", "Trigger"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            while self.running:
                try:
                    log_entry = self.log_queue.get(timeout=1)
                    writer.writerow({
                        "Source": log_entry["source"],
                        "Timestamp": log_entry["timestamp"],
                        "Message": log_entry["message"],
                        "Trigger": log_entry["trigger"]
                    })
                    csvfile.flush()
                except Empty:
                    continue
                except Exception as e:
                    print(f"Error writing to CSV: {e}")

    def start_monitoring(self):
        threads = []
        
        # Create monitoring threads
        threads.append(threading.Thread(target=self.monitor_kernel))
        threads.append(threading.Thread(target=self.monitor_pam))
        threads.append(threading.Thread(target=self.monitor_commands))
        threads.append(threading.Thread(target=self.write_logs))
        
        # Start all threads
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        print(f"Monitoring started. Logs are being written to {self.csv_filename}")
        print("Press Ctrl+C to stop monitoring...")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
            self.running = False
            
            for thread in threads:
                thread.join(timeout=2)
            
            print("Monitoring stopped.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        exit(1)
        
    monitor = LogMonitor()
    monitor.start_monitoring()
