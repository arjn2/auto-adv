#!/usr/bin/env python3

import os
import sys
import time
import shutil
import subprocess
import logging
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogCollector:
    def __init__(self):
        self.base_dir = "/var/log"
        self.output_dir = f"/var/log/caldera_attacks/{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.log_files = {
            'auth': '/var/log/auth.log',
            'syslog': '/var/log/syslog',
            'kern': '/var/log/kern.log',
            'audit': '/var/log/audit/audit.log'
        }
        self.tcpdump_process = None
        self.setup_logging()

    def setup_logging(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'{self.output_dir}/collector.log'),
                logging.StreamHandler()
            ]
        )

    def start_tcpdump(self):
        try:
            pcap_file = f"{self.output_dir}/network_capture.pcap"
            self.tcpdump_process = subprocess.Popen(
                ['tcpdump', '-i', 'any', '-w', pcap_file, 'not', 'port', '22'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logging.info(f"Started tcpdump capture to {pcap_file}")
        except Exception as e:
            logging.error(f"Failed to start tcpdump: {str(e)}")

    def copy_initial_logs(self):
        for log_type, log_path in self.log_files.items():
            try:
                if os.path.exists(log_path):
                    shutil.copy2(log_path, f"{self.output_dir}/{log_type}_initial.log")
                    logging.info(f"Copied {log_path} to output directory")
            except Exception as e:
                logging.error(f"Failed to copy {log_path}: {str(e)}")

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, output_dir):
        self.output_dir = output_dir

    def on_modified(self, event):
        if event.is_directory:
            return
        
        try:
            filename = os.path.basename(event.src_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dest_path = f"{self.output_dir}/{filename}_{timestamp}"
            
            shutil.copy2(event.src_path, dest_path)
            logging.info(f"Updated log file detected: {filename}")
            
            # Parse for specific attack indicators
            self.analyze_log_file(event.src_path)
        except Exception as e:
            logging.error(f"Error handling modified file {event.src_path}: {str(e)}")

    def analyze_log_file(self, file_path):
        indicators = {
            'Failed password': 'Authentication Failure',
            'session opened': 'New Session',
            'COMMAND': 'Command Execution',
            'USER_CMD': 'User Command',
            'SYSCALL': 'System Call'
        }

        try:
            with open(file_path, 'r') as f:
                content = f.readlines()[-100:]  # Read last 100 lines
                for line in content:
                    for indicator, description in indicators.items():
                        if indicator in line:
                            logging.warning(f"Attack Indicator Found - {description}: {line.strip()}")
        except Exception as e:
            logging.error(f"Error analyzing log file: {str(e)}")

def main():
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)

    collector = LogCollector()
    logging.info("Starting log collection...")

    # Start network capture
    collector.start_tcpdump()

    # Copy initial log states
    collector.copy_initial_logs()

    # Set up file monitoring
    event_handler = LogFileHandler(collector.output_dir)
    observer = Observer()
    
    # Monitor specific log files
    for log_path in collector.log_files.values():
        if os.path.exists(log_path):
            observer.schedule(event_handler, os.path.dirname(log_path), recursive=False)

    observer.start()
    logging.info("Log monitoring started. Press Ctrl+C to stop...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        if collector.tcpdump_process:
            collector.tcpdump_process.terminate()
        logging.info("Log collection stopped")

    observer.join()

if __name__ == "__main__":
    main()
