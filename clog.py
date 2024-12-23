#!/usr/bin/env python3

import os
import sys
import time
import json
import shutil
import subprocess
import logging
import csv
import threading
import keyboard
import tqdm
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from queue import Queue
from collections import defaultdict

class SignatureLoader:
    @staticmethod
    def load_signatures():
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            signature_path = os.path.join(script_dir, 'signatures.json')

            with open(signature_path, 'r') as f:
                signatures = json.load(f)

            # Extract whitelisted services
            whitelisted_services = set(signatures.get('whitelisted_services', []))

            # Flatten all technique signatures for easier searching
            flattened_indicators = {}
            techniques = signatures.get('techniques', {})

            for tactic, technique_group in techniques.items():
                for technique_id, technique_info in technique_group.items():
                    if isinstance(technique_info, dict) and 'signatures' in technique_info:
                        for pattern, description in technique_info['signatures'].items():
                            # Include MITRE ID and tactic in description
                            full_description = f"{description} [{tactic.upper()} - {technique_id}]"
                            flattened_indicators[pattern] = full_description

                    # Special handling for Caldera-specific patterns
                    if tactic == 'caldera_specific' and isinstance(technique_info, dict):
                        for pattern, description in technique_info.get('signatures', {}).items():
                            flattened_indicators[pattern] = f"{description} [CALDERA]"

            # Extract process monitoring patterns
            discovery_processes = set()
            if 'caldera_specific' in techniques:
                process_checks = techniques['caldera_specific'].get('process_checks', {})
                if 'signatures' in process_checks:
                    discovery_processes = {key.split('grep')[-1].strip()
                                           for key in process_checks['signatures'].keys()
                                           if 'grep' in key}

            # Add critical file monitoring
            file_monitoring = signatures.get('file_monitoring', {})
            critical_files = set(file_monitoring.get('critical_files', []))
            critical_dirs = set(file_monitoring.get('critical_directories', []))

            return {
                'discovery_processes': discovery_processes,
                'whitelisted_services': whitelisted_services,
                'indicators': flattened_indicators,
                'critical_files': critical_files,
                'critical_directories': critical_dirs,
                'metadata': signatures.get('metadata', {})
            }

        except Exception as e:
            logging.error(f"Error loading signatures.json: {str(e)}")
            logging.error("Using default empty signatures")
            return {
                'discovery_processes': set(),
                'whitelisted_services': set(),
                'indicators': {},
                'critical_files': set(),
                'critical_directories': set(),
                'metadata': {}
            }

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_queue, start_time=None):
        self.log_queue = log_queue
        self.start_time = start_time
        self.recent_logs = set()

        # Load signatures from JSON
        signatures = SignatureLoader.load_signatures()
        self.discovery_processes = signatures['discovery_processes']
        self.whitelisted_services = signatures['whitelisted_services']
        self.indicators = signatures['indicators']
        self.critical_files = signatures['critical_files']
        self.critical_dirs = signatures['critical_directories']

    def is_whitelisted_service(self, log_line):
        return any(service.lower() in log_line.lower()
                   for service in self.whitelisted_services)

    def is_discovery_activity(self, log_line):
        return any(f"grep.*{proc}" in log_line.lower()
                   for proc in self.discovery_processes)

    def analyze_log_file(self, file_path, log_file_name):
        if not os.path.exists(file_path):
            return

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.readlines()[-100:]
                for line in content:
                    line_hash = hash(line.strip())
                    if line_hash in self.recent_logs:
                        continue

                    if self.start_time:
                        try:
                            timestamp_str = ' '.join(line.split()[:3])
                            log_time = datetime.strptime(f"{timestamp_str} {datetime.now().year}",
                                                       "%b %d %H:%M:%S %Y")
                            if log_time < self.start_time:
                                continue
                        except:
                            continue

                    # Skip whitelisted services
                    if self.is_whitelisted_service(line):
                        continue

                    # Check for discovery activity
                    if self.is_discovery_activity(line):
                        self.record_finding(line_hash, "Process Discovery",
                                             "Discovery Activity", line, log_file_name)
                        continue

                    # Check other indicators
                    for indicator, description in self.indicators.items():
                        if indicator in line.lower():
                            self.record_finding(line_hash, indicator,
                                                 description, line, log_file_name)
                            break

        except Exception as e:
            logging.error(f"Error analyzing log file {file_path}: {str(e)}")

    def record_finding(self, line_hash, indicator, description, line, log_file_name):
        self.recent_logs.add(line_hash)
        if len(self.recent_logs) > 1000:
            self.recent_logs.pop()

        log_entry = [
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            log_file_name,
            indicator,
            description,
            line.strip()
        ]
        self.log_queue.put(log_entry)

        logging.warning(
            f"Indicator Found in {log_file_name} - {description} [Signature: {indicator}]: {line.strip()}"
        )

class LogCollector:
    def __init__(self, start_time=None):
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.start_time = start_time
        self.base_dir = "/var/log"
        self.output_dir = f"/var/log/caldera_attacks/{self.timestamp}"
        self.csv_path = os.path.join(self.output_dir, "attack_indicators.csv")
        self.final_csv_path = os.path.join(self.output_dir, "final_compiled_logs.csv")
        self.warning_logs = []  # Store warning logs for final compilation
        self.log_files = {
            'auth': '/var/log/auth.log',
            'syslog': '/var/log/syslog',
            'kern': '/var/log/kern.log',
            'audit': '/var/log/audit/audit.log'
        }
        self.logging_services = {
            'rsyslog': 'rsyslog.service',
            'auditd': 'auditd.service'
        }
        self.tcpdump_process = None
        self.stop_event = threading.Event()
        self.log_queue = Queue()

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        self.setup_logging()
        self.setup_csv()

    def check_logging_services(self):
        """Check and restart logging services if needed"""
        logging.info("Checking logging services status...")

        for service_name, service_unit in self.logging_services.items():
            try:
                # Check service status
                status = subprocess.run(['systemctl', 'is-active', service_unit],
                                     capture_output=True, text=True)

                if status.stdout.strip() != 'active':
                    logging.warning(f"{service_name} is not active. Attempting to start...")

                    # Try to start the service
                    subprocess.run(['systemctl', 'start', service_unit], check=True)
                    logging.info(f"Successfully started {service_name}")
                else:
                    logging.info(f"{service_name} is running properly")

            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to manage {service_name}: {str(e)}")

        # Ensure log files exist and are writable
        for log_name, log_path in self.log_files.items():
            if not os.path.exists(log_path):
                logging.warning(f"{log_path} does not exist. Creating it...")
                try:
                    with open(log_path, 'a') as f:
                        pass  # Create empty file
                    os.chmod(log_path, 0o644)  # Set proper permissions
                    logging.info(f"Created {log_path}")
                except Exception as e:
                    logging.error(f"Failed to create {log_path}: {str(e)}")

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )

    def setup_csv(self):
        try:
            with open(self.csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(['Timestamp', 'Log File', 'Indicator Type', 'Description', 'Raw Log Entry'])
            logging.info(f"Created CSV log file at {self.csv_path}")
        except Exception as e:
            logging.error(f"Failed to create CSV file: {str(e)}")

    def parse_log_timestamp(self, line):
        """Parse timestamp from log line with multiple format support"""
        try:
            # Common log timestamp formats
            timestamp_str = ' '.join(line.split()[:3])
            current_year = datetime.now().year

            # Try standard syslog format
            try:
                return datetime.strptime(f"{timestamp_str} {current_year}",
                                       "%b %d %H:%M:%S %Y")
            except ValueError:
                pass

            # Try alternative formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%b %d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S"
            ]

            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue

            return None
        except:
            return None

    def compile_final_csv(self):
        logging.info("Compiling final CSV of warning logs...")

        try:
            with open(self.final_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile, delimiter='|', quotechar='"', quoting=csv.QUOTE_MINIMAL)

                # Write headers
                writer.writerow([
                    'Timestamp',
                    'Source Log',
                    'Event Type',
                    'Description',
                    'Full Log Entry'
                ])

                # Get all warning logs from monitored files
                warning_logs = []
                indicators = {
                    'Failed password': 'Authentication Failure',
                    'session opened': 'New Session',
                    'COMMAND': 'Command Execution',
                    'USER_CMD': 'User Command',
                    'SYSCALL': 'System Call',
                    'Authentication failure': 'Auth Failure',
                    'Invalid user': 'Invalid Access',
                    'sudo:': 'Sudo Event',
                    'error: PAM': 'PAM Error',
                    'segfault': 'Program Crash'
                }

                for log_name, log_path in self.log_files.items():
                    if os.path.exists(log_path):
                        try:
                            with open(log_path, 'r', encoding='utf-8') as f:
                                lines = f.readlines()
                                with tqdm.tqdm(total=len(lines),
                                             desc=f"Processing {log_name}",
                                             bar_format='{l_bar}{bar:30}{r_bar}') as pbar:

                                    for line in lines:
                                        # Check timestamp if start_time is set
                                        if self.start_time:
                                            try:
                                                log_time = self.parse_log_timestamp(line)
                                                if log_time and log_time < self.start_time:
                                                    pbar.update(1)
                                                    continue
                                            except:
                                                pbar.update(1)
                                                continue

                                        # Check for indicators
                                        for indicator, description in indicators.items():
                                            if indicator in line:
                                                timestamp = self.parse_log_timestamp(line)
                                                if timestamp:
                                                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                                                else:
                                                    timestamp_str = 'Unknown'

                                                warning_logs.append([
                                                    timestamp_str,
                                                    log_name,
                                                    indicator,
                                                    description,
                                                    line.strip()
                                                ])
                                                break
                                        pbar.update(1)
                        except Exception as e:
                            logging.error(f"Error processing {log_path}: {str(e)}")

                # Sort warning logs by timestamp
                warning_logs.sort(key=lambda x: x[0])

                # Write sorted logs to CSV
                total_warnings = len(warning_logs)
                with tqdm.tqdm(total=total_warnings,
                             desc="Writing warning logs to CSV",
                             bar_format='{l_bar}{bar:30}{r_bar}') as pbar:
                    for log_entry in warning_logs:
                        writer.writerow(log_entry)
                        pbar.update(1)

            logging.info(f"Final CSV compiled at: {self.final_csv_path}")
            logging.info(f"Total warning logs collected: {total_warnings}")

        except Exception as e:
            logging.error(f"Error compiling final CSV: {str(e)}")

    def start_tcpdump(self):
        try:
            pcap_file = os.path.join(self.output_dir, "network_capture.pcap")
            self.tcpdump_process = subprocess.Popen(
                ['tcpdump', '-i', 'any', '-w', pcap_file, 'not', 'port', '22'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logging.info(f"Started tcpdump capture to {pcap_file}")
        except Exception as e:
            logging.error(f"Failed to start tcpdump: {str(e)}")

    def csv_writer_thread(self):
        while not self.stop_event.is_set() or not self.log_queue.empty():
            try:
                if not self.log_queue.empty():
                    log_entry = self.log_queue.get()
                    with open(self.csv_path, 'a', newline='', encoding='utf-8') as csvfile:
                        writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow(log_entry)
                    self.log_queue.task_done()
                else:
                    time.sleep(0.1)
            except Exception as e:
                logging.error(f"Error writing to CSV: {str(e)}")

def keyboard_monitor(stop_event):
    keyboard.wait('`')
    stop_event.set()
    logging.info("Stop signal received. Shutting down...")

def get_user_timeline_choice():
    while True:
        choice = input("Do you want to scan logs from current time only? (yes/no): ").lower()
        if choice in ['yes', 'no']:
            return choice == 'yes'
        print("Please enter 'yes' or 'no'")

def main():
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)

    # Get user's timeline preference
    start_time = datetime.now() if get_user_timeline_choice() else None

    collector = LogCollector(start_time)

    # Check and initialize logging services
    collector.check_logging_services()

    logging.info("Starting log collection...")
    if start_time:
        logging.info(f"Collecting logs from: {start_time}")
    else:
        logging.info("Collecting all available logs")

    # Start network capture
    collector.start_tcpdump()

    # Start CSV writer thread
    csv_thread = threading.Thread(target=collector.csv_writer_thread)
    csv_thread.start()

    # Start keyboard monitor thread
    keyboard_thread = threading.Thread(target=keyboard_monitor, args=(collector.stop_event,))
    keyboard_thread.daemon = True
    keyboard_thread.start()

    # Set up file monitoring
    event_handler = LogFileHandler(collector.log_queue, start_time)
    observer = Observer()

    # Monitor specific log files
    for log_path in collector.log_files.values():
        if os.path.exists(log_path):
            observer.schedule(event_handler, os.path.dirname(log_path), recursive=False)

    observer.start()
    logging.info("Log monitoring started. Press ` (backtick) to stop...")

    try:
        while not collector.stop_event.is_set():
            time.sleep(1)
    finally:
        observer.stop()
        if collector.tcpdump_process:
            collector.tcpdump_process.terminate()
        observer.join()
        collector.log_queue.join()  # Wait for remaining logs to be written

        print("\nCompiling final CSV report...")
        collector.compile_final_csv()
        logging.info("Log collection completed")

if __name__ == "__main__":
    main()
