import psutil
import time
import csv
import threading
import queue
import os
import json
from datetime import datetime
import signal
import sys
import subprocess
import select
import termios
import tty
from collections import defaultdict
import curses
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import shutil

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_queue, start_time=None):
        self.log_queue = log_queue
        self.start_time = start_time
        self.recent_logs = set()
        self.process_tracker = {}

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

                    # Check for indicators in the line
                    self.analyze_line(line, line_hash, log_file_name)

        except Exception as e:
            logging.error(f"Error analyzing log file {file_path}: {str(e)}")

    def analyze_line(self, line, line_hash, log_file_name):
        # Common indicators to look for
        indicators = {
            'cmd': 'Command Execution',
            'exec': 'Program Execution',
            'curl': 'Network Download',
            'wget': 'Network Download',
            'chmod': 'Permission Change',
            'splunkd': 'Agent Execution',
            'connection': 'Network Connection',
            'sudo': 'Privilege Escalation',
            'systemctl': 'Service Management'
        }

        for indicator, description in indicators.items():
            if indicator in line.lower():
                self.record_finding(line_hash, description, indicator, line, log_file_name)
                break

    def record_finding(self, line_hash, adversary_name, command, line, log_file_name):
        self.recent_logs.add(line_hash)
        if len(self.recent_logs) > 1000:
            self.recent_logs.pop()

        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'log_file': log_file_name,
            'type': adversary_name,
            'command': command,
            'raw_log': line.strip(),
            'source': 'log_monitor'
        }
        self.log_queue.put(log_entry)

    def on_modified(self, event):
        if event.is_directory:
            return
        try:
            self.analyze_log_file(event.src_path, os.path.basename(event.src_path))
        except Exception as e:
            logging.error(f"Error handling modified file {event.src_path}: {str(e)}")

class SandcatLogger:
    def __init__(self):
        self.running = True
        self.log_queue = queue.Queue()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"/var/log/sandcat_logs_{timestamp}"
        self.csv_file = os.path.join(self.output_dir, "sandcat_logs.csv")
        self.pcap_file = os.path.join(self.output_dir, "network_capture.pcap")
        self.sandcat_pid = None
        self.server = "http://192.168.203.15:8888"
        self.stats = defaultdict(int)
        self.last_entries = []
        self.screen = None
        self.command_history = []
        self.tcpdump_process = None
        self.log_files = {
            'auth': '/var/log/auth.log',
            'syslog': '/var/log/syslog',
            'kern': '/var/log/kern.log',
            'audit': '/var/log/audit/audit.log'
        }

        # Create output directory
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(self.output_dir, 'logger.log')),
                logging.StreamHandler()
            ]
        )

    def start_network_capture(self):
        """Start tcpdump capture"""
        try:
            self.tcpdump_process = subprocess.Popen(
                ['tcpdump', '-i', 'any', '-w', self.pcap_file, 'not', 'port', '22'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logging.info(f"Started network capture to {self.pcap_file}")
        except Exception as e:
            logging.error(f"Failed to start tcpdump: {str(e)}")

    def find_sandcat_process(self):
        """Find Sandcat process with enhanced detection"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.cmdline()
                if not cmdline:
                    continue
                
                # Check for both curl download and splunkd execution
                if ('curl' in cmdline[0] and self.server in ' '.join(cmdline)) or \
                   ('splunkd' in cmdline[0] and '-server' in cmdline):
                    self.sandcat_pid = proc.pid
                    self.record_process_start(proc)
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def record_process_start(self, process):
        """Record process start details"""
        try:
            with process.oneshot():
                cmdline = ' '.join(process.cmdline())
                create_time = datetime.fromtimestamp(process.create_time())
                parent = process.parent()
                parent_cmd = ' '.join(parent.cmdline()) if parent else 'Unknown'

                log_entry = {
                    'timestamp': create_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'type': 'process_start',
                    'pid': process.pid,
                    'command': cmdline,
                    'parent_pid': parent.pid if parent else 'Unknown',
                    'parent_cmd': parent_cmd,
                    'source': 'process_monitor'
                }
                self.log_queue.put(log_entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.error(f"Error recording process start: {e}")

    def monitor_process_activities(self):
        """Monitor process activities with enhanced tracking"""
        while self.running:
            if not self.sandcat_pid:
                if not self.find_sandcat_process():
                    time.sleep(1)
                    continue

            try:
                process = psutil.Process(self.sandcat_pid)
                self.analyze_process(process)
                
                # Monitor child processes
                for child in process.children(recursive=True):
                    try:
                        self.analyze_process(child)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.sandcat_pid = None
            
            time.sleep(0.1)

    def analyze_process(self, process):
        """Analyze a single process"""
        try:
            with process.oneshot():
                # Get process details
                cmdline = process.cmdline()
                if not cmdline:
                    return

                # Record process metrics
                metrics = {
                    'cpu_percent': process.cpu_percent(),
                    'memory_percent': process.memory_percent(),
                    'num_threads': process.num_threads(),
                    'open_files': len(process.open_files()),
                    'connections': len(process.connections())
                }

                # Record interesting activities
                log_entry = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'type': 'process_activity',
                    'pid': process.pid,
                    'command': ' '.join(cmdline),
                    'metrics': metrics,
                    'source': 'process_monitor'
                }
                self.log_queue.put(log_entry)

                # Update display
                self.last_entries = \
                    ([f"[{log_entry['timestamp']}] PID {process.pid}: {' '.join(cmdline)[:100]}..."] + 
                     self.last_entries)[:10]
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.error(f"Error analyzing process: {e}")

    def log_writer(self):
        """Enhanced log writer with multiple file outputs"""
        with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Timestamp', 'Type', 'PID', 'Command', 'Details', 'Source', 
                'Raw Log'
            ])
            
            while self.running or not self.log_queue.empty():
                try:
                    log_entry = self.log_queue.get(timeout=1)
                    writer.writerow([
                        log_entry.get('timestamp', ''),
                        log_entry.get('type', ''),
                        log_entry.get('pid', ''),
                        log_entry.get('command', ''),
                        json.dumps(log_entry.get('metrics', {})),
                        log_entry.get('source', ''),
                        log_entry.get('raw_log', '')
                    ])
                    f.flush()
                    self.stats['rows_written'] += 1
                except queue.Empty:
                    continue

    def update_display(self):
        """Update terminal display"""
        while self.running:
            try:
                self.screen.clear()
                height, width = self.screen.getmaxyx()
                
                # Display title and status
                self.screen.addstr(0, 0, "Sandcat Process Logger - Live Statistics", curses.A_BOLD)
                self.screen.addstr(1, 0, "=" * (width - 1))
                
                status = "ACTIVE" if self.sandcat_pid else "SEARCHING"
                self.screen.addstr(2, 0, f"Status: {status}", 
                                 curses.A_BOLD | (curses.A_REVERSE if status == "ACTIVE" else 0))
                
                # Display statistics
                self.screen.addstr(4, 0, f"Statistics:", curses.A_BOLD)
                self.screen.addstr(5, 2, f"Events Captured: {self.stats['rows_written']}")
                self.screen.addstr(6, 2, f"Network Capture: {'Active' if self.tcpdump_process else 'Inactive'}")
                
                # Display recent events
                self.screen.addstr(8, 0, "Recent Events:", curses.A_BOLD)
                for i, entry in enumerate(self.last_entries):
                    if 9 + i < height - 2:
                        self.screen.addstr(9 + i, 2, entry[:width-3])
                
                # Display footer
                self.screen.addstr(height-1, 0, "Press '`' to stop logging", curses.A_REVERSE)
                
                self.screen.refresh()
                time.sleep(0.1)
                
            except curses.error:
                continue

    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        if self.tcpdump_process:
            self.tcpdump_process.terminate()
        if self.screen:
            curses.nocbreak()
            self.screen.keypad(False)
            curses.echo()
            curses.endwin()
        logging.info(f"Logging completed. Results written to {self.output_dir}")

    def run(self):
        """Main execution method"""
        if os.geteuid() != 0:
            print("This script requires root privileges. Please run with sudo.")
            sys.exit(1)

        try:
            # Initialize curses
            self.screen = curses.initscr()
            curses.start_color()
            curses.noecho()
            curses.cbreak()
            self.screen.keypad(True)

            # Start network capture
            self.start_network_capture()

            # Set up file monitoring
            event_handler = LogFileHandler(self.log_queue)
            observer = Observer()
            for log_path in self.log_files.values():
                if os.path.exists(log_path):
                    observer.schedule(event_handler, os.path.dirname(log_path), recursive=False)
            observer.start()

            # Start monitoring threads
            threads = [
                threading.Thread(target=self.monitor_process_activities),
                threading.Thread(target=self.log_writer),
                threading.Thread(target=self.update_display)
            ]
            
            for thread in threads:
                thread.daemon = True
                thread.start()

            # Monitor for backtick
            while self.running:
                if self.screen.getch() == ord('`'):
                    self.running = False
                    break

            # Cleanup and wait for threads
            self.cleanup()
            observer.stop()
            observer.join()
            for thread in threads:
                thread.join(timeout=1.0)

        except Exception as e:
            self.cleanup()
            print(f"Error: {e}")
        finally:
            self.cleanup()

if __name__ == "__main__":
    logger = SandcatLogger()
    logger.run()
