#!/usr/bin/env python3
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
import logging
import logging.handlers
from systemd import journal
from collections import defaultdict
import audit
import inotify.adapters
import re

class CalderaMonitor:
    def __init__(self):
        self.running = True
        self.log_queue = queue.Queue()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = "/var/log/caldera-monitor"
        self.csv_file = os.path.join(self.output_dir, f"caldera_logs_{timestamp}.csv")
        self.ability_file = os.path.join(self.output_dir, f"ability_logs_{timestamp}.csv")
        self.target_pid = None
        self.stats = defaultdict(int)
        self.command_history = set()
        self.current_ability = None
        self.ability_start_time = None

        # Caldera specific patterns
        self.caldera_patterns = {
            'sandcat': re.compile(r'sandcat|curl.*http.*[8-9][0-9]{3}|splunkd.*-server'),
            'ability': re.compile(r'ability_id=([a-f0-9-]{36})'),
            'command': re.compile(r'command=(.*?)(?:&|$)')
        }
        
        # Setup enhanced logging and monitoring
        self.setup_logging()
        self.setup_audit()
        self.setup_directories()

    def setup_logging(self):
        """Configure enhanced logging with systemd journal integration"""
        self.logger = logging.getLogger('CalderaMonitor')
        self.logger.setLevel(logging.DEBUG)
        
        # Journal handler for system logging
        journal_handler = journal.JournalHandler(
            SYSLOG_IDENTIFIER='caldera-monitor',
            level=logging.INFO
        )
        
        # File handler for detailed debug logging
        debug_handler = logging.handlers.RotatingFileHandler(
            os.path.join(self.output_dir, 'debug.log'),
            maxBytes=50*1024*1024,  # 50MB
            backupCount=5
        )
        debug_handler.setLevel(logging.DEBUG)
        
        # Add handlers
        self.logger.addHandler(journal_handler)
        self.logger.addHandler(debug_handler)

    def setup_audit(self):
        """Setup enhanced audit monitoring"""
        try:
            # Configure audit rules for detailed process tracking
            self.audit_rules = {
                'exec': audit.AUDIT_EXEC,
                'write': audit.AUDIT_WRITE,
                'attr': audit.AUDIT_ATTR,
                'socket': audit.AUDIT_SOCKET
            }
            
            for rule_type in self.audit_rules.values():
                audit.add_rule(rule_type, audit.AUDIT_ALWAYS)
                
        except Exception as e:
            self.logger.error(f"Failed to setup audit: {e}")

    def setup_directories(self):
        """Setup directory structure with proper permissions"""
        try:
            os.makedirs(self.output_dir, mode=0o750, exist_ok=True)
            os.chmod(self.output_dir, 0o750)
            os.chown(self.output_dir, 0, 0)  # root:root
        except Exception as e:
            self.logger.error(f"Failed to setup directories: {e}")

    def find_caldera_process(self):
        """Enhanced Caldera process detection"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.cmdline())
                if not cmdline:
                    continue
                
                if self.caldera_patterns['sandcat'].search(cmdline):
                    self.target_pid = proc.pid
                    
                    # Check for ability ID in command
                    ability_match = self.caldera_patterns['ability'].search(cmdline)
                    if ability_match:
                        ability_id = ability_match.group(1)
                        self.track_ability_execution(ability_id, cmdline)
                    
                    if cmdline not in self.command_history:
                        self.command_history.add(cmdline)
                        self.log_event(
                            'process_start',
                            cmdline,
                            'Caldera agent process started'
                        )
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def track_ability_execution(self, ability_id, command):
        """Track individual ability executions"""
        if ability_id != self.current_ability:
            if self.current_ability:
                # Log completion of previous ability
                duration = time.time() - self.ability_start_time
                self.log_ability(
                    self.current_ability,
                    'completed',
                    f'Duration: {duration:.2f}s'
                )
            
            # Start tracking new ability
            self.current_ability = ability_id
            self.ability_start_time = time.time()
            self.log_ability(ability_id, 'started', command)

    def monitor_process_activities(self):
        """Enhanced process monitoring for Caldera operations"""
        while self.running:
            if not self.target_pid:
                if not self.find_caldera_process():
                    time.sleep(1)
                    continue

            try:
                process = psutil.Process(self.target_pid)
                with process.oneshot():
                    # Monitor system metrics
                    self.monitor_system_metrics(process)
                    
                    # Track file operations
                    self.monitor_file_operations(process)
                    
                    # Monitor network activity
                    self.monitor_network_activity(process)
                    
                    # Track child processes
                    self.monitor_child_processes(process)
                    
                    # Check audit events
                    self.check_audit_events()

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                if self.current_ability:
                    # Log ability termination
                    self.log_ability(
                        self.current_ability,
                        'terminated',
                        'Process ended unexpectedly'
                    )
                    self.current_ability = None
                self.target_pid = None
            
            time.sleep(0.1)

    def monitor_system_metrics(self, process):
        """Monitor detailed system metrics"""
        try:
            cpu_percent = process.cpu_percent()
            memory_info = process.memory_info()
            io_counters = process.io_counters()
            
            if self.current_ability:
                self.log_ability(
                    self.current_ability,
                    'metrics',
                    f'CPU: {cpu_percent}%, Memory: {memory_info.rss/1024/1024:.1f}MB, '
                    f'IO Read: {io_counters.read_bytes/1024:.1f}KB, '
                    f'Write: {io_counters.write_bytes/1024:.1f}KB'
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.warning(f"Failed to monitor system metrics: {e}")

    def monitor_file_operations(self, process):
        """Track file operations with enhanced detail"""
        try:
            open_files = process.open_files()
            for file in open_files:
                file_str = f"File access: {file.path}"
                if file_str not in self.command_history:
                    self.command_history.add(file_str)
                    self.log_event(
                        'file_operation',
                        file.path,
                        f'Access: {file.mode}'
                    )
                    if self.current_ability:
                        self.log_ability(
                            self.current_ability,
                            'file_access',
                            f'Accessed: {file.path}'
                        )
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.warning(f"Failed to monitor file operations: {e}")

    def monitor_network_activity(self, process):
        """Enhanced network activity monitoring"""
        try:
            connections = process.connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    conn_str = f"{conn.laddr}:{conn.raddr}"
                    if conn_str not in self.command_history:
                        self.command_history.add(conn_str)
                        self.log_event(
                            'network_connection',
                            conn_str,
                            f'Type: {conn.type}, Family: {conn.family}'
                        )
                        if self.current_ability:
                            self.log_ability(
                                self.current_ability,
                                'network_activity',
                                f'Connection: {conn_str}'
                            )
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.warning(f"Failed to monitor network activity: {e}")

    def monitor_child_processes(self, process):
        """Monitor child processes with command tracking"""
        try:
            children = process.children(recursive=True)
            for child in process.children(recursive=True):
                try:
                    cmd = ' '.join(child.cmdline())
                    if cmd and cmd not in self.command_history:
                        self.command_history.add(cmd)
                        self.log_event(
                            'command_execution',
                            cmd,
                            f'Child PID: {child.pid}'
                        )
                        if self.current_ability:
                            self.log_ability(
                                self.current_ability,
                                'command',
                                f'Executed: {cmd}'
                            )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.warning(f"Failed to monitor child processes: {e}")

    def check_audit_events(self):
        """Monitor system audit events"""
        try:
            for event in audit.get_events():
                event_str = f"Audit event: {event.type}"
                if event_str not in self.command_history:
                    self.command_history.add(event_str)
                    self.log_event(
                        'audit_event',
                        str(event.type),
                        f'Details: {event.data}'
                    )
                    if self.current_ability:
                        self.log_ability(
                            self.current_ability,
                            'audit',
                            f'Event: {event.type}'
                        )
        except Exception as e:
            self.logger.warning(f"Failed to check audit events: {e}")

    def log_event(self, event_type, command, details):
        """Enhanced event logging"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'event_type': event_type,
            'command': command,
            'details': details,
            'pid': self.target_pid,
            'ability_id': self.current_ability
        }
        self.log_queue.put(('event', log_entry))
        self.stats[event_type] += 1

    def log_ability(self, ability_id, action, details):
        """Log ability-specific activities"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'ability_id': ability_id,
            'action': action,
            'details': details,
            'pid': self.target_pid
        }
        self.log_queue.put(('ability', log_entry))
        self.stats[f'ability_{action}'] += 1

    def log_writer(self):
        """Enhanced log writer with separate event and ability logs"""
        event_writer = None
        ability_writer = None

        try:
            with open(self.csv_file, 'w', newline='') as event_file, \
                 open(self.ability_file, 'w', newline='') as ability_file:
                
                event_writer = csv.writer(event_file)
                ability_writer = csv.writer(ability_file)
                
                # Write headers
                event_writer.writerow([
                    'Timestamp', 'Event Type', 'Command', 'Details', 
                    'PID', 'Ability ID'
                ])
                ability_writer.writerow([
                    'Timestamp', 'Ability ID', 'Action', 'Details', 'PID'
                ])
                
                while self.running or not self.log_queue.empty():
                    try:
                        log_type, log_entry = self.log_queue.get(timeout=1)
                        
                        if log_type == 'event':
                            event_writer.writerow([
                                log_entry['timestamp'],
                                log_entry['event_type'],
                                log_entry['command'],
                                log_entry['details'],
                                log_entry['pid'],
                                log_entry['ability_id']
                            ])
                            event_file.flush()
                        else:  # ability log
                            ability_writer.writerow([
                                log_entry['timestamp'],
                                log_entry['ability_id'],
                                log_entry['action'],
                                log_entry['details'],
                                log_entry['pid']
                            ])
                            ability_file.flush()
                            
                        self.stats['rows_written'] += 1
                    except queue.Empty:
                        continue
                        
        except IOError as e:
            self.logger.error(f"Failed to write to log file: {e}")

    def cleanup(self):
        """Enhanced cleanup procedure"""
        try:
            # Remove audit rules
            for rule_type in self.audit_rules.values():
                try:
                    audit.remove_rule(rule_type, audit.AUDIT_ALWAYS)
                except:
                    pass

            # Final statistics logging
            self.logger.info("Monitoring completed. Statistics:")
            for event_type, count in self.stats.items():
                self.logger.info(f"{event_type}: {count} events")

            # Log final status of current ability if any
            if self.current_ability:
                duration = time.time() - self.ability_start_time
                self.log_ability(
                    self.current_ability,
                    'terminated',
                    f'Monitor shutdown - Duration: {duration:.2f}s'
                )

        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")

    def run(self):
        """Main execution method"""
        if os.geteuid() != 0:
            print("This script requires root privileges. Please run with sudo.")
            sys.exit(1)

        # Verify developer mode
        if not os.path.exists('/etc/developer_mode'):
            print("System not in developer mode. Please run setup script first.")
