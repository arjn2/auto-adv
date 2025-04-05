#!/usr/bin/env python3
import os
import sys
import psutil
import threading
import queue
import json
import time
import signal
import argparse
import subprocess
import logging
from datetime import datetime, timedelta
import re
from collections import defaultdict
import yaml
import concurrent.futures

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PIDMonitor")

class ProcessMonitor:
    def __init__(self, output_dir=None):
        # Ensure we're running as root
        if os.geteuid() != 0:
            raise PermissionError("This script must be run as root")
            
        # Set up output directory
        self.output_dir = output_dir or f"pid_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Process tracking
        self.monitored_pids = set()
        self.pid_data = {}
        self.process_queue = queue.Queue()
        self.shutdown_flag = threading.Event()
        
        # For storing historical process data
        self.historical_pids = {}
        
        # Create subprocess capturing threads
        self.worker_threads = []
        
        # MITRE ATT&CK mapping
        self.load_mitre_mapping()
        
        # Set up auditd
        self.setup_auditd()

    def load_mitre_mapping(self):
        """Load or create MITRE ATT&CK technique mapping"""
        self.mitre_techniques = {
            # Example mappings - would be expanded in a real implementation
            "ssh": {"technique_id": "T1021.004", "tactic": "lateral-movement", "name": "Remote Services: SSH"},
            "sudo": {"technique_id": "T1548.003", "tactic": "privilege-escalation", "name": "Abuse Elevation Control Mechanism: Sudo"},
            "crontab": {"technique_id": "T1053.003", "tactic": "persistence", "name": "Scheduled Task/Job: Cron"},
            "passwd": {"technique_id": "T1003.008", "tactic": "credential-access", "name": "OS Credential Dumping: /etc/passwd"},
            "python": {"technique_id": "T1059.006", "tactic": "execution", "name": "Command and Scripting Interpreter: Python"}
        }

    def setup_auditd(self):
        """Set up auditd for better process tracking"""
        try:
            # Start auditd service if not running
            subprocess.run(["systemctl", "is-active", "auditd"], check=False, stdout=subprocess.PIPE)
            
            # Add process execution tracking rules
            rules = [
                ["auditctl", "-D"],  # Clear existing rules
                ["auditctl", "-a", "exit,always", "-F", "arch=b64", "-S", "execve", "-k", "command_execution"],
                ["auditctl", "-a", "exit,always", "-F", "arch=b32", "-S", "execve", "-k", "command_execution"],
                ["auditctl", "-w", "/etc/pam.d/", "-p", "wa", "-k", "pam_config"],
                ["auditctl", "-w", "/etc/passwd", "-p", "wa", "-k", "credential_access"],
                ["auditctl", "-a", "exit,always", "-S", "ptrace", "-k", "process_injection"],
                ["auditctl", "-e", "1"]  # Enable auditing
            ]
            
            for rule in rules:
                subprocess.run(rule, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
            logger.info("Auditd configured for process tracking")
        except Exception as e:
            logger.error(f"Failed to configure auditd: {e}")

    def find_pids_by_name(self, process_name):
        """Find all PIDs matching a process name"""
        pids = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if process_name.lower() in proc.info['name'].lower():
                    pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return pids

    def find_kernel_threads(self):
        """Find kernel thread PIDs"""
        kernel_pids = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Kernel threads typically have names in brackets
                if proc.info['name'].startswith('[') and proc.info['name'].endswith(']'):
                    kernel_pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return kernel_pids

    def find_pam_processes(self):
        """Find PAM-related processes"""
        pam_pids = []
        # Common PAM-related process names
        pam_process_names = ["pam", "login", "sshd", "sudo", "su", "systemd-logind"]
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Check process name
                if any(pam_name in proc.info['name'].lower() for pam_name in pam_process_names):
                    pam_pids.append(proc.info['pid'])
                    continue
                
                # Check command line for PAM modules
                cmdline = ' '.join(proc.info.get('cmdline', []))
                if 'pam' in cmdline.lower():
                    pam_pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return pam_pids

    def collect_process_info(self, pid):
        """Collect detailed information about a process"""
        try:
            if not psutil.pid_exists(pid):
                logger.warning(f"PID {pid} no longer exists")
                # Check if we have historical data
                if pid in self.historical_pids:
                    return self.historical_pids[pid]
                return None

            process = psutil.Process(pid)
            
            # Basic process info
            process_info = {
                'pid': process.pid,
                'ppid': process.ppid(),
                'name': process.name(),
                'exe': process.exe() if hasattr(process, 'exe') else '',
                'cmdline': ' '.join(process.cmdline()) if hasattr(process, 'cmdline') else '',
                'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
                'username': process.username(),
                'status': process.status(),
                'terminal': process.terminal() if hasattr(process, 'terminal') else None,
                'cwd': process.cwd() if hasattr(process, 'cwd') else None,
            }
            
            # Get open files
            try:
                process_info['open_files'] = [f.path for f in process.open_files()]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                process_info['open_files'] = []
            
            # Get connections
            try:
                conns = []
                for conn in process.connections():
                    conns.append({
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': str(conn.laddr) if conn.laddr else None,
                        'raddr': str(conn.raddr) if conn.raddr else None,
                        'status': conn.status
                    })
                process_info['connections'] = conns
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                process_info['connections'] = []
            
            # Process children
            try:
                process_info['children'] = []
                for child in process.children(recursive=False):
                    process_info['children'].append({
                        'pid': child.pid,
                        'name': child.name(),
                        'cmdline': ' '.join(child.cmdline()) if hasattr(child, 'cmdline') else ''
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Process tree (ancestry)
            try:
                process_info['ancestry'] = []
                current = process
                while current and current.pid > 1:
                    parent = current.parent()
                    if parent:
                        process_info['ancestry'].append({
                            'pid': parent.pid,
                            'name': parent.name(),
                            'cmdline': ' '.join(parent.cmdline()) if hasattr(parent, 'cmdline') else ''
                        })
                    current = parent
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Store historical data
            self.historical_pids[pid] = process_info
            
            return process_info

        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} no longer exists")
            # Check if we have historical data
            if pid in self.historical_pids:
                return self.historical_pids[pid]
            return None
        except psutil.AccessDenied:
            logger.warning(f"Access denied to process {pid}")
            return None
        except Exception as e:
            logger.error(f"Error collecting info for PID {pid}: {e}")
            return None

    def get_process_logs(self, pid, process_info=None):
        """Get logs related to the process from various sources"""
        logs = defaultdict(list)
        
        # If process_info is provided, use it
        if not process_info:
            process_info = self.collect_process_info(pid)
            if not process_info:
                return {}
        
        # Define time window
        if 'create_time' in process_info:
            try:
                start_time = datetime.fromisoformat(process_info['create_time']) - timedelta(seconds=5)
                end_time = datetime.now() + timedelta(seconds=5)
            except (ValueError, TypeError):
                start_time = datetime.now() - timedelta(minutes=5)
                end_time = datetime.now()
        else:
            start_time = datetime.now() - timedelta(minutes=5)
            end_time = datetime.now()
        
        # Format for journalctl
        start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
        end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Get journal logs
        try:
            cmd = f"journalctl _PID={pid} --since '{start_str}' --until '{end_str}' -o json"
            output = subprocess.check_output(cmd, shell=True, text=True)
            
            # Parse JSON output from journalctl
            for line in output.splitlines():
                try:
                    if line.strip():
                        logs['journal'].append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except subprocess.SubprocessError:
            logger.warning(f"Failed to get journal logs for PID {pid}")
        
        # Get audit logs for the PID
        try:
            cmd = f"ausearch -p {pid} -i"
            output = subprocess.check_output(cmd, shell=True, text=True)
            logs['audit'] = output.splitlines()
        except subprocess.SubprocessError:
            logger.warning(f"Failed to get audit logs for PID {pid}")
        
        # Get dmesg entries that might be related to this PID
        try:
            # Get command name to search in dmesg
            proc_name = process_info.get('name', '')
            if proc_name:
                cmd = f"dmesg | grep -i '{proc_name}'"
                try:
                    output = subprocess.check_output(cmd, shell=True, text=True)
                    logs['dmesg'] = output.splitlines()
                except subprocess.SubprocessError:
                    # Grep returns non-zero if no matches
                    pass
        except Exception as e:
            logger.warning(f"Failed to get dmesg logs: {e}")
        
        return dict(logs)

    def analyze_pid(self, pid):
        """Analyze a single PID and return a structured report"""
        process_info = self.collect_process_info(pid)
        if not process_info:
            return None
        
        # Get logs
        process_logs = self.get_process_logs(pid, process_info)
        
        # MITRE ATT&CK analysis
        mitre_analysis = self.analyze_mitre_techniques(process_info, process_logs)
        
        # Full analysis report
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'process_info': process_info,
            'process_logs': process_logs,
            'mitre_analysis': mitre_analysis
        }
        
        return analysis

    def analyze_mitre_techniques(self, process_info, process_logs):
        """Analyze process for potential MITRE ATT&CK techniques"""
        techniques = []
        
        # Process name-based detection
        proc_name = process_info.get('name', '').lower()
        cmdline = process_info.get('cmdline', '').lower()
        
        # Check process name against known techniques
        for key, technique in self.mitre_techniques.items():
            if key in proc_name or key in cmdline:
                techniques.append({
                    'technique_id': technique['technique_id'],
                    'tactic': technique['tactic'],
                    'name': technique['name'],
                    'confidence': 'medium',
                    'evidence': f"Process name/cmdline contains '{key}'"
                })
        
        # Command line analysis
        if 'cat /etc/passwd' in cmdline or 'cat /etc/shadow' in cmdline:
            techniques.append({
                'technique_id': 'T1003.008',
                'tactic': 'credential-access',
                'name': 'OS Credential Dumping: /etc/passwd and /etc/shadow',
                'confidence': 'high',
                'evidence': f"Command line: {cmdline}"
            })
        
        if 'crontab' in cmdline or '/etc/cron' in cmdline:
            techniques.append({
                'technique_id': 'T1053.003',
                'tactic': 'persistence',
                'name': 'Scheduled Task/Job: Cron',
                'confidence': 'high',
                'evidence': f"Command line: {cmdline}"
            })
        
        # Suspicious file access
        open_files = process_info.get('open_files', [])
        for file_path in open_files:
            if '/etc/pam.d/' in file_path:
                techniques.append({
                    'technique_id': 'T1556.003',
                    'tactic': 'defense-evasion',
                    'name': 'Modify Authentication Process: Pluggable Authentication Modules',
                    'confidence': 'high',
                    'evidence': f"Accessing PAM config: {file_path}"
                })
        
        # Network connections
        for conn in process_info.get('connections', []):
            raddr = conn.get('raddr')
            if raddr and not raddr.startswith('127.0.0.1'):
                techniques.append({
                    'technique_id': 'T1071',
                    'tactic': 'command-and-control',
                    'name': 'Application Layer Protocol',
                    'confidence': 'low',
                    'evidence': f"External network connection: {raddr}"
                })
        
        # Process ancestry analysis
        ancestry = process_info.get('ancestry', [])
        for ancestor in ancestry:
            ancestor_name = ancestor.get('name', '').lower()
            if ancestor_name in ['bash', 'sh', 'zsh']:
                techniques.append({
                    'technique_id': 'T1059.004',
                    'tactic': 'execution',
                    'name': 'Command and Scripting Interpreter: Unix Shell',
                    'confidence': 'medium',
                    'evidence': f"Process has shell ancestry: {ancestor_name}"
                })
        
        # Journal log analysis
        for log in process_logs.get('journal', []):
            message = log.get('MESSAGE', '').lower()
            if 'authentication failure' in message or 'failed password' in message:
                techniques.append({
                    'technique_id': 'T1110',
                    'tactic': 'credential-access',
                    'name': 'Brute Force',
                    'confidence': 'medium',
                    'evidence': f"Authentication failure log: {message}"
                })
        
        return techniques

    def monitor_pid_worker(self):
        """Worker thread to monitor PIDs from the queue"""
        while not self.shutdown_flag.is_set():
            try:
                pid = self.process_queue.get(timeout=1)
                logger.info(f"Analyzing PID {pid}")
                
                # Analyze process
                analysis = self.analyze_pid(pid)
                
                if analysis:
                    # Save analysis to file
                    output_file = os.path.join(self.output_dir, f"pid_{pid}_analysis.json")
                    with open(output_file, 'w') as f:
                        json.dump(analysis, f, indent=2, default=str)
                    logger.info(f"Analysis for PID {pid} saved to {output_file}")
                    
                    # Save highlight file with key findings
                    highlights = self.extract_highlights(analysis)
                    if highlights:
                        highlight_file = os.path.join(self.output_dir, f"pid_{pid}_highlights.json")
                        with open(highlight_file, 'w') as f:
                            json.dump(highlights, f, indent=2, default=str)
                
                self.process_queue.task_done()
            except queue.Empty:
                # Queue is empty, just continue
                pass
            except Exception as e:
                logger.error(f"Error in monitor thread: {e}")

    def extract_highlights(self, analysis):
        """Extract key highlights from the analysis"""
        if not analysis:
            return None
        
        process_info = analysis.get('process_info', {})
        mitre_analysis = analysis.get('mitre_analysis', [])
        
        highlights = {
            'pid': process_info.get('pid'),
            'name': process_info.get('name'),
            'cmdline': process_info.get('cmdline'),
            'user': process_info.get('username'),
            'start_time': process_info.get('create_time'),
            'mitre_techniques': [
                {
                    'id': t.get('technique_id'),
                    'name': t.get('name'),
                    'tactic': t.get('tactic'),
                    'confidence': t.get('confidence')
                } for t in mitre_analysis
            ],
            'suspicious_activities': []
        }
        
        # Extract key suspicious activities
        for log in analysis.get('process_logs', {}).get('journal', [])[:5]:
            if 'MESSAGE' in log:
                highlights['suspicious_activities'].append(log['MESSAGE'])
        
        for log in analysis.get('process_logs', {}).get('audit', [])[:5]:
            if 'EXECVE' in log or 'USER_AUTH' in log:
                highlights['suspicious_activities'].append(log)
        
        return highlights

    def start_monitoring(self, num_workers=4):
        """Start monitoring threads"""
        self.shutdown_flag.clear()
        
        # Create worker threads
        for _ in range(num_workers):
            thread = threading.Thread(target=self.monitor_pid_worker)
            thread.daemon = True
            thread.start()
            self.worker_threads.append(thread)
        
        logger.info(f"Started {num_workers} monitoring threads")

    def stop_monitoring(self):
        """Stop all monitoring threads"""
        self.shutdown_flag.set()
        
        # Wait for threads to finish
        for thread in self.worker_threads:
            thread.join(timeout=2)
        
        logger.info("Stopped monitoring threads")

    def add_pid_to_monitor(self, pid):
        """Add a PID to the monitoring queue"""
        if pid not in self.monitored_pids and psutil.pid_exists(pid):
            self.monitored_pids.add(pid)
            self.process_queue.put(pid)
            return True
        return False

    def monitor_process_by_name(self, process_name):
        """Find and monitor all processes matching a name"""
        pids = self.find_pids_by_name(process_name)
        count = 0
        for pid in pids:
            if self.add_pid_to_monitor(pid):
                count += 1
        
        logger.info(f"Added {count} PIDs for process name '{process_name}'")
        return count

    def monitor_kernel_and_pam(self):
        """Monitor kernel and PAM-related processes"""
        # Monitor key kernel threads
        kernel_pids = self.find_kernel_threads()
        kernel_count = 0
        for pid in kernel_pids:
            if self.add_pid_to_monitor(pid):
                kernel_count += 1
        
        # Monitor PAM processes
        pam_pids = self.find_pam_processes()
        pam_count = 0
        for pid in pam_pids:
            if self.add_pid_to_monitor(pid):
                pam_count += 1
        
        logger.info(f"Added {kernel_count} kernel threads and {pam_count} PAM-related processes for monitoring")
        return kernel_count + pam_count

    def run_adversary_operation(self, adversary_id=None):
        """Run a Caldera adversary operation and monitor its PIDs"""
        try:
            # Caldera API configuration - adjust as needed
            caldera_url = "http://localhost:8888"
            api_key = "ADMIN123"  # Replace with actual API key
            headers = {"KEY": api_key}
            
            # Prepare operation data
            operation_name = f"Auto_Operation_{int(time.time())}"
            data = {
                "name": operation_name,
                "group": "red",
                "adversary_id": adversary_id or "5d3e170e-f1b8-49f9-9ee1-c51605552a08",  # Default adversary
                "state": "running"
            }
            
            # Start the operation
            logger.info(f"Starting Caldera operation: {operation_name}")
            response = subprocess.check_output(
                ["curl", "-s", "-X", "POST", 
                 "-H", f"KEY: {api_key}", 
                 "-H", "Content-Type: application/json",
                 "-d", json.dumps(data),
                 f"{caldera_url}/api/v2/operations"
                ],
                text=True
            )
            
            operation_data = json.loads(response)
            operation_id = operation_data.get('id')
            
            if not operation_id:
                logger.error("Failed to get operation ID")
                return
            
            logger.info(f"Started operation {operation_id}, monitoring for adversary processes")
            
            # Start a thread to continually check for new PIDs
            def monitor_adversary_pids():
                previously_seen_pids = set()
                
                # Check for new processes every second for 5 minutes
                end_time = time.time() + 300  # 5 minutes
                
                while time.time() < end_time and not self.shutdown_flag.is_set():
                    try:
                        # Get current running processes
                        current_pids = set(psutil.pids())
                        
                        # Find new PIDs
                        new_pids = current_pids - previously_seen_pids
                        
                        # Add new PIDs to monitoring
                        for pid in new_pids:
                            try:
                                proc = psutil.Process(pid)
                                create_time = datetime.fromtimestamp(proc.create_time())
                                
                                # Only consider processes created after operation start
                                if create_time > datetime.now() - timedelta(minutes=5):
                                    logger.info(f"Detected new process: {pid} ({proc.name()})")
                                    self.add_pid_to_monitor(pid)
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                        
                        # Update previously seen PIDs
                        previously_seen_pids = current_pids
                        
                        # Sleep briefly
                        time.sleep(0.5)
                        
                    except Exception as e:
                        logger.error(f"Error monitoring adversary PIDs: {e}")
                
                logger.info("Finished monitoring for adversary PIDs")
            
            # Start the monitoring thread
            adversary_thread = threading.Thread(target=monitor_adversary_pids)
            adversary_thread.daemon = True
            adversary_thread.start()
            
            # Wait for the thread to complete
            adversary_thread.join()
            
            return operation_id
            
        except Exception as e:
            logger.error(f"Error running adversary operation: {e}")
            return None

    def analyze_stockpile_abilities(self, adversary_id=None):
        """Analyze abilities from MITRE Stockpile"""
        try:
            # Path to stockpile repository
            stockpile_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stockpile")
            if not os.path.exists(stockpile_path):
                stockpile_path = os.path.expanduser("~/stockpile")
                if not os.path.exists(stockpile_path):
                    logger.error("Stockpile repository not found")
                    return
            
            adversaries_path = os.path.join(stockpile_path, "data/adversaries/packs")
            abilities_path = os.path.join(stockpile_path, "data/abilities")
            
            # If adversary_id is provided, only analyze that adversary
            if adversary_id:
                adversary_file = None
                for filename in os.listdir(adversaries_path):
                    if filename.endswith('.yml'):
                        with open(os.path.join(adversaries_path, filename), 'r') as f:
                            adversary = yaml.safe_load(f)
                            if adversary.get('id') == adversary_id:
                                adversary_file = os.path.join(adversaries_path, filename)
                                break
                
                if not adversary_file:
                    logger.error(f"Adversary {adversary_id} not found")
                    return
                
                adversary_files = [adversary_file]
            else:
                # Get all adversary files
                adversary_files = [os.path.join(adversaries_path, f) for f in os.listdir(adversaries_path) if f.endswith('.yml')]
            
            logger.info(f"Analyzing {len(adversary_files)} adversaries")
            
            # Process each adversary
            for adversary_file in adversary_files:
                try:
                    with open(adversary_file, 'r') as f:
                        adversary = yaml.safe_load(f)
                    
                    adversary_name = os.path.basename(adversary_file).replace('.yml', '')
                    adversary_id = adversary.get('id', 'unknown')
                    
                    print(f"\n[*] Processing adversary: {adversary_name} ({adversary_id})")
                    
                    # Run the adversary and monitor PIDs
                    operation_id = self.run_adversary_operation(adversary_id)
                    
                    # Wait for all monitoring to complete
                    self.process_queue.join()
                    
                    print(f"[+] Completed analysis for adversary {adversary_name}")
                    
                except Exception as e:
                    logger.error(f"Error processing adversary {adversary_file}: {str(e)}")
            
            print("\n[+] Completed analysis of all adversaries")
            
        except Exception as e:
            logger.error(f"Error analyzing stockpile abilities: {e}")

def main():
    parser = argparse.ArgumentParser(description='Real-time Process Monitor for Security Analysis')
    parser.add_argument('--output', help='Output directory for analysis results')
    parser.add_argument('--process', help='Process name to monitor')
    parser.add_argument('--pid', type=int, help='Specific PID to monitor')
    parser.add_argument('--kernel', action='store_true', help='Monitor kernel threads')
    parser.add_argument('--pam', action='store_true', help='Monitor PAM-related processes')
    parser.add_argument('--adversary', help='Run specific adversary ID')
    parser.add_argument('--all-adversaries', action='store_true', help='Run all available adversaries')
    parser.add_argument('--workers', type=int, default=4, help='Number of worker threads')
    args = parser.parse_args()
    
    print("""
╔═══════════════════════════════════════════════╗
║   Real-time Process Monitor for Attack Analysis║
║   Kernel, PAM, and Adversary PID Tracking     ║
╚═══════════════════════════════════════════════╝
    """)
    
    try:
        # Create monitor
        monitor = ProcessMonitor(output_dir=args.output)
        
        # Start monitoring threads
        monitor.start_monitoring(num_workers=args.workers)
        
        try:
            # Add PIDs to monitor based on arguments
            if args.process:
                monitor.monitor_process_by_name(args.process)
            
            if args.pid:
                monitor.add_pid_to_monitor(args.pid)
            
            if args.kernel or args.pam or (not args.process and not args.pid and not args.adversary and not args.all_adversaries):
                # If no specific monitoring is requested, default to kernel and PAM
                if args.kernel:
                    kernel_pids = monitor.find_kernel_threads()
                    logger.info(f"Monitoring {len(kernel_pids)} kernel threads")
                    for pid in kernel_pids:
                        monitor.add_pid_to_monitor(pid)
                
                if args.pam:
                    pam_pids = monitor.find_pam_processes()
                    logger.info(f"Monitoring {len(pam_pids)} PAM processes")
                    for pid in pam_pids:
                        monitor.add_pid_to_monitor(pid)
            
            # Run adversary analysis if requested
            if args.adversary:
                monitor.run_adversary_operation(args.adversary)
            elif args.all_adversaries:
                monitor.analyze_stockpile_abilities()
            
            # Wait for monitoring to complete
            if not args.adversary and not args.all_adversaries:
                # For manual monitoring, wait for user input
                print("\nPress Ctrl+C to stop monitoring")
                while True:
                    time.sleep(1)
            
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
        finally:
            # Stop monitoring threads
            monitor.stop_monitoring()
        
        print(f"\n[+] Analysis results saved to {monitor.output_dir}")
        
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
