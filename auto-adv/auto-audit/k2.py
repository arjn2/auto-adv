#!/usr/bin/env python3
import os
import sys
import yaml
import json
import time
import psutil
import logging
import argparse
import subprocess
import pwd
import grp
from datetime import datetime, timedelta
import glob
import re
from collections import defaultdict

class MITREAttackDatasetGenerator:
    def __init__(self, args):
        """Initialize the MITRE ATT&CK Dataset Generator"""
        # Verify root privileges
        if os.geteuid() != 0:
            raise SystemExit("This script must be run as root to access logs and analyze processes.")

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging

        # Parse arguments
        self.args = args
        
        # Initialize paths and configurations
        self._initialize_paths_and_configs()
        
        # Check and restore logging services
        self.check_and_restore_logging()
        
        # Configure log manipulation settings
        self._setup_log_manipulation()
        
        # Set up stockpile repository
        self._setup_stockpile()
        
        # Set up output directory and files
        self._setup_output_directory()
        
        # Initialize metadata
        self._initialize_metadata()
        
        # Set up auditd for better process tracking
        self.setup_auditd()

    def _initialize_paths_and_configs(self):
        """Initialize paths and configurations for log sources"""
        # Script directory
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Define log sources and their default paths
        self.log_sources = {
            'auth': '/var/log/auth.log',
            'syslog': '/var/log/syslog',
            'kernel': '/var/log/kern.log',
            'audit': '/var/log/audit/audit.log',
            'secure': '/var/log/secure',
            'journal': None  # Will use journalctl
        }
        
        # MITRE technique mapping
        self.technique_mapping = {}
        
        # Time window for log collection (seconds)
        self.time_window_before = 2
        self.time_window_after = 5

    def _setup_log_manipulation(self):
        """Set up log manipulation configurations"""
        if not self.args.assume_yes:
            print("\nWarning: Some adversaries contain log manipulation abilities.")
            disable_logs = input("Do you want to skip log manipulation abilities? (yes/no) [yes]: ").lower() or 'yes'
            self.skip_log_manipulation = disable_logs == 'yes'
        else:
            self.skip_log_manipulation = True
            print("\n[*] Automatically skipping log manipulation abilities based on --yes flag")

        # Define log manipulation abilities to skip
        self.log_manipulation_abilities = {
            '47d08617-5ce1-424a-8cc5-c9c978ce6bf9',  # Clear System Logs
            'aaf34e38-5e49-4a09-9f4b-c862c4cffc87',  # Disable System Logging
            '91a3c622-0ef3-4e2a-ab03-2f742ba0f291',  # Disable Audit Logging
        }

    def _setup_stockpile(self):
        """Set up the MITRE Stockpile repository"""
        stockpile_path = os.path.join(self.script_dir, "stockpile")
        if not os.path.exists(stockpile_path):
            print("\n[-] Stockpile directory not found. Attempting to clone from GitHub...")
            try:
                clone_cmd = "git clone https://github.com/mitre/stockpile.git"
                subprocess.run(clone_cmd, shell=True, check=True)
                print("\n[+] Successfully cloned stockpile repository")
            except subprocess.CalledProcessError as e:
                raise SystemExit(f"Failed to clone stockpile repository: {e}")

        self.stockpile_path = stockpile_path
        self.adversaries_path = os.path.join(self.stockpile_path, "data/adversaries/packs")
        self.abilities_path = os.path.join(self.stockpile_path, "data/abilities")

    def _setup_output_directory(self):
        """Set up output directory and files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(self.script_dir, f"mitre_attack_dataset_{timestamp}")
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Directory structure
        self.json_output_dir = os.path.join(self.output_dir, "json_data")
        self.highlights_dir = os.path.join(self.output_dir, "highlights")
        
        # Create subdirectories
        os.makedirs(self.json_output_dir, exist_ok=True)
        os.makedirs(self.highlights_dir, exist_ok=True)
        
        # Set up output files
        self.summary_file = os.path.join(self.output_dir, "dataset_summary.json")
        self.metadata_file = os.path.join(self.output_dir, "metadata.json")
        self.error_log = os.path.join(self.output_dir, "error.log")

    def _initialize_metadata(self):
        """Initialize metadata for the collection"""
        self.metadata = {
            'collection_start': datetime.now().isoformat(),
            'system_info': self.get_system_info(),
            'adversaries_run': [],
            'abilities_executed': [],
            'dataset_stats': {
                'total_adversaries': 0,
                'total_abilities': 0,
                'abilities_skipped': 0,
                'successful_executions': 0,
                'failed_executions': 0
            }
        }

    def check_and_restore_logging(self):
        """Check and ensure logging services are running"""
        logging_services = [
            'rsyslog',
            'syslog',
            'auditd'
        ]

        print("\n[*] Checking logging services...")

        for service in logging_services:
            try:
                # Check if service exists and is running
                status = subprocess.run(['systemctl', 'is-active', service],
                                     capture_output=True, text=True)

                if status.stdout.strip() != 'active':
                    print(f"[!] {service} is not active. Attempting to start...")
                    subprocess.run(['systemctl', 'start', service], check=True)
                    print(f"[+] Successfully started {service}")
                else:
                    print(f"[+] {service} is running")

            except subprocess.CalledProcessError:
                print(f"[-] Failed to check/start {service}")
            except Exception as e:
                print(f"[-] Error with {service}: {str(e)}")

        # Ensure log files exist with proper permissions
        for log_name, log_path in self.log_sources.items():
            if log_path:  # Skip None values (like journalctl)
                try:
                    if not os.path.exists(log_path):
                        # Create log file if it doesn't exist
                        with open(log_path, 'a') as f:
                            pass
                        # Set proper permissions (typically 640)
                        os.chmod(log_path, 0o640)
                        # Set proper ownership (typically root:adm)
                        os.chown(log_path,
                                pwd.getpwnam('root').pw_uid,
                                grp.getgrnam('adm').gr_gid)
                        print(f"[+] Created and configured {log_path}")
                except Exception as e:
                    print(f"[-] Error configuring {log_path}: {str(e)}")

    def setup_auditd(self):
        """Setup and verify auditd installation and rules"""
        try:
            # Start auditd service (already checked in check_and_restore_logging)
            
            # Add audit rules
            rules = [
                ['auditctl', '-D'],  # Delete existing rules
                ['auditctl', '-a', 'exit,always', '-F', 'arch=b64', '-S', 'execve', '-k', 'command_execution'],
                ['auditctl', '-a', 'exit,always', '-F', 'arch=b32', '-S', 'execve', '-k', 'command_execution'],
                ['auditctl', '-w', '/etc/passwd', '-p', 'wa', '-k', 'credential_access'],
                ['auditctl', '-w', '/etc/shadow', '-p', 'wa', '-k', 'credential_access'],
                ['auditctl', '-a', 'exit,always', '-S', 'ptrace', '-k', 'process_injection'],
                ['auditctl', '-e', '1']  # Enable auditing
            ]
            
            for rule in rules:
                subprocess.run(rule, check=True)
                
            logging.info("Auditd setup completed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to setup auditd: {e}")
            return False
        except FileNotFoundError as e:
            logging.error(f"Required command not found: {e}")
            return False

    def get_system_info(self):
        """Collect system information for context"""
        info = {}
        try:
            info['hostname'] = subprocess.getoutput('hostname')
            info['os'] = subprocess.getoutput('cat /etc/os-release')
            info['kernel'] = subprocess.getoutput('uname -a')
            info['users'] = subprocess.getoutput('who')
            info['network'] = subprocess.getoutput('ip a')
        except Exception as e:
            info['error'] = f"Failed to collect system info: {str(e)}"
        return info

    def get_log_entries(self, start_time, log_source):
        """Collect logs based on timestamp range"""
        try:
            # For journalctl
            if log_source == 'journal':
                # Get logs from window_before to window_after seconds around command execution
                before_time = start_time - timedelta(seconds=self.time_window_before)
                after_time = start_time + timedelta(seconds=self.time_window_after)
                cmd = f"journalctl --since '{before_time.strftime('%Y-%m-%d %H:%M:%S')}' " \
                      f"--until '{after_time.strftime('%Y-%m-%d %H:%M:%S')}' -o json"
                
                output = subprocess.getoutput(cmd)
                journal_entries = []
                
                # Parse JSON output from journalctl
                for line in output.splitlines():
                    try:
                        if line.strip():
                            entry = json.loads(line)
                            journal_entries.append(entry)
                    except json.JSONDecodeError:
                        continue
                
                return journal_entries

            # For standard log files
            log_file = self.log_sources[log_source]
            if not os.path.exists(log_file):
                return []

            # Read the entire log file
            with open(log_file, 'r') as f:
                log_lines = f.readlines()

            # Define time window
            before_time = start_time - timedelta(seconds=self.time_window_before)
            after_time = start_time + timedelta(seconds=self.time_window_after)

            relevant_logs = []
            current_year = datetime.now().year

            for line in log_lines:
                try:
                    # Common Linux log timestamp format
                    # Example: "Dec 22 17:08:38"
                    log_date_str = line.split()[0:3]
                    if len(log_date_str) >= 3:
                        # Parse timestamp
                        log_time_str = f"{current_year} {' '.join(log_date_str)}"
                        log_time = datetime.strptime(log_time_str, "%Y %b %d %H:%M:%S")

                        # Check if log is within our time window
                        if before_time <= log_time <= after_time:
                            relevant_logs.append(line.strip())
                except (ValueError, IndexError):
                    continue

            return relevant_logs

        except Exception as e:
            print(f"[-] Error reading {log_source} logs: {str(e)}")
            return []

    def find_ability_file(self, ability_id):
        """Find the YAML file containing a specific ability"""
        for root, _, files in os.walk(self.abilities_path):
            for file in files:
                if file.endswith('.yml'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            ability_yaml = yaml.safe_load(f)
                            if isinstance(ability_yaml, list):
                                for ability in ability_yaml:
                                    if ability.get('id') == ability_id:
                                        return file_path, ability
                            elif ability_yaml.get('id') == ability_id:
                                return file_path, ability_yaml
                    except Exception as e:
                        logging.error(f"Error reading ability file {file_path}: {e}")
                        continue
        print(f"[-] Could not find ability file for ID: {ability_id}")
        return None, None

    def collect_process_info(self, pid):
        """Collect detailed information about a process"""
        try:
            if not psutil.pid_exists(pid):
                logging.info(f"PID {pid} no longer exists")
                return None

            process = psutil.Process(pid)
            process_info = {
                'pid': process.pid,
                'ppid': process.ppid(),
                'name': process.name(),
                'cmdline': ' '.join(process.cmdline()),
                'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
                'username': process.username(),
                'status': process.status()
            }

            try:
                children = process.children(recursive=True)
                process_info['children'] = [
                    {
                        'pid': child.pid,
                        'name': child.name(),
                        'cmdline': ' '.join(child.cmdline()),
                        'create_time': datetime.fromtimestamp(child.create_time()).isoformat()
                    } for child in children
                ]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_info['children'] = []

            # Get process ancestry
            try:
                ancestry = []
                current = process
                while current and current.pid > 1:
                    parent = current.parent()
                    if parent:
                        ancestry.append({
                            'pid': parent.pid,
                            'name': parent.name(),
                            'cmdline': ' '.join(parent.cmdline())
                        })
                    current = parent
                process_info['ancestry'] = ancestry
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_info['ancestry'] = []

            return process_info

        except psutil.NoSuchProcess:
            return self.collect_historical_info(pid)
        except Exception as e:
            logging.error(f"Error collecting process info for PID {pid}: {e}")
            return None

    def collect_historical_info(self, pid):
        """Collect historical information from audit logs"""
        try:
            # Try audit logs without json format
            cmd = [
                'ausearch',
                '-p', str(pid),
                '-i'
            ]
            output = subprocess.check_output(cmd, universal_newlines=True)
            if output:
                return {
                    'pid': pid,
                    'status': 'terminated',
                    'audit_logs': output.splitlines()
                }
        except subprocess.CalledProcessError:
            logging.error(f"Failed to retrieve audit logs for PID {pid}")
        return None

    def collect_system_logs(self, process_info, start_time):
        """Collect system logs related to the process"""
        system_logs = defaultdict(list)
        
        # If we have process creation time, use it; otherwise use provided start_time
        if isinstance(process_info, dict) and 'create_time' in process_info:
            try:
                proc_time = datetime.fromisoformat(process_info['create_time'])
                start_time = proc_time
            except (ValueError, TypeError):
                pass  # Use provided start_time
        
        # Collect logs from each source
        for source in self.log_sources:
            logs = self.get_log_entries(start_time, source)
            if logs:
                system_logs[source] = logs
        
        # Collect audit logs specifically for the PID
        if isinstance(process_info, dict) and 'pid' in process_info:
            try:
                cmd = ['ausearch', '-p', str(process_info['pid']), '-i']
                output = subprocess.check_output(cmd, universal_newlines=True)
                system_logs['audit_specific'] = output.splitlines()
            except subprocess.CalledProcessError:
                pass
        
        return dict(system_logs)

    def execute_command(self, command, ability_info):
        """Execute a command and return PID and output"""
        try:
            # Start the process and get its PID
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            pid = process.pid
            
            # Wait for the process to complete with timeout
            try:
                stdout, stderr = process.communicate(timeout=30)
                output = stdout.decode('utf-8', errors='replace')
                if stderr:
                    output += "\nSTDERR: " + stderr.decode('utf-8', errors='replace')
                return pid, output, True
            except subprocess.TimeoutExpired:
                process.kill()
                return pid, "Command timed out after 30 seconds", False
        
        except Exception as e:
            logging.error(f"Error executing command: {e}")
            return None, f"Error: {str(e)}", False

    def analyze_pid(self, pid, ability_info, command, output, execution_time):
        """Analyze a process ID and generate a detailed JSON report"""
        # Ensure we have a valid PID
        if not pid:
            return None
        
        # Structure to hold all data
        event_data = {
            'timestamp': execution_time.isoformat(),
            'ability_info': ability_info,
            'command_executed': command,
            'command_output': output,
            'process_info': None,
            'related_logs': {},
            'mitre_context': {
                'tactic': ability_info.get('tactic', 'unknown'),
                'technique_id': ability_info.get('technique_id', 'unknown'),
                'technique_name': ability_info.get('technique_name', 'unknown'),
                'ability_id': ability_info.get('id', 'unknown'),
                'ability_name': ability_info.get('name', 'unknown'),
                'description': ability_info.get('description', '')
            }
        }
        
        # Collect process information
        process_info = self.collect_process_info(pid)
        if process_info:
            event_data['process_info'] = process_info
            
            # Collect system logs
            system_logs = self.collect_system_logs(process_info, execution_time)
            event_data['related_logs'] = system_logs
        
        # Return the complete event data
        return event_data

    def generate_technique_mapping(self):
        """Generate mapping of technique IDs to names from ability files"""
        technique_mapping = {}
        
        for root, _, files in os.walk(self.abilities_path):
            for file in files:
                if file.endswith('.yml'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            abilities = yaml.safe_load(f)
                            if isinstance(abilities, list):
                                for ability in abilities:
                                    technique_id = ability.get('technique_id')
                                    technique_name = ability.get('technique_name')
                                    if technique_id and technique_name:
                                        technique_mapping[technique_id] = technique_name
                            elif isinstance(abilities, dict):
                                technique_id = abilities.get('technique_id')
                                technique_name = abilities.get('technique_name')
                                if technique_id and technique_name:
                                    technique_mapping[technique_id] = technique_name
                    except:
                        continue
        
        self.technique_mapping = technique_mapping
        print(f"[+] Generated mapping for {len(technique_mapping)} MITRE ATT&CK techniques")

    def save_json_data(self, data, filename):
        """Save data as JSON with proper formatting"""
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            logging.error(f"Error saving JSON data to {filename}: {e}")
            return False

    def extract_key_signatures(self, event_data):
        """Extract key attack signatures from the event data"""
        highlights = {}
        
        # Get MITRE technique info
        technique_id = event_data.get('mitre_context', {}).get('technique_id', 'unknown')
        ability_name = event_data.get('mitre_context', {}).get('ability_name', 'unknown')
        
        # Command executed
        command = event_data.get('command_executed', '')
        
        # Process information
        process_info = event_data.get('process_info', {})
        process_name = process_info.get('name', '') if process_info else ''
        
        # Extract key log entries
        key_logs = []
        for source, logs in event_data.get('related_logs', {}).items():
            if source == 'journal':
                for log in logs[:3]:  # Take first 3 logs
                    if isinstance(log, dict) and 'MESSAGE' in log:
                        if 'EXECVE' in log['MESSAGE']:
                            key_logs.append(log['MESSAGE'])
            elif source == 'audit_specific':
                for log in logs[:3]:  # Take first 3 logs
                    if 'EXECVE' in log:
                        key_logs.append(log)
        
        # Create highlights object
        highlights = {
            'technique_id': technique_id,
            'technique_name': self.technique_mapping.get(technique_id, 'Unknown Technique'),
            'ability_name': ability_name,
            'command': command,
            'process_name': process_name,
            'key_logs': key_logs[:5],  # Limit to top 5 logs
            'pid': process_info.get('pid', '') if process_info else '',
        }
        
        return highlights

    def process_ability(self, ability_id, adversary_name, adversary_id):
        """Process a single ability"""
        ability_file, ability_data = self.find_ability_file(ability_id)
        
        if not ability_file or not ability_data:
            print(f"  [-] Unable to find data for ability {ability_id}")
            return None
        
        # Extract tactic from directory structure
        tactic = os.path.basename(os.path.dirname(ability_file))
        
        # Check if this is a defense evasion ability that should be skipped
        if self.args.skip_defense_evasion and tactic.lower() == 'defense-evasion':
            print(f"  [*] Skipping defense evasion ability: {ability_id}")
            self.metadata['dataset_stats']['abilities_skipped'] += 1
            return None
        
        # Check if this is a log manipulation ability that should be skipped
        if self.skip_log_manipulation and ability_id in self.log_manipulation_abilities:
            print(f"  [*] Skipping log manipulation ability: {ability_id}")
            self.metadata['dataset_stats']['abilities_skipped'] += 1
            return None
        
        # Enhance ability info with MITRE ATT&CK context
        ability_info = {
            'id': ability_data.get('id'),
            'name': ability_data.get('name'),
            'description': ability_data.get('description'),
            'tactic': tactic,
            'technique_id': ability_data.get('technique_id'),
            'technique_name': ability_data.get('technique_name'),
        }
        
        print(f"  [*] Executing ability: {ability_info['name']} ({ability_info['id']})")
        
        # Track this ability in metadata
        self.metadata['abilities_executed'].append({
            'id': ability_info['id'],
            'name': ability_info['name'],
            'tactic': tactic,
            'technique_id': ability_info['technique_id'],
            'time': datetime.now().isoformat(),
            'adversary': adversary_name
        })
        
        # Process all commands for this ability
        results = []
        
        try:
            if ability_data.get('platforms', {}).get('linux'):
                for executor, executor_block in ability_data['platforms']['linux'].items():
                    commands = executor_block.get('command', '').split('\n')
                    for cmd in commands:
                        if cmd.strip():
                            print(f"    → Executing: {cmd[:60]}{'...' if len(cmd) > 60 else ''}")
                            
                            # Execute the command and get PID
                            execution_time = datetime.now()
                            pid, output, success = self.execute_command(cmd, ability_info)
                            
                            if success:
                                self.metadata['dataset_stats']['successful_executions'] += 1
                            else:
                                self.metadata['dataset_stats']['failed_executions'] += 1
                            
                            # Allow process to complete and generate logs
                            time.sleep(1)
                            
                            # Analyze the PID
                            if pid:
                                event_data = self.analyze_pid(pid, ability_info, cmd, output, execution_time)
                                if event_data:
                                    # Generate unique filename
                                    safe_id = ability_info['id'].replace('/', '_')
                                    filename = f"ability_{safe_id}_pid_{pid}.json"
                                    filepath = os.path.join(self.json_output_dir, filename)
                                    
                                    # Save full data
                                    if self.save_json_data(event_data, filepath):
                                        print(f"    [+] Saved detailed analysis to {filename}")
                                        
                                        # Extract and save highlights
                                        highlights = self.extract_key_signatures(event_data)
                                        highlight_file = os.path.join(self.highlights_dir, f"highlights_{safe_id}_pid_{pid}.json")
                                        self.save_json_data(highlights, highlight_file)
                                        
                                        # Add to results
                                        results.append({
                                            'pid': pid,
                                            'command': cmd,
                                            'data_file': filename,
                                            'highlights_file': os.path.basename(highlight_file)
                                        })
                            
                            # Small delay between commands
                            time.sleep(2)
        
        except Exception as e:
            print(f"  [-] Error processing ability {ability_id}: {str(e)}")
            logging.error(f"Error processing ability {ability_id}: {str(e)}")
        
        return results

    def should_process_adversary(self, adversary_name, adversary_id, adversary_data):
        """Determine if an adversary should be processed based on user preferences"""
        # Skip defense evasion adversaries if requested
        tags = adversary_data.get('tags', [])
        if self.args.skip_defense_evasion and any('defense-evasion' in tag.lower() for tag in tags):
            if not self.args.assume_yes:
                user_input = input(f"Skip defense evasion adversary {adversary_name}? (yes/no) [yes]: ").lower() or 'yes'
                if user_input == 'yes':
                    print(f"[*] Skipping defense evasion adversary: {adversary_name}")
                    return False
            else:
                print(f"[*] Automatically skipping defense evasion adversary: {adversary_name}")
                return False

        return True

    def process_adversary(self, adversary_file):
        """Process a single adversary"""
        try:
            with open(adversary_file, 'r') as f:
                adversary = yaml.safe_load(f)
                
            adversary_name = os.path.basename(adversary_file).replace('.yml', '')
            adversary_id = adversary.get('id', 'unknown')
            
            # Check if we should process this adversary
            if not self.should_process_adversary(adversary_name, adversary_id, adversary):
                return
            
            print(f"\n[*] Processing adversary: {adversary_name} ({adversary_id})")
            
            # Record adversary in metadata
            self.metadata['adversaries_run'].append({
                'name': adversary_name,
                'id': adversary_id,
                'time': datetime.now().isoformat(),
                'abilities_count': len(adversary.get('atomic_ordering', [])),
                'description': adversary.get('description', '')
            })
            
            # Update statistics
            self.metadata['dataset_stats']['total_adversaries'] += 1
            self.metadata['dataset_stats']['total_abilities'] += len(adversary.get('atomic_ordering', []))
            
            # Process each ability in the adversary
            adversary_results = {
                'adversary_name': adversary_name,
                'adversary_id': adversary_id,
                'abilities': []
            }
            
            for ability_id in adversary.get('atomic_ordering', []):
                ability_results = self.process_ability(ability_id, adversary_name, adversary_id)
                if ability_results:
                    adversary_results['abilities'].append({
                        'ability_id': ability_id,
                        'results': ability_results
                    })
            
            # Save adversary results
            adversary_summary_file = os.path.join(self.output_dir, f"adversary_{adversary_id.replace('/', '_')}_summary.json")
            self.save_json_data(adversary_results, adversary_summary_file)
            
            return adversary_results
            
        except Exception as e:
            error_msg = f"Error processing adversary {adversary_file}: {str(e)}"
            print(f"[-] {error_msg}")
            logging.error(error_msg)
            return None

    def run(self):
        """Main execution method"""
        print("\n[*] Starting MITRE ATT&CK Dataset Generation...")
        
        # Generate technique mapping first
        self.generate_technique_mapping()
        
        # Get list of adversaries
        adversary_files = glob.glob(os.path.join(self.adversaries_path, "*.yml"))
        print(f"[+] Found {len(adversary_files)} adversaries in stockpile")
        
        # Process each adversary
        dataset_results = []
        
        for adversary_file in adversary_files:
            result = self.process_adversary(adversary_file)
            if result:
                dataset_results.append(result)
        
        # Save final metadata with statistics
        self.metadata['collection_end'] = datetime.now().isoformat()
        self.save_json_data(self.metadata, self.metadata_file)
        
        # Save overall dataset summary
        self.save_json_data(dataset_results, self.summary_file)
        
        # Display summary
        print("\n[+] Dataset Generation Complete!")
        print(f"[+] Processed {self.metadata['dataset_stats']['total_adversaries']} adversaries")
        print(f"[+] Executed {self.metadata['dataset_stats']['successful_executions']} commands successfully")
        print(f"[+] Skipped {self.metadata['dataset_stats']['abilities_skipped']} abilities")
        print(f"[+] Dataset directory: {self.output_dir}")
        print(f"[+] JSON data directory: {self.json_output_dir}")
        print(f"[+] Highlights directory: {self.highlights_dir}")

def main():
    parser = argparse.ArgumentParser(description='MITRE ATT&CK Dataset Generator')
    parser.add_argument('--skip-defense-evasion', action='store_true', help='Skip defense evasion adversaries')
    parser.add_argument('--yes', '-y', dest='assume_yes', action='store_true', help='Assume yes for all prompts')
    parser.add_argument('--output', help='Output directory for dataset')
    args = parser.parse_args()
    
    print("""
╔═══════════════════════════════════════════════╗
║       MITRE ATT&CK Dataset Generator          ║
║    PID-Based Attack Pattern Analysis Tool     ║
╚═══════════════════════════════════════════════╝
    """)

    try:
        generator = MITREAttackDatasetGenerator(args)
        generator.run()
    except KeyboardInterrupt:
        print("\n\n[!] Dataset generation interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
