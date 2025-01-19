import numpy as np
import networkx as nx
from datetime import datetime
import csv
from collections import defaultdict
import re
from bcc import BPF
import ctypes as ct
import os
import sys
import logging

class LogCorrelator:
    def __init__(self):
        self.processor = LogProcessor()
        self.graph_nn = LogGraphNN()
        
    def read_audit_logs(self):
        try:
            with open('/var/log/audit/audit.log', 'r') as f:
                return [self._parse_audit_line(line.strip()) for line in f]
        except FileNotFoundError:
            logging.error("Audit log file not found")
            return []
            
    def _parse_audit_line(self, line):
        # Parse audit log line into structured format
        parsed = {}
        parts = line.split()
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                parsed[key] = value
        return parsed

    def read_system_logs(self):
        system_logs = {}
        log_paths = {
            'syslog': '/var/log/syslog',
            'auth': '/var/log/auth.log',
            'kern': '/var/log/kern.log'
        }
        
        for log_type, path in log_paths.items():
            try:
                with open(path, 'r') as f:
                    system_logs[log_type] = [line.strip() for line in f]
            except FileNotFoundError:
                logging.error(f"Log file not found: {path}")
                system_logs[log_type] = []
        return system_logs


# part 2

class LogGraphNN:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.relationship_types = {
            'process_child': 0.8,
            'command_match': 0.7,
            'resource_access': 0.6
        }

    def build_graph(self, audit_logs, system_logs, kernel_events):
        # Add nodes for each log type
        for log in audit_logs:
            self.graph.add_node(f"audit_{log['pid']}", 
                              type='audit',
                              data=log)

        for source, logs in system_logs.items():
            for log in logs:
                # Ensure log is a dictionary
                if isinstance(log, dict):
                    node_id = f"system_{source}_{log['pid']}"
                    self.graph.add_node(node_id,
                                      type='system',
                                      source=source,
                                      data=log)

        for event in kernel_events:
            self.graph.add_node(f"kernel_{event['pid']}", 
                              type='kernel',
                              data=event)

        self._create_relationships()

    def _create_relationships(self):
        for node1, data1 in self.graph.nodes(data=True):
            for node2, data2 in self.graph.nodes(data=True):
                if node1 != node2:
                    weight = self._calculate_relationship_weight(
                        data1['data'], 
                        data2['data']
                    )
                    if weight > 0:
                        self.graph.add_edge(node1, node2, weight=weight)

    def _calculate_relationship_weight(self, data1, data2):
        weight = 0
        
        # Check PID match
        if str(data1.get('pid')) == str(data2.get('pid')):
            weight += self.relationship_types['process_child']
            
        # Check command match
        if data1.get('command') == data2.get('command'):
            weight += self.relationship_types['command_match']
            
        return weight

    def get_correlated_dataset(self):
        correlated_data = []
        
        # Find audit log nodes
        audit_nodes = [n for n, d in self.graph.nodes(data=True) 
                      if d['type'] == 'audit']
        
        for audit_node in audit_nodes:
            related = self._get_related_logs(audit_node)
            if related:
                correlated_data.append({
                    'audit_log': self.graph.nodes[audit_node]['data'],
                    'related_logs': related
                })
                
        return correlated_data

    def _get_related_logs(self, audit_node, threshold=0.5):
        related = defaultdict(list)
        
        for neighbor in self.graph.neighbors(audit_node):
            edge_data = self.graph.get_edge_data(audit_node, neighbor)
            if edge_data['weight'] >= threshold:
                node_data = self.graph.nodes[neighbor]
                related[node_data['type']].append({
                    'log': node_data['data'],
                    'weight': edge_data['weight']
                })
                
        return related

# part 3

class LogProcessor:
    def __init__(self):
        self.graph_nn = LogGraphNN()
        self.log_sources = {
            'audit': '/var/log/audit/audit.log',
            'syslog': '/var/log/syslog',
            'auth': '/var/log/auth.log',
            'kern': '/var/log/kern.log'
        }

    def process_logs(self, audit_logs, system_logs, kernel_events):
        # Build graph and get correlations
        self.graph_nn.build_graph(audit_logs, system_logs, kernel_events)
        correlated_data = self.graph_nn.get_correlated_dataset()
        
        # Format the correlated data
        formatted_data = []
        for entry in correlated_data:
            formatted_entry = {
                'audit_log': self._format_audit_log(entry['audit_log']),
                'related_logs': {}
            }
            
            # Format related logs by type
            for log_type, logs in entry['related_logs'].items():
                formatted_entry['related_logs'][log_type] = [
                    self._format_log(log['log'], log['weight'])
                    for log in logs
                ]
            
            formatted_data.append(formatted_entry)
            
        return formatted_data

    def _format_audit_log(self, audit_log):
        return (f"Command: {audit_log.get('command', 'unknown')} "
                f"(PID: {audit_log.get('pid', 'unknown')})")

    def _format_log(self, log, weight):
        formatted = str(log)
        if isinstance(log, dict):
            if 'message' in log:
                formatted = log['message']
            elif 'comm' in log:
                formatted = f"Process: {log['comm']} (PID: {log['pid']})"
        
        # Add correlation weight
        formatted += f" [correlation: {weight:.2f}]"
        return formatted

    def write_csv(self, formatted_data, output_file):
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Audit Log', 'System Logs', 'Auth Logs', 'Kernel Events'])
            
            for entry in formatted_data:
                row = [
                    entry['audit_log'],
                    self._join_logs(entry['related_logs'].get('system', [])),
                    self._join_logs(entry['related_logs'].get('auth', [])),
                    self._join_logs(entry['related_logs'].get('kernel', []))
                ]
                writer.writerow(row)

    def _join_logs(self, logs):
        return ' | '.join(logs) if logs else ''


# part 4

class KernelEventTracer:
    def __init__(self):
        self.bpf_text = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>
        
        struct event_t {
            u32 pid;
            u32 ppid;
            char comm[16];
            u64 timestamp;
            char syscall[32];
        };
        
        BPF_HASH(process_events, u32, struct event_t);
        BPF_PERF_OUTPUT(events);

        int trace_exec(struct pt_regs *ctx) {
            struct event_t event = {};
            event.pid = bpf_get_current_pid_tgid() >> 32;
            event.ppid = bpf_get_current_ppid_tgid() >> 32;
            event.timestamp = bpf_ktime_get_ns();
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            
            events.perf_submit(ctx, &event, sizeof(event));
            return 0;
        }
        """
        self.kernel_events = []
        
    def start_tracing(self):
        try:
            self.bpf = BPF(text=self.bpf_text)
            self.bpf.attach_kprobe(event="do_execve", fn_name="trace_exec")
            self.bpf["events"].open_perf_buffer(self._process_event)
        except Exception as e:
            logging.error(f"Failed to start kernel tracing: {e}")
            raise

    def _process_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        self.kernel_events.append({
            'pid': event.pid,
            'ppid': event.ppid,
            'comm': event.comm.decode('utf-8'),
            'timestamp': event.timestamp,
            'syscall': event.syscall.decode('utf-8')
        })

class LogCorrelationManager:
    def __init__(self):
        self.correlator = LogCorrelator()
        self.kernel_tracer = KernelEventTracer()
        self.processor = LogProcessor()
        
    def run(self):
        try:
            # Start kernel tracing
            self.kernel_tracer.start_tracing()
            
            # Read logs
            audit_logs = self.correlator.read_audit_logs()
            system_logs = self.correlator.read_system_logs()
            
            # Process and correlate logs
            correlated_data = self.processor.process_logs(
                audit_logs,
                system_logs,
                self.kernel_tracer.kernel_events
            )
            
            # Generate output
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"correlated_logs_{timestamp}.csv"
            self.processor.write_csv(correlated_data, output_file)
            
            logging.info(f"Log correlation completed. Output written to {output_file}")
            
        except Exception as e:
            logging.error(f"Error in log correlation: {e}")
            raise
        finally:
            if hasattr(self.kernel_tracer, 'bpf'):
                self.kernel_tracer.bpf.cleanup()

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    try:
        manager = LogCorrelationManager()
        manager.run()
    except KeyboardInterrupt:
        logging.info("Stopping log correlation...")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
