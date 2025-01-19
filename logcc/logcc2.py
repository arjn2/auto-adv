#part1 
import numpy as np
import networkx as nx
from datetime import datetime
import csv
from collections import defaultdict

import re
import Levenshtein
from bcc import BPF
import ctypes as ct
import os
import sys
import logging


class LogCorrelationNN:
    def __init__(self):
        self.input_layer = {
            'command': self._create_input_node('command'),
            'pid': self._create_input_node('pid'),
            'user': self._create_input_node('user'),
            'resource': self._create_input_node('resource'),
            'operation': self._create_input_node('operation')
        }
        
        self.pattern_layer = {
            'command_pattern': self._create_hidden_node('command_pattern'),
            'process_hierarchy': self._create_hidden_node('process_hierarchy'),
            'resource_access': self._create_hidden_node('resource_access'),
            'state_transition': self._create_hidden_node('state_transition')
        }
        
        self.correlation_layer = {
            'semantic': self._create_hidden_node('semantic'),
            'structural': self._create_hidden_node('structural')
        }
        
        self.output_layer = {
            'confidence': self._create_output_node('confidence'),
            'relationship': self._create_output_node('relationship')
        }
        
        self.weights = self._initialize_weights()
        self.learning_rate = 0.01

    def _create_input_node(self, name):
        return {'name': name, 'type': 'input', 'value': None}

    def _create_hidden_node(self, name):
        return {'name': name, 'type': 'hidden', 'value': None}

    def _create_output_node(self, name):
        return {'name': name, 'type': 'output', 'value': None}

    def _initialize_weights(self):
        return {
            'input_to_pattern': np.random.randn(len(self.input_layer), len(self.pattern_layer)),
            'pattern_to_correlation': np.random.randn(len(self.pattern_layer), len(self.correlation_layer)),
            'correlation_to_output': np.random.randn(len(self.correlation_layer), len(self.output_layer))
        }

    def forward_propagation(self, input_data):
        input_values = np.array([input_data[node['name']] for node in self.input_layer.values()])
        pattern_values = np.tanh(np.dot(input_values, self.weights['input_to_pattern']))
        correlation_values = np.tanh(np.dot(pattern_values, self.weights['pattern_to_correlation']))
        output_values = np.sigmoid(np.dot(correlation_values, self.weights['correlation_to_output']))
        return output_values


# part 2 kernel event tracing integration

#from bcc import BPF
#import ctypes as ct

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
        self.process_graph = nx.DiGraph()
        
    def start_tracing(self):
        self.bpf = BPF(text=self.bpf_text)
        self.bpf.attach_kprobe(event="do_execve", fn_name="trace_exec")
        
    def process_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        kernel_event = {
            'pid': event.pid,
            'ppid': event.ppid,
            'comm': event.comm.decode('utf-8'),
            'timestamp': event.timestamp,
            'syscall': event.syscall.decode('utf-8')
        }
        self.kernel_events.append(kernel_event)
        self.process_graph.add_edge(event.ppid, event.pid)

# part 3 Log correlation

class EnhancedLogCorrelator(LogCorrelator):
    def __init__(self):
        super().__init__()
        self.kernel_tracer = KernelEventTracer()
        self.process_graph = nx.DiGraph()
        
    def run(self):
        try:
            # Start kernel tracing
            self.kernel_tracer.start_tracing()
            
            # Read logs
            audit_logs = self.read_audit_logs()
            system_logs = self.read_system_logs()
            
            # Enhance correlation with kernel data
            enhanced_data = self._enhance_correlation(audit_logs, system_logs)
            
            # Process and correlate logs
            correlated_data = self.processor.process_logs(enhanced_data, system_logs)
            
            # Write results to CSV
            self.processor.write_csv(correlated_data)
            
        except Exception as e:
            print(f"Error in enhanced log correlation: {e}")
        finally:
            # Cleanup kernel tracer
            if hasattr(self.kernel_tracer, 'bpf'):
                self.kernel_tracer.bpf.cleanup()
                
    def _enhance_correlation(self, audit_logs, system_logs):
        enhanced_logs = []
        for audit_entry in audit_logs:
            pid = int(audit_entry.get('pid', 0))
            kernel_context = self._get_kernel_context(pid)
            
            # Enhance audit entry with kernel data
            enhanced_entry = audit_entry.copy()
            enhanced_entry.update(kernel_context)
            enhanced_logs.append(enhanced_entry)
            
        return enhanced_logs
        
    def _get_kernel_context(self, pid):
        return {
            'process_depth': len(list(nx.ancestors(self.process_graph, pid))),
            'child_processes': len(list(nx.descendants(self.process_graph, pid))),
            'kernel_events': len([e for e in self.kernel_tracer.kernel_events 
                                if e['pid'] == pid])
        }


# part 4 log processing and pattern matching  

class EnhancedLogProcessor(LogProcessor):
    def __init__(self):
        super().__init__()
        self.pattern_cache = {}
        
    def _find_related_logs(self, audit_entry, logs, correlation_score):
        related = []
        pid = audit_entry.get('pid', '0')
        command = audit_entry.get('command', '')
        
        for log in logs:
            # Check for direct matches
            if pid in log or command in log:
                confidence = correlation_score[0]  # Use neural network confidence
                if confidence > 0.5:  # Threshold for correlation
                    related.append(log)
                    
            # Check for pattern matches
            elif self._match_pattern(log, audit_entry):
                related.append(log)
                
        return related
        
    def _match_pattern(self, log, audit_entry):
        # Get or create pattern for the log
        if log not in self.pattern_cache:
            self.pattern_cache[log] = self._create_pattern(log)
            
        log_pattern = self.pattern_cache[log]
        audit_pattern = self._create_pattern(str(audit_entry))
        
        # Compare patterns
        return self._pattern_similarity(log_pattern, audit_pattern) > 0.7
        
    def _create_pattern(self, text):
        # Remove variable data but keep structure
        pattern = re.sub(r'\d+', '*', text)
        pattern = re.sub(r'([a-zA-Z]+)=([^ ]+)', r'\1=*', pattern)
        return pattern
        
    def _pattern_similarity(self, pattern1, pattern2):
        # Calculate similarity between patterns
        # Using Levenshtein distance normalized
        distance = Levenshtein.distance(pattern1, pattern2)
        max_length = max(len(pattern1), len(pattern2))
        return 1 - (distance / max_length)


#part 5  CSV and driver

class LogOutputManager:
    def __init__(self):
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
    def write_correlated_logs(self, correlated_data):
        filename = f"correlated_logs_{self.timestamp}.csv"
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write headers with facility types
            writer.writerow(['Command_Audit_Log', 'System_Logs', 'Auth_Logs', 
                           'Kernel_Logs', 'Process_Context'])
            
            for entry in correlated_data:
                # Format audit log with command info
                audit_log = self._format_audit_log(entry['audit'])
                
                # Format related logs with severity and facility
                system_logs = self._format_related_logs(entry.get('syslog', []))
                auth_logs = self._format_related_logs(entry.get('auth', []))
                kernel_logs = self._format_related_logs(entry.get('kern', []))
                
                # Add process context from kernel tracer
                process_context = self._format_process_context(entry.get('process_context', {}))
                
                writer.writerow([audit_log, system_logs, auth_logs, 
                               kernel_logs, process_context])
                
    def _format_audit_log(self, audit_entry):
        return f"{audit_entry['command']} (PID: {audit_entry['pid']})"
        
    def _format_related_logs(self, logs):
        return ','.join(logs)
        
    def _format_process_context(self, context):
        return f"Depth: {context.get('process_depth', 0)}, " \
               f"Children: {context.get('child_processes', 0)}"

if __name__ == "__main__":
    try:
        correlator = EnhancedLogCorrelator()
        correlator.run()
    except KeyboardInterrupt:
        print("\nStopping log correlation...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("Log correlation completed")




