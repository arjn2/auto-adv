package main

import (
    "bufio"
    "encoding/csv"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"
)

type Monitor struct {
    tracePipe    *os.File
    processTree  map[int]*ProcessTree
    eventChan    chan ProcessEvent
    done         chan bool
    writer       *csv.Writer
    targetRegex  []*regexp.Regexp
    mu           sync.RWMutex
}

func NewMonitor(outFile string) (*Monitor, error) {
    f, err := os.Create(outFile)
    if err != nil {
        return nil, err
    }

    writer := csv.NewWriter(f)
    if err := writer.Write([]string{
        "Timestamp", "PID", "PPID", "Command",
        "Event Type", "Syscall", "Resource",
    }); err != nil {
        f.Close()
        return nil, err
    }

    targetPatterns := []string{
        `curl.*sandcat`,
        `splunkd.*-server`,
        `.*python.*sandcat`,
        `.*sh.*sandcat`,
    }

    m := &Monitor{
        processTree: make(map[int]*ProcessTree),
        eventChan:   make(chan ProcessEvent, 1000),
        done:        make(chan bool),
        writer:      writer,
        targetRegex: make([]*regexp.Regexp, len(targetPatterns)),
    }

    for i, pattern := range targetPatterns {
        m.targetRegex[i] = regexp.MustCompile(pattern)
    }

    return m, nil
}

func (m *Monitor) Start() error {
    if err := m.setupTracing(); err != nil {
        return fmt.Errorf("trace setup failed: %v", err)
    }

    go m.processEvents()
    go m.monitorProcesses()
    go m.readTrace()

    return nil
}

func (m *Monitor) setupTracing() error {
    if err := ioutil.WriteFile("/sys/kernel/debug/tracing/tracing_on", []byte("1"), 0644); err != nil {
        return err
    }

    pipe, err := os.OpenFile("/sys/kernel/debug/tracing/trace_pipe", os.O_RDONLY, 0)
    if err != nil {
        return err
    }
    m.tracePipe = pipe

    return nil
}

func (m *Monitor) readTrace() {
    scanner := bufio.NewScanner(m.tracePipe)
    for scanner.Scan() {
        select {
        case <-m.done:
            return
        default:
            if event := m.parseTraceEvent(scanner.Text()); event != nil {
                m.eventChan <- *event
            }
        }
    }
}

func (m *Monitor) parseTraceEvent(line string) *ProcessEvent {
    parts := strings.Fields(line)
    if len(parts) < 4 {
        return nil
    }

    pid, _ := strconv.Atoi(parts[0])
    event := &ProcessEvent{
        PID:       pid,
        Time:      time.Now(),
        EventType: "trace",
    }

    switch {
    case strings.Contains(line, "execve"):
        event.EventType = "exec"
        if idx := strings.Index(line, "filename="); idx != -1 {
            cmdLine := line[idx+9:]
            parts := strings.SplitN(cmdLine, " ", 2)
            event.Cmd = strings.Trim(parts[0], "\"")
            if len(parts) > 1 {
                event.Resource = parts[1]
            }
        }
        event.SysCall = "execve"

    case strings.Contains(line, "write"):
        event.EventType = "write"
        event.SysCall = "write"
        if idx := strings.Index(line, "write"); idx != -1 {
            event.Resource = line[idx:]
        }

    case strings.Contains(line, "open"):
        event.EventType = "open"
        event.SysCall = "open"
        if idx := strings.Index(line, "open"); idx != -1 {
            event.Resource = line[idx:]
        }
    }

    return event
}

func (m *Monitor) monitorProcesses() {
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-m.done:
            return
        case <-ticker.C:
            m.updateProcessTree()
        }
    }
}

func (m *Monitor) updateProcessTree() {
    procs, err := ioutil.ReadDir("/proc")
    if err != nil {
        return
    }

    for _, proc := range procs {
        pid, err := strconv.Atoi(proc.Name())
        if err != nil {
            continue
        }

        cmdline, err := ioutil.ReadFile(filepath.Join("/proc", proc.Name(), "cmdline"))
        if err != nil {
            continue
        }

        cmdStr := string(cmdline)
        
        for _, re := range m.targetRegex {
            if re.MatchString(cmdStr) {
                m.mu.Lock()
                if _, exists := m.processTree[pid]; !exists {
                    m.processTree[pid] = &ProcessTree{
                        PID:      pid,
                        Children: make(map[int]*ProcessTree),
                        Events:   make([]ProcessEvent, 0),
                    }
                    
                    event := ProcessEvent{
                        PID:       pid,
                        Time:      time.Now(),
                        Cmd:       cmdStr,
                        EventType: "process_start",
                    }
                    m.eventChan <- event
                }
                m.mu.Unlock()
                break
            }
        }
    }
}

func (m *Monitor) processEvents() {
    for {
        select {
        case event := <-m.eventChan:
            m.handleEvent(event)
        case <-m.done:
            return
        }
    }
}

func (m *Monitor) handleEvent(event ProcessEvent) {
    m.mu.Lock()
    defer m.mu.Unlock()

    m.writer.Write([]string{
        event.Time.Format("2006-01-02 15:04:05.000"),
        strconv.Itoa(event.PID),
        strconv.Itoa(event.PPID),
        event.Cmd,
        event.EventType,
        event.SysCall,
        event.Resource,
    })
    m.writer.Flush()

    if proc, exists := m.processTree[event.PID]; exists {
        proc.Events = append(proc.Events, event)
    }
}

func (m *Monitor) Stop() {
    close(m.done)
    if m.tracePipe != nil {
        m.tracePipe.Close()
    }
    m.writer.Flush()
}
