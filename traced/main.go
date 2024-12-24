package main

import (
    "fmt"
    "log"
    "os"
    "os/signal"
    "path/filepath"
    "syscall"
    "time"
)

func main() {
    if os.Geteuid() != 0 {
        log.Fatal("This program requires root privileges")
    }

    outDir := fmt.Sprintf("process_logs_%s", time.Now().Format("20060102_150405"))
    if err := os.MkdirAll(outDir, 0755); err != nil {
        log.Fatal(err)
    }

    monitor, err := NewMonitor(filepath.Join(outDir, "events.csv"))
    if err != nil {
        log.Fatal(err)
    }

    if err := monitor.Start(); err != nil {
        log.Fatal(err)
    }

    log.Printf("Process monitor started. Writing logs to %s", outDir)

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh

    monitor.Stop()
    log.Printf("Monitor stopped. Logs written to %s", outDir)
}
