package main

import "time"

type ProcessEvent struct {
    PID       int
    PPID      int
    Cmd       string
    EventType string
    Time      time.Time
    SysCall   string
    Resource  string
}

type ProcessTree struct {
    PID      int
    Children map[int]*ProcessTree
    Events   []ProcessEvent
}
