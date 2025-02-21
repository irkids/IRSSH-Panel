# Alert Configuration Guide

## Alert Rules
### System Alerts
```yaml
groups:
  - name: system
    rules:
      - alert: HighCPUUsage
        expr: system_cpu_usage > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High CPU usage

      - alert: HighMemoryUsage
        expr: system_memory_usage > 90
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: High memory usage
