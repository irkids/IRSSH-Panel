# Performance Issues Runbook

## CPU High Usage

### Symptoms
- CPU usage > 80%
- Increased response times
- System alerts

### Investigation Steps
1. Check current CPU usage:
   ```bash
   top -bn1
   ps aux --sort=-%cpu | head -10
