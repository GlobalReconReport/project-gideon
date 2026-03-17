/*
    DFIR Triage Toolkit - Default YARA Rules
    Covers: credential dumping tools, common RATs/backdoors,
            suspicious scripts, webshells, packed PE, C2 patterns
*/

// ─── Credential Theft ───────────────────────────────────────────────────────

rule Mimikatz {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        severity    = "critical"
        category    = "credential_theft"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa::logonpasswords" nocase
        $s3 = "lsadump::sam" nocase
        $s4 = "privilege::debug" nocase
        $s5 = "kerberos::ptt" nocase
        $b1 = { 6D 69 6D 69 6B 61 74 7A }   // "mimikatz"
    condition:
        any of them
}

rule CredentialDumper_Generic {
    meta:
        description = "Generic credential dumping indicators"
        severity    = "high"
        category    = "credential_theft"
    strings:
        $s1 = "lsass.exe" nocase
        $s2 = "SAM\\Domains\\Account" nocase
        $s3 = "SECURITY\\Policy\\Secrets" nocase
        $s4 = "NtlmPasswordHashList" nocase
        $s5 = "wce.exe" nocase
        $s6 = "fgdump" nocase
        $s7 = "pwdump" nocase
    condition:
        2 of them
}

// ─── Reverse Shells / Backdoors ──────────────────────────────────────────────

rule ReverseShell_PowerShell {
    meta:
        description = "PowerShell reverse shell patterns"
        severity    = "critical"
        category    = "backdoor"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-EncodedC" nocase
        $enc3 = "-enc " nocase
        $nop  = "-NonInteractive" nocase
        $nop2 = "-NoProfile" nocase
        $tcp  = "Net.Sockets.TCPClient" nocase
        $rev  = "System.Net.Sockets.NetworkStream" nocase
        $iex  = "IEX(" nocase
        $dl   = "DownloadString" nocase
        $ba64 = /[A-Za-z0-9+\/]{100,}={0,2}/   // long base64 blob
    condition:
        ($tcp and $rev) or ($enc1 and $ba64) or ($iex and $dl)
}

rule ReverseShell_Netcat {
    meta:
        description = "Netcat reverse shell usage"
        severity    = "high"
        category    = "backdoor"
    strings:
        $nc1 = "nc -e /bin/sh" nocase
        $nc2 = "nc -e /bin/bash" nocase
        $nc3 = "ncat --exec" nocase
        $nc4 = "/bin/sh | nc " nocase
        $nc5 = "ncat -e cmd" nocase
    condition:
        any of them
}

rule ReverseShell_Python {
    meta:
        description = "Python reverse shell"
        severity    = "high"
        category    = "backdoor"
    strings:
        $s1 = "socket.socket(" nocase
        $s2 = "os.dup2(s.fileno()" nocase
        $s3 = "subprocess.call([\"/bin/sh\"" nocase
        $s4 = "pty.spawn" nocase
        $s5 = "os.execve" nocase
    condition:
        2 of them
}

rule ReverseShell_Bash {
    meta:
        description = "Bash reverse shell"
        severity    = "high"
        category    = "backdoor"
    strings:
        $s1 = "bash -i >& /dev/tcp/" nocase
        $s2 = "/dev/tcp/" nocase
        $s3 = "exec 5<>/dev/tcp/" nocase
    condition:
        any of them
}

// ─── Webshells ───────────────────────────────────────────────────────────────

rule Webshell_PHP {
    meta:
        description = "PHP webshell indicators"
        severity    = "critical"
        category    = "webshell"
    strings:
        $s1 = "eval(base64_decode(" nocase
        $s2 = "eval(gzinflate(" nocase
        $s3 = "eval(str_rot13(" nocase
        $s4 = "system($_" nocase
        $s5 = "passthru($_" nocase
        $s6 = "shell_exec($_" nocase
        $s7 = "exec($_" nocase
        $s8 = "assert($_" nocase
        $s9 = "@eval(" nocase
        $s10 = "preg_replace('/.*/e'" nocase
    condition:
        any of them
}

rule Webshell_ASPX {
    meta:
        description = "ASPX/ASP webshell indicators"
        severity    = "critical"
        category    = "webshell"
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "Process.Start" nocase
        $s3 = "Shell.Application" nocase
        $s4 = "WScript.Shell" nocase
        $s5 = "Response.Write(Execute" nocase
    condition:
        any of them
}

// ─── Packed / Obfuscated PE ──────────────────────────────────────────────────

rule Packed_UPX {
    meta:
        description = "UPX packed executable"
        severity    = "medium"
        category    = "packer"
    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = "UPX!" ascii
    condition:
        2 of them
}

rule SuspiciousPE_NoImports {
    meta:
        description = "PE file with very few imports (possible packer/shellcode loader)"
        severity    = "medium"
        category    = "suspicious_pe"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe
}

// ─── Lateral Movement / Recon ────────────────────────────────────────────────

rule LateralMovement_PSExec {
    meta:
        description = "PSExec / remote execution indicators"
        severity    = "high"
        category    = "lateral_movement"
    strings:
        $s1 = "psexec" nocase
        $s2 = "PSEXESVC" nocase
        $s3 = "\\ADMIN$" nocase
        $s4 = "\\IPC$" nocase
    condition:
        2 of them
}

rule Recon_NetworkScanner {
    meta:
        description = "Network scanning tool indicators"
        severity    = "medium"
        category    = "recon"
    strings:
        $s1 = "nmap" nocase
        $s2 = "masscan" nocase
        $s3 = "zmap" nocase
        $s4 = "-sV -sC" nocase
        $s5 = "--open --script" nocase
    condition:
        any of them
}

// ─── C2 Beaconing ────────────────────────────────────────────────────────────

rule C2_CobaltStrike {
    meta:
        description = "Cobalt Strike Beacon indicators"
        severity    = "critical"
        category    = "c2"
    strings:
        $s1 = "beacon.dll" nocase
        $s2 = "cobaltstrike" nocase
        $s3 = "ReflectiveLoader" nocase
        $s4 = "%s (admin)" ascii
        $b1 = { 69 68 69 68 69 6B }  // common beacon XOR pattern
        $b2 = "MZARUH" ascii         // reflective DLL stub
    condition:
        any of them
}

rule C2_Metasploit {
    meta:
        description = "Metasploit Meterpreter/payload indicators"
        severity    = "critical"
        category    = "c2"
    strings:
        $s1 = "meterpreter" nocase
        $s2 = "Meterpreter" ascii
        $s3 = "metasploit" nocase
        $s4 = "stdapi_" ascii
        $s5 = "kiwi_cmd" nocase
    condition:
        any of them
}

// ─── Data Exfiltration ───────────────────────────────────────────────────────

rule Exfil_ArchiveTool {
    meta:
        description = "Data staging / archiving prior to exfil"
        severity    = "medium"
        category    = "exfiltration"
    strings:
        $s1 = "7z a " nocase
        $s2 = "rar a " nocase
        $s3 = "zip -r " nocase
        $s4 = "-Password" nocase
        $s5 = "winrar" nocase
    condition:
        2 of them
}

rule Exfil_CurlWget {
    meta:
        description = "Data exfiltration via curl/wget"
        severity    = "medium"
        category    = "exfiltration"
    strings:
        $s1 = "curl -X POST" nocase
        $s2 = "curl --upload-file" nocase
        $s3 = "wget --post-file" nocase
        $s4 = "curl -F @" nocase
    condition:
        any of them
}

// ─── Persistence ─────────────────────────────────────────────────────────────

rule Persistence_ScheduledTask {
    meta:
        description = "Scheduled task / cron-based persistence"
        severity    = "high"
        category    = "persistence"
    strings:
        $s1 = "schtasks /create" nocase
        $s2 = "/sc ONLOGON" nocase
        $s3 = "/sc ONSTART" nocase
        $s4 = "at.exe" nocase
        $s5 = "/etc/cron" nocase
        $s6 = "crontab -e" nocase
    condition:
        any of them
}

rule Persistence_Registry {
    meta:
        description = "Registry run key persistence"
        severity    = "high"
        category    = "persistence"
    strings:
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $s2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $s3 = "CurrentVersion\\RunOnce" nocase
        $s4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        any of them
}

// ─── Anti-Forensics ──────────────────────────────────────────────────────────

rule AntiForensics_LogClearing {
    meta:
        description = "Log clearing / anti-forensics activity"
        severity    = "high"
        category    = "anti_forensics"
    strings:
        $s1 = "wevtutil cl" nocase
        $s2 = "Clear-EventLog" nocase
        $s3 = "Remove-Item.*EventLog" nocase
        $s4 = "history -c" nocase
        $s5 = "shred -u" nocase
        $s6 = "rm -rf ~/.bash_history" nocase
        $s7 = "HISTFILE=/dev/null" nocase
    condition:
        any of them
}
