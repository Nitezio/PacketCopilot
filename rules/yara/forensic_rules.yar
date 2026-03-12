rule Windows_PE_Header {
    meta:
        description = "Detects the 'MZ' magic header of a Windows Portable Executable"
        risk_level = "CRITICAL"
    strings:
        $mz = { 4d 5a }
    condition:
        $mz at 0
}

rule PowerShell_Downloader {
    meta:
        description = "Detects PowerShell WebClient or IEX download patterns"
        risk_level = "HIGH"
    strings:
        $s1 = "System.Net.WebClient" nocase
        $s2 = "DownloadFile" nocase
        $s3 = "DownloadString" nocase
        $s4 = "Invoke-Expression" nocase
        $s5 = "iex " nocase
    condition:
        $s1 and ($s2 or $s3) or ($s4 or $s5)
}

rule Obfuscated_VBScript {
    meta:
        description = "Detects common VBScript obfuscation or shell execution"
        risk_level = "HIGH"
    strings:
        $v1 = "WScript.Shell" nocase
        $v2 = "CreateObject" nocase
        $v3 = "Execute" nocase
        $v4 = "Chr(" nocase
    condition:
        all of ($v1, $v2) or ($v3 and $v4)
}

rule Generic_Shell_Command {
    meta:
        description = "Detects common shell commands indicative of command execution"
        risk_level = "MEDIUM"
    strings:
        $c1 = "whoami" nocase
        $c2 = "net user" nocase
        $c3 = "ipconfig /all" nocase
        $c4 = "cat /etc/passwd" nocase
    condition:
        any of them
}
