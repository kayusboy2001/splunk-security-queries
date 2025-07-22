# Splunk Security Detection Queries

This repository contains a comprehensive list of Splunk queries for detecting various security threats, including brute force attacks, lateral movement, privilege escalation, data exfiltration, phishing, ransomware, and more.

## Queries 1-110

### 1. Identify Potential DDoS Attacks
```spl
sourcetype=network_traffic
| stats sum(bytes) as total_bytes by src_ip
| where total_bytes > 100000000
```

### 2. Identify Potential Ransomware Activity
```spl
sourcetype=access_* action=file_delete
| rex field=file_path ".*\\.(?<extension>[^\\.]+)"
| search extension="encrypted" OR extension="locked" OR extension="ransom"
```

### 3. Identify Potential Insider Threats
```spl
sourcetype=access_* action=file_upload
| stats count by user, file_path
| where count > 10
```

### 4. Identify Successful Authentication Attempts from Unknown IP Addresses
```spl
sourcetype=access_* action=login
| stats count by src_ip
| where count >= 5 AND NOT src_ip IN (192.168.0.0/16, 10.0.0.0/8)
```

### 5. Identify Potential Brute Force Attacks on SSH
```spl
sourcetype=network_traffic service=ssh
| stats count by src_ip
| where count >= 10
```

### 6. Identify Successful SSH Logins from Unusual Countries
```spl
sourcetype=access_* action=login service=ssh
| iplocation src_ip
| stats count by src_country
| where count > 10 AND NOT src_country="United States"
```

### 7. Identify Exploit Attempts for Known Vulnerabilities
```spl
sourcetype=access_* method=POST
| rex field=_raw "(?<exploit>CVE-\\d{4}-\\d+)"
| stats count by exploit
| where count > 5
```

### 8. Identify Brute Force Attacks on a Specific User
```spl
sourcetype=access_* user=username AND action=failure
| stats count by src_ip
| where count >= 5
```

### 9. Identify Potential Man-in-the-Middle Attacks
```spl
sourcetype=network_traffic protocol=tcp
| stats count by dest_ip
| where count > 100
```

### 10. Identify Potential Data Exfiltration
```spl
sourcetype=access_* action=file_upload
| stats count by user, file_path
| where count > 10
```

### 11. Identify Potential DNS Tunneling Activity
```spl
sourcetype=dns
| rex field=answer "data\"\s*:\s*\"(?<data>[^\"]+)\""
| eval data_length=len(data)
| where data_length > 32 AND (data_length % 4) == 0
```

### 12. Identify Suspicious PowerShell Activity
```spl
sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
| eval script_block=mvindex(Message,3)
| search script_block="*Start-Process*"
```

### 13. Identify Unusual File Access
```spl
sourcetype=access_* action=file_delete OR action=file_rename
| stats count by user
| where count > 10
```

### 14. Identify Network Port Scans
```spl
sourcetype=network_traffic
| stats count by src_ip, dest_port
| where count > 100
```

### 15. Identify Suspicious Email Activity
```spl
sourcetype=email
| search "phishing" OR "malware" OR "suspicious link"
```

### 16. Identify Potential Data Exfiltration via Downloads
```spl
sourcetype=access_* action=file_download
| stats count by user, dest_ip, dest_port
| where count > 10
```

### 17. Identify Failed VPN Attempts
```spl
sourcetype=access_* VPN AND action="failure"
```

### 18. Identify Successful VPN Attempts
```spl
sourcetype=access_* VPN AND action="success"
```

### 19. Identify Login Attempts from New or Unknown IP Addresses
```spl
sourcetype=access_* action=login
| stats count by user, src_ip
| where count=1
```

### 20. Identify Potential SQL Injection Attempts
```spl
sourcetype=access_* method=POST
| rex field=_raw "SELECT\s+(?<query>[^;]+)"
| eval query_length=length(query)
| where query_length > 50 AND query_length < 100
```

### 21. Identify Unusual File Extensions
```spl
sourcetype=access_* action=file_upload
| rex field=file_path ".*\.(?<extension>[^\.]+)"
| stats count by extension
| where count > 10
```

### 22. Identify Potential Phishing Attacks
```spl
sourcetype=email
| search "password" OR "reset" OR "verify" OR "login"
```

### 23. Identify Traffic to Known Malicious IP Addresses
```spl
sourcetype=network_traffic dest_ip=malicious_ip
```

### 24. Identify Unusual Login Times
```spl
sourcetype=access_* action=login
| eval hour=strftime(_time,"%H")
| stats count by user, hour
| where count < 3
```

### 25. Identify Privilege Escalation Attempts on Linux Systems
```spl
sourcetype=linux_secure "sudo:"
| where user!="root" AND user!=""
```

### 26. Identify Potential Brute Force Attacks Against Specific User
```spl
sourcetype=access_* user=username AND action=failure
| stats count by src_ip
| where count >= 5
```

### 27. Identify Unusual DNS Requests
```spl
sourcetype=dns
| stats count by query
| where count > 10
```

### 28. Identify Potential Spear-Phishing Attempts
```spl
sourcetype=email
| search "CEO" OR "CFO" OR "Finance" OR "Accounting" OR "Payment"
```

### 29. Identify Potential Malware Infections
```spl
sourcetype=access_* action=file_download
| rex field=file_path ".*\.(?<extension>[^\.]+)"
| search extension="exe" OR extension="dll"
```

### 30. Identify Unusual User Activity (High Purchase Volume)
```spl
sourcetype=access_* action=purchase
| stats count by user
| where count > 100
```

### 31. Identify Potential DDoS Attacks
```spl
sourcetype=network_traffic
| stats sum(bytes) as total_bytes by src_ip
| where total_bytes > 100000000
```

### 32. Identify Potential Ransomware Activity
```spl
sourcetype=access_* action=file_delete
| rex field=file_path ".*\.(?<extension>[^\.]+)"
| search extension="encrypted" OR extension="locked" OR extension="ransom"
```

### 33. Identify Potential Insider Threats
```spl
sourcetype=access_* action=file_upload
| stats count by user, file_path
| where count > 10
```

### 34. Identify Authentication from Unknown IP Addresses
```spl
sourcetype=access_* action=login
| stats count by src_ip
| where count >= 5 AND NOT src_ip IN (192.168.0.0/16, 10.0.0.0/8)
```

### 35. Identify Potential Brute Force Attacks on SSH Service
```spl
sourcetype=network_traffic service=ssh
| stats count by src_ip
| where count >= 10
```

### 36. Identify SSH Logins from Unusual Countries
```spl
sourcetype=access_* action=login service=ssh
| iplocation src_ip
| stats count by src_country
| where count > 10 AND NOT src_country="United States"
```

### 37. Identify Potential CVE Exploitation Attempts
```spl
sourcetype=access_* method=POST
| rex field=_raw "(?<exploit>CVE-\d{4}-\d+)"
| stats count by exploit
| where count > 5
```

### 38. Identify Brute Force Attacks on Specific User (Alternative)
```spl
sourcetype=access_* user=username AND action=failure
| stats count by src_ip
| where count >= 5
```

### 39. Identify Potential Man-in-the-Middle Attacks (TCP Traffic)
```spl
sourcetype=network_traffic protocol=tcp
| stats count by dest_ip
| where count > 100
```

### 40. Identify Potential Data Exfiltration (File Uploads)
```spl
sourcetype=access_* action=file_upload
| stats count by user, file_path
| where count > 10
```

### 41. Identify Ransomware Activity on Windows Systems
```spl
sourcetype=WinEventLog:Security EventCode=4663
| rex field=Object_Name "\\\\.*\\\\(?<filename>.+)"
| rex field=filename ".*\.(?<extension>[^\.]+)"
| search extension="encrypted" OR extension="locked" OR extension="ransom"
```

### 42. Identify Unusual Network Traffic Patterns
```spl
sourcetype=network_traffic
| stats count by dest_ip, dest_port
| where count > 100 AND NOT dest_ip="192.168.0.1"
```

### 43. Identify Brute Force Attacks on HTTP Protocol
```spl
sourcetype=network_traffic protocol=http
| stats count by src_ip
| where count >= 50
```

### 44. Identify Potential Account Takeover Attempts
```spl
sourcetype=access_* action=login
| stats count by user
| where count > 10
```

### 45. Identify DNS Tunneling Activity (Alternative)
```spl
sourcetype=dns
| stats count by query
| where count > 5 AND NOT match(query, "\.")
```

### 46. Identify SQL Injection on Web Servers
```spl
sourcetype=access_* method=POST uri_path="*.php"
| rex field=_raw "SELECT\s+(?<query>[^;]+)"
| eval query_length=length(query)
| where query_length > 50 AND query_length < 100
```

### 47. Identify Brute Force Attacks on Specific Domain
```spl
sourcetype=access_* host=example.com AND action=failure
| stats count by src_ip
| where count >= 10
```

### 48. Identify Brute Force Attacks on Specific Application
```spl
sourcetype=access_* uri_path="/app/login" AND action=failure
| stats count by src_ip
| where count >= 5
```

### 49. Identify Phishing Attempts via Email Attachments
```spl
sourcetype=email
| search attachment="*.exe" OR attachment="*.zip"
```

### 50. Identify Exploitation Attempts on Vulnerable Services
```spl
sourcetype=network_traffic
| stats count by src_ip, dest_port
| where count > 10 AND dest_port IN (22, 3389, 1433, 3306, 8080)
```

### 51. Identify Potential Reconnaissance Activity
```spl
sourcetype=access_* method=GET
| stats count by uri_path
| where count > 100
```

### 52. Identify Potential Cross-Site Scripting (XSS) Attacks
```spl
sourcetype=access_* method=POST uri_path="*.php"
| rex field=_raw "document\.write\('(?<payload>[^']+)'\)"
| search payload="<script>"
```

### 53. Identify Potential Privilege Escalation Attempts
```spl
sourcetype=access_* action=privilege_escalation
| stats count by user
| where count > 5
```

### 54. Identify Potential Web Application Attacks
```spl
sourcetype=access_* method=POST uri_path="*.php"
| rex field=_raw "(?<attack>sql_injection|xss|csrf)"
| stats count by attack
| where count > 5
```

### 55. Identify Potential Lateral Movement via SMB
```spl
sourcetype=network_traffic protocol=tcp dest_port=445
| stats count by src_ip, dest_ip
| where count > 10
```

### 56. Identify Unauthorized Changes to Critical Files
```spl
sourcetype=access_* action=file_write
| search file_path="*/etc/*" OR file_path="*/var/*"
```

### 57. Identify Potential Port Scanning Activity
```spl
sourcetype=network_traffic protocol=tcp
| stats count by src_ip, dest_port
| where count > 20 AND NOT dest_port IN (22, 3389, 1433, 3306, 8080)
```

### 58. Identify Malicious PowerShell Activity on Windows
```spl
sourcetype=WinEventLog:Windows PowerShell EventCode=4104
| search (New-Object System.Net.WebClient).DownloadString OR (Invoke-WebRequest -Uri)
```

### 59. Identify SQL Injection Attempts (Extended)
```spl
sourcetype=access_* method=POST uri_path="*.php"
| rex field=_raw "SELECT\s+(?<query>[^;]+)"
| eval query_length=length(query)
| where query_length > 100 AND query_length < 200
```

### 60. Identify Brute Force on Domain Controller
```spl
sourcetype=WinEventLog:Security EventCode=4625 domain_controller="DC01"
| stats count by src_ip
| where count >= 5
```

### 61. Identify Potential DDoS Attacks (High Volume)
```spl
sourcetype=network_traffic
| stats count by src_ip
| where count > 1000
```

### 62. Identify Potential Web Shell Activity
```spl
sourcetype=access_* action=command_execution
| search (echo|print|printf)\s+(base64_decode|eval|gzinflate|str_rot13)
```

### 63. Identify Brute Force on Network Device
```spl
sourcetype=cisco:asa
| stats count by src_ip
| where count >= 10
```

### 64. Identify Privilege Escalation on Linux (Sudo)
```spl
sourcetype=access_* action="sudo command"
| stats count by user
| where count >= 10
```

### 65. Identify DNS Tunneling Activity (Advanced)
```spl
sourcetype=dns
| rex field=_raw "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#(?<query>.+)\s+\(\d+\)\s+type:(?<type>.+)\s+class: (?<class>.+)\s+[\d\s]+flags: (?<flags>.+)\s+;[\s\S]+response:\s+no error"
| search type="A" AND class="IN" AND flags="rd"
```

### 66. Identify Lateral Movement via RDP
```spl
sourcetype=WinEventLog:Security EventCode=4624 OR EventCode=4625
| search Logon_Type=10
```

### 67. Identify Command and Control Traffic
```spl
sourcetype=network_traffic
| stats count by dest_ip
| where count > 500 AND NOT dest_ip IN (192.168.0.0/16, 10.0.0.0/8)
```

### 68. Identify PowerShell Empire Activity
```spl
sourcetype=WinEventLog:Windows PowerShell
| search (powershell.exe net.webclient).downloadstring) -nop -w hidden -ep bypass -c)|(iex(new-object
```

### 69. Identify Ransomware File Activity
```spl
sourcetype=access_* action=file_write
| search file_path="*.crypt" OR file_path="*.locky"
```

### 70. Identify Malicious Traffic from Specific IP
```spl
sourcetype=network_traffic src_ip=10.1.1.1
| stats count by dest_ip
| where count > 10
```

### 71. Identify Brute Force on Web Applications
```spl
sourcetype=access_* method=POST uri_path="*.php"
| stats count by src_ip
| where count >= 50
```

### 72. Identify Unauthorized Access to Sensitive Files
```spl
sourcetype=access_* action=file_read
| search file_path="*/etc/shadow" OR file_path="*/etc/passwd"
```

### 73. Identify Lateral Movement via SMB Shares
```spl
sourcetype=WinEventLog:Security EventCode=5140
| search Object_Name="*\\ADMIN$" OR Object_Name="*\\C$"
```

### 74. Identify SSH Brute Force (Invalid Attempts)
```spl
sourcetype=linux_secure action=invalid
| stats count by src_ip
| where count >= 10
```

### 75. Identify Phishing Attacks via Form Submission
```spl
sourcetype=access_* method=POST uri_path="*.php"
| search form_action="http://www.evilsite.com/login.php" AND (input_password=* OR input_password=*)
```

### 76. Identify Command Injection on Web Servers
```spl
sourcetype=access_* method=POST uri_path="*.php"
| rex field=_raw "(?<command>cat|ls|dir)\s+(?<argument>[^;]+)"
| where isnotnull(command) AND isnotnull(argument)
```

### 77. Identify Lateral Movement via WinRM
```spl
sourcetype=WinEventLog:Microsoft-Windows-WinRM/Operational EventCode=146
| search "winrs: client" AND "is starting a command" AND NOT user="NETWORK SERVICE" AND NOT user="LocalSystem"
```

### 78. Identify Brute Force on WordPress Login
```spl
sourcetype=access_* method=POST uri_path="*/wp-login.php"
| stats count by src_ip
| where count >= 20
```

### 79. Identify Windows Privilege Escalation
```spl
sourcetype=WinEventLog:Security EventCode=4688
| search (New_Process_Name="*\\runas.exe" OR New_Process_Name="*\\psexec.exe") AND NOT User="SYSTEM"
```

### 80. Identify Beaconing Activity from Compromised Host
```spl
sourcetype=network_traffic src_ip=10.1.1.1
| stats count by dest_port
| where count > 1000
```

### 81. Identify SSH Failed Login Attempts
```spl
sourcetype=linux_secure action=failed
| stats count by src_ip
| where count >= 10
```

### 82. Identify Data Exfiltration via HTTP Downloads
```spl
sourcetype=access_* action=file_download
| search uri_path="*.zip" OR uri_path="*.rar" OR uri_path="*.tgz" OR uri_path="*.tar.gz"
```

### 83. Identify Lateral Movement via WMI
```spl
sourcetype=WinEventLog:Security EventCode=5861
| search (Operation="ExecQuery" AND QueryLanguage="WQL") OR (Operation="MethodCall" AND NOT MethodName="GetSecurityDescriptor" AND NOT MethodName="SetSecurityDescriptor")
```

### 84. Identify MSSQL Server Brute Force
```spl
sourcetype=mssql_access action=failed
| stats count by src_ip
| where count >= 10
```

### 85. Identify PowerShell Privilege Escalation
```spl
sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational EventCode=400
| search "PowerShell pipeline execution details" AND NOT "UserPrincipalName=SYSTEM@*" AND NOT "UserPrincipalName=NETWORK SERVICE@*"
```

### 86. Identify Email Account Brute Force
```spl
sourcetype=exchangeps
| stats count by src_ip
| where count >= 10
```

### 87. Identify Successful RDP Lateral Movement
```spl
sourcetype=WinEventLog:Security EventCode=4624
| search Logon_Type=10
```

### 88. Identify Successful MSSQL Logins
```spl
sourcetype=mssql_access action=success
| stats count by src_ip
| where count >= 10
```

### 89. Identify Data Exfiltration via FTP
```spl
sourcetype=access_* action=file_upload
| search uri_path="*/ftp" OR uri_path="*/sftp"
```

### 90. Identify Successful SMB Lateral Movement
```spl
sourcetype=WinEventLog:Security EventCode=5140
| search Object_Name="*\\ADMIN$" OR Object_Name="*\\C$"
```

### 91. Identify RDP Brute Force Attacks
```spl
sourcetype=WinEventLog:Security EventCode=4625
| search Logon_Type=10 AND Status="0xC000006D"
```

### 92. Identify Web Application Brute Force (Extended)
```spl
sourcetype=access_* method=POST
| stats count by src_ip, uri_path
| where count >= 100
```

### 93. Identify Remote Registry Lateral Movement
```spl
sourcetype=WinEventLog:Security EventCode=4663
| search Object_Name="*\\REGISTRY\\MACHINE\\SOFTWARE" AND NOT User="SYSTEM" AND NOT User="NETWORK SERVICE" AND NOT User="LOCAL SERVICE"
```

### 94. Identify Linux Privilege Escalation (Sudo)
```spl
sourcetype=linux_secure "sudo:"
```

### 95. Identify Data Exfiltration via DNS
```spl
sourcetype=dns
| search query_type=A AND query !="*.google.com" AND query !="*.facebook.com" AND query !="*.twitter.com" AND query !="*.microsoft.com"
```

### 96. Identify Failed SMB Lateral Movement
```spl
sourcetype=WinEventLog:Security EventCode=5152
| search Object_Name="*\\ADMIN$" OR Object_Name="*\\C$" AND Status="0xC000006D"
```

### 97. Identify MSSQL Failed Login Attempts
```spl
sourcetype=mssql_access action=failed
| stats count by src_ip
| where count >= 10
```

### 98. Identify Data Exfiltration via SMTP
```spl
sourcetype=smtp action=send_message
| search recipient!="*@gmail.com" AND recipient!="*@yahoo.com" AND recipient!="*@hotmail.com" AND recipient!="*@aol.com"
```

### 99. Identify NetBIOS Lateral Movement
```spl
sourcetype=WinEventLog:Security EventCode=5719
| search "No Domain Controller is available" OR "This computer was not able to set up a secure session with a domain controller"
```

### 100. Identify Telnet Server Brute Force
```spl
sourcetype=access_* method=POST uri_path="*/telnet"
| stats count by src_ip
| where count >= 10
```

### 101. Identify FTP Data Exfiltration
```spl
sourcetype=ftp action=putfile
| stats count by src_ip
| where count >= 10
```

### 102. Identify Failed WMI Lateral Movement
```spl
sourcetype=WinEventLog:Security EventCode=5605
| search Object_Name="*\\ROOT\\CIMV2" AND NOT User="SYSTEM"
```

### 103. Identify SSH Server Brute Force (Alternative)
```spl
sourcetype=access_* method=POST uri_path="*/ssh"
| stats count by src_ip
| where count >= 10
```

### 104. Identify Windows Service Configuration Changes
```spl
sourcetype=WinEventLog:Security EventCode=4697 OR EventCode=7045
| search Image_Path="*\\System32\\*" AND NOT User="SYSTEM"
```

### 105. Identify SNMP Brute Force Attacks
```spl
sourcetype=snmptrap
| stats count by src_ip
| where count >= 10
```

### 106. Identify HTTP Upload Data Exfiltration
```spl
sourcetype=access_* method=POST uri_path="/upload"
| stats count by src_ip
| where count >= 10
```

### 107. Identify Failed DCOM Lateral Movement
```spl
sourcetype=WinEventLog:Security EventCode=10009
| search "DCOM was unable to communicate with the computer" AND NOT User="SYSTEM"
```

### 108. Identify MySQL Server Brute Force
```spl
sourcetype=mysql_access action=failed
| stats count by src_ip
| where count >= 10
```

### 109. Identify Scheduled Task Privilege Escalation
```spl
sourcetype=WinEventLog:Security EventCode=4698
| search "Task Scheduler service found a misconfiguration" AND NOT User="SYSTEM"
```

### 110. Identify HTTPS Data Exfiltration
```spl
sourcetype=ssl method=POST
| stats count by src_ip, dest_ip
| where count >= 10
```

---
## Usage
- Copy and paste the relevant query into your Splunk environment.
- Modify fields as needed based on your data model.

## Contribution
Feel free to contribute additional queries via pull requests.

## License
MIT License
