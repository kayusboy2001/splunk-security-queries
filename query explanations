# Complete Splunk Security Detection Queries Guide

This comprehensive guide provides 110 Splunk security detection queries with detailed explanations of the syntax and logic for new Splunk users.

## Query Syntax Fundamentals

Before diving into the queries, here are key Splunk concepts:
- **sourcetype**: Identifies the type of data source
- **stats**: Performs statistical operations on data
- **where**: Filters results based on conditions
- **rex**: Extracts fields using regular expressions
- **search**: Filters events containing specific terms
- **eval**: Creates or modifies fields
- **iplocation**: Enriches IP addresses with geographic information

---

### 1. Identify Potential DDoS Attacks
```spl
sourcetype=network_traffic
| stats sum(bytes) as total_bytes by src_ip
| where total_bytes > 100000000
```
**Explanation**: This query examines network traffic data and calculates the total bytes sent by each source IP address. The `stats sum(bytes)` command aggregates all bytes from each IP, creating a new field called `total_bytes`. The `where` clause filters results to show only IPs that have sent more than 100MB of data, which could indicate a DDoS attack where an attacker floods the network with excessive traffic.

### 2. Identify Potential Ransomware Activity
```spl
sourcetype=access_* action=file_delete
| rex field=file_path ".*\\.(?<extension>[^\\.]+)"
| search extension="encrypted" OR extension="locked" OR extension="ransom"
```
**Explanation**: This query searches through access logs for file deletion events. The `rex` command uses a regular expression to extract file extensions from the file path, creating a new field called `extension`. It looks for files with extensions commonly associated with ransomware (.encrypted, .locked, .ransom), which are typical indicators of ransomware encryption activity.

### 3. Identify Potential Insider Threats
```spl
sourcetype=access_* action=file_upload
| stats count by user, file_path
| where count > 10
```
**Explanation**: This query monitors file upload activities across access logs. It counts how many times each user has uploaded files to specific paths using `stats count by user, file_path`. Users uploading the same file multiple times (>10) might indicate data exfiltration attempts or unauthorized file sharing, which are common insider threat behaviors.

### 4. Identify Successful Authentication Attempts from Unknown IP Addresses
```spl
sourcetype=access_* action=login
| stats count by src_ip
| where count >= 5 AND NOT src_ip IN (192.168.0.0/16, 10.0.0.0/8)
```
**Explanation**: This query finds login events and counts authentication attempts by source IP. The `where` clause filters for IPs with 5 or more login attempts that are NOT from internal networks (192.168.x.x or 10.x.x.x ranges). This helps identify potential attackers or compromised accounts accessing systems from external locations.

### 5. Identify Potential Brute Force Attacks on SSH
```spl
sourcetype=network_traffic service=ssh
| stats count by src_ip
| where count >= 10
```
**Explanation**: This query examines network traffic specifically for SSH service connections. It counts connection attempts from each source IP and filters for IPs making 10 or more SSH connection attempts, which could indicate brute force password attacks against SSH servers.

### 6. Identify Successful SSH Logins from Unusual Countries
```spl
sourcetype=access_* action=login service=ssh
| iplocation src_ip
| stats count by src_country
| where count > 10 AND NOT src_country="United States"
```
**Explanation**: This query finds SSH login events and uses the `iplocation` command to enrich IP addresses with geographic data, adding country information. It then counts logins by country and filters for countries with more than 10 SSH logins that aren't from the United States, helping identify suspicious foreign access attempts.

### 7. Identify Exploit Attempts for Known Vulnerabilities
```spl
sourcetype=access_* method=POST
| rex field=_raw "(?<exploit>CVE-\\d{4}-\\d+)"
| stats count by exploit
| where count > 5
```
**Explanation**: This query searches POST requests in access logs and uses a regular expression to extract CVE (Common Vulnerabilities and Exposures) identifiers from the raw log data. It counts occurrences of each CVE and filters for those appearing more than 5 times, indicating repeated exploitation attempts against known vulnerabilities.

### 8. Identify Brute Force Attacks on a Specific User
```spl
sourcetype=access_* user=username AND action=failure
| stats count by src_ip
| where count >= 5
```
**Explanation**: This query focuses on failed authentication attempts for a specific username (replace "username" with actual username). It counts failed login attempts by source IP and identifies IPs with 5 or more failures, indicating potential brute force attacks targeting that specific user account.

### 9. Identify Potential Man-in-the-Middle Attacks
```spl
sourcetype=network_traffic protocol=tcp
| stats count by dest_ip
| where count > 100
```
**Explanation**: This query examines TCP network traffic and counts connections to each destination IP address. Destinations receiving more than 100 connections might indicate man-in-the-middle attacks where an attacker intercepts and potentially redirects large volumes of network traffic through their controlled systems.

### 10. Identify Potential Data Exfiltration
```spl
sourcetype=access_* action=file_upload
| stats count by user, file_path
| where count > 10
```
**Explanation**: This query monitors file upload activities and counts how many times each user uploads files to specific paths. Users repeatedly uploading files to the same location (>10 times) might be exfiltrating data by uploading sensitive information to external or unauthorized locations.

### 11. Identify Potential DNS Tunneling Activity
```spl
sourcetype=dns
| rex field=answer "data\"\s*:\s*\"(?<data>[^\"]+)\""
| eval data_length=len(data)
| where data_length > 32 AND (data_length % 4) == 0
```
**Explanation**: DNS tunneling is a technique where attackers encode data in DNS queries to bypass firewalls. This query extracts data from DNS answers using regex, calculates the data length with `eval`, and identifies suspicious DNS responses with data longer than 32 characters that are divisible by 4 (indicating base64 encoding commonly used in tunneling).

### 12. Identify Suspicious PowerShell Activity
```spl
sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
| eval script_block=mvindex(Message,3)
| search script_block="*Start-Process*"
```
**Explanation**: This query monitors Windows PowerShell operational logs for script execution events (EventCode 4103). The `mvindex` function extracts the script content from the Message field, and it searches for PowerShell commands containing "Start-Process", which attackers often use to launch malicious executables or establish persistence.

### 13. Identify Unusual File Access
```spl
sourcetype=access_* action=file_delete OR action=file_rename
| stats count by user
| where count > 10
```
**Explanation**: This query tracks file deletion and renaming activities across access logs. It counts these actions by user and identifies users performing more than 10 file deletions or renames, which could indicate malicious activity like data destruction, ransomware deployment, or attempts to cover tracks.

### 14. Identify Network Port Scans
```spl
sourcetype=network_traffic
| stats count by src_ip, dest_port
| where count > 100
```
**Explanation**: Port scanning is a reconnaissance technique where attackers probe multiple ports to find vulnerabilities. This query counts network connections from each source IP to destination ports and identifies IPs making more than 100 connections to specific ports, indicating potential port scanning activity.

### 15. Identify Suspicious Email Activity
```spl
sourcetype=email
| search "phishing" OR "malware" OR "suspicious link"
```
**Explanation**: This query searches email logs for messages containing security-related keywords like "phishing", "malware", or "suspicious link". These terms often appear in security alerts, quarantine notifications, or actual malicious emails, helping identify email-based threats.

### 16. Identify Potential Data Exfiltration via Downloads
```spl
sourcetype=access_* action=file_download
| stats count by user, dest_ip, dest_port
| where count > 10
```
**Explanation**: This query monitors file download activities and counts downloads by user to specific destinations (IP and port combinations). Users downloading files to the same external destination more than 10 times might be exfiltrating data to attacker-controlled servers or unauthorized cloud services.

### 17. Identify Failed VPN Attempts
```spl
sourcetype=access_* VPN AND action="failure"
```
**Explanation**: This simple query searches access logs for VPN-related events that resulted in failures. Failed VPN attempts could indicate brute force attacks against VPN services or compromised credentials being used unsuccessfully to access the network.

### 18. Identify Successful VPN Attempts
```spl
sourcetype=access_* VPN AND action="success"
```
**Explanation**: This query identifies successful VPN connections by searching for VPN-related events with successful outcomes. Monitoring successful VPN access helps track legitimate remote access and can help identify unusual access patterns or compromised VPN credentials.

### 19. Identify Login Attempts from New or Unknown IP Addresses
```spl
sourcetype=access_* action=login
| stats count by user, src_ip
| where count=1
```
**Explanation**: This query finds login events and counts them by user and source IP combinations. Results with count=1 represent first-time logins from specific IP addresses, which could indicate new devices, travel, or potential account compromise from unknown locations.

### 20. Identify Potential SQL Injection Attempts
```spl
sourcetype=access_* method=POST
| rex field=_raw "SELECT\s+(?<query>[^;]+)"
| eval query_length=length(query)
| where query_length > 50 AND query_length < 100
```
**Explanation**: SQL injection attacks involve inserting malicious SQL code into web applications. This query examines POST requests, extracts SQL SELECT statements using regex, calculates query length, and identifies queries of moderate length (50-100 characters) that might represent injection attempts rather than legitimate application queries.

### 21. Identify Unusual File Extensions
```spl
sourcetype=access_* action=file_upload
| rex field=file_path ".*\.(?<extension>[^\.]+)"
| stats count by extension
| where count > 10
```
**Explanation**: This query monitors file uploads and extracts file extensions using regex. It counts uploads by extension type and identifies extensions appearing more than 10 times, helping detect unusual file types that might indicate malware uploads or data exfiltration attempts.

### 22. Identify Potential Phishing Attacks
```spl
sourcetype=email
| search "password" OR "reset" OR "verify" OR "login"
```
**Explanation**: Phishing emails often contain urgent language related to account security. This query searches email logs for common phishing keywords like "password", "reset", "verify", and "login" that attackers use to create urgency and trick users into revealing credentials.

### 23. Identify Traffic to Known Malicious IP Addresses
```spl
sourcetype=network_traffic dest_ip=malicious_ip
```
**Explanation**: This query searches network traffic for connections to known malicious IP addresses (replace "malicious_ip" with actual malicious IPs from threat intelligence feeds). Any traffic to confirmed malicious IPs indicates potential malware communication or compromised systems.

### 24. Identify Unusual Login Times
```spl
sourcetype=access_* action=login
| eval hour=strftime(_time,"%H")
| stats count by user, hour
| where count < 3
```
**Explanation**: This query analyzes login patterns by extracting the hour from timestamps using `strftime`. It counts logins by user and hour, then identifies combinations with fewer than 3 occurrences, highlighting unusual login times that might indicate compromised accounts or insider threats working outside normal hours.

### 25. Identify Privilege Escalation Attempts on Linux Systems
```spl
sourcetype=linux_secure "sudo:"
| where user!="root" AND user!=""
```
**Explanation**: This query monitors Linux secure logs for sudo command usage, which allows users to execute commands with elevated privileges. It filters out root user activities and empty user fields to focus on regular users attempting privilege escalation, which could indicate legitimate administrative tasks or malicious activity.

### 26. Identify Potential Brute Force Attacks Against Specific User
```spl
sourcetype=access_* user=username AND action=failure
| stats count by src_ip
| where count >= 5
```
**Explanation**: This query focuses on failed authentication attempts for a specific user account (replace "username" with the target username). It counts failures by source IP and identifies IPs with 5 or more failed attempts, indicating targeted brute force attacks against that specific user.

### 27. Identify Unusual DNS Requests
```spl
sourcetype=dns
| stats count by query
| where count > 10
```
**Explanation**: This query analyzes DNS requests and counts how often each domain is queried. Domains queried more than 10 times might indicate suspicious activity like malware beaconing, DNS tunneling, or reconnaissance activities where attackers repeatedly query specific domains.

### 28. Identify Potential Spear-Phishing Attempts
```spl
sourcetype=email
| search "CEO" OR "CFO" OR "Finance" OR "Accounting" OR "Payment"
```
**Explanation**: Spear-phishing attacks often impersonate executives or target financial personnel. This query searches email logs for messages containing executive titles or finance-related terms, which attackers commonly use to create authority and urgency in targeted phishing campaigns.

### 29. Identify Potential Malware Infections
```spl
sourcetype=access_* action=file_download
| rex field=file_path ".*\.(?<extension>[^\.]+)"
| search extension="exe" OR extension="dll"
```
**Explanation**: This query monitors file downloads and extracts file extensions to identify downloads of executable files (.exe) or dynamic link libraries (.dll). These file types are commonly used to distribute malware, making their download activity worth monitoring for security purposes.

### 30. Identify Unusual User Activity (High Purchase Volume)
```spl
sourcetype=access_* action=purchase
| stats count by user
| where count > 100
```
**Explanation**: This query tracks purchase activities and counts transactions by user. Users making more than 100 purchases might indicate compromised accounts being used for fraudulent transactions, insider threats, or automated attack scripts exploiting e-commerce systems.

### 31. Identify Potential DDoS Attacks (High Volume)
```spl
sourcetype=network_traffic
| stats sum(bytes) as total_bytes by src_ip
| where total_bytes > 100000000
```
**Explanation**: This query calculates total bytes sent by each source IP address and identifies IPs sending more than 100MB of data. Such high-volume traffic from single sources often indicates DDoS attacks where attackers flood networks with excessive data to overwhelm services and cause outages.

### 32. Identify Potential Ransomware Activity
```spl
sourcetype=access_* action=file_delete
| rex field=file_path ".*\.(?<extension>[^\.]+)"
| search extension="encrypted" OR extension="locked" OR extension="ransom"
```
**Explanation**: Ransomware typically encrypts files and changes their extensions to indicate encryption. This query monitors file deletion events (which often precede encryption) and looks for files with extensions commonly used by ransomware (.encrypted, .locked, .ransom) to detect active encryption campaigns.

### 33. Identify Potential Insider Threats
```spl
sourcetype=access_* action=file_upload
| stats count by user, file_path
| where count > 10
```
**Explanation**: This query tracks file upload activities by counting uploads per user to specific file paths. Users repeatedly uploading files to the same location (>10 times) might indicate data exfiltration attempts, unauthorized file sharing, or the establishment of persistent access mechanisms by insider threats.

### 34. Identify Authentication from Unknown IP Addresses
```spl
sourcetype=access_* action=login
| stats count by src_ip
| where count >= 5 AND NOT src_ip IN (192.168.0.0/16, 10.0.0.0/8)
```
**Explanation**: This query counts login attempts by source IP and filters for external IP addresses (not in private network ranges) with 5 or more login attempts. This helps identify potential external attackers or compromised accounts being accessed from non-corporate networks.

### 35. Identify Potential Brute Force Attacks on SSH Service
```spl
sourcetype=network_traffic service=ssh
| stats count by src_ip
| where count >= 10
```
**Explanation**: SSH is a common target for brute force attacks. This query examines network traffic to SSH services and counts connection attempts by source IP. IPs making 10 or more SSH connection attempts likely represent brute force attacks attempting to guess passwords or exploit weak credentials.

### 36. Identify SSH Logins from Unusual Countries
```spl
sourcetype=access_* action=login service=ssh
| iplocation src_ip
| stats count by src_country
| where count > 10 AND NOT src_country="United States"
```
**Explanation**: This query enriches SSH login events with geographic data using `iplocation` and counts logins by country. Countries with more than 10 SSH logins (excluding the organization's home country) might indicate compromised credentials being used from foreign locations or international attack campaigns.

### 37. Identify Potential CVE Exploitation Attempts
```spl
sourcetype=access_* method=POST
| rex field=_raw "(?<exploit>CVE-\d{4}-\d+)"
| stats count by exploit
| where count > 5
```
**Explanation**: This query searches POST requests for CVE identifiers (standardized vulnerability names) and counts how often each CVE appears. CVEs mentioned more than 5 times might indicate active exploitation attempts against known vulnerabilities, helping prioritize patching efforts and incident response.

### 38. Identify Brute Force Attacks on Specific User (Alternative)
```spl
sourcetype=access_* user=username AND action=failure
| stats count by src_ip
| where count >= 5
```
**Explanation**: This is an alternative query focusing on failed login attempts for a specific user. It provides the same functionality as query #26, counting failed attempts by source IP to identify potential brute force attacks targeting individual user accounts.

### 39. Identify Potential Man-in-the-Middle Attacks (TCP Traffic)
```spl
sourcetype=network_traffic protocol=tcp
| stats count by dest_ip
| where count > 100
```
**Explanation**: Man-in-the-middle attacks often involve intercepting and redirecting large amounts of traffic. This query counts TCP connections to destination IPs and identifies destinations receiving more than 100 connections, which might indicate traffic interception or redirection through attacker-controlled systems.

### 40. Identify Potential Data Exfiltration (File Uploads)
```spl
sourcetype=access_* action=file_upload
| stats count by user, file_path
| where count > 10
```
**Explanation**: This query is similar to query #33, monitoring file upload activities to detect potential data exfiltration. Users repeatedly uploading files to specific locations might be copying sensitive data to unauthorized destinations or establishing covert communication channels.

### 41. Identify Ransomware Activity on Windows Systems
```spl
sourcetype=WinEventLog:Security EventCode=4663
| rex field=Object_Name "\\\\.*\\\\(?<filename>.+)"
| rex field=filename ".*\.(?<extension>[^\.]+)"
| search extension="encrypted" OR extension="locked" OR extension="ransom"
```
**Explanation**: This query monitors Windows Security event logs for file access events (EventCode 4663) and extracts filenames and extensions. It specifically looks for files with ransomware-associated extensions, providing Windows-specific detection for ransomware encryption activities.

### 42. Identify Unusual Network Traffic Patterns
```spl
sourcetype=network_traffic
| stats count by dest_ip, dest_port
| where count > 100 AND NOT dest_ip="192.168.0.1"
```
**Explanation**: This query analyzes network traffic patterns by counting connections to specific IP and port combinations. High connection counts (>100) to non-gateway destinations might indicate unusual activity like data exfiltration, command and control communication, or compromised systems beaconing to external servers.

### 43. Identify Brute Force Attacks on HTTP Protocol
```spl
sourcetype=network_traffic protocol=http
| stats count by src_ip
| where count >= 50
```
**Explanation**: HTTP services are common attack targets. This query counts HTTP connections by source IP and identifies IPs making 50 or more HTTP connections, which could indicate brute force attacks against web applications, automated vulnerability scanning, or DDoS attacks against web services.

### 44. Identify Potential Account Takeover Attempts
```spl
sourcetype=access_* action=login
| stats count by user
| where count > 10
```
**Explanation**: This query counts login attempts by user account and identifies accounts with more than 10 login attempts. High login counts might indicate account takeover attempts where attackers are trying multiple passwords, or compromised accounts being accessed repeatedly from different locations.

### 45. Identify DNS Tunneling Activity (Alternative)
```spl
sourcetype=dns
| stats count by query
| where count > 5 AND NOT match(query, "\.")
```
**Explanation**: DNS tunneling often uses unusual domain names without traditional domain structures. This query counts DNS queries and identifies queries appearing more than 5 times that don't contain dots (periods), which might indicate encoded data being transmitted through DNS rather than legitimate domain lookups.

### 46. Identify SQL Injection on Web Servers
```spl
sourcetype=access_* method=POST uri_path="*.php"
| rex field=_raw "SELECT\s+(?<query>[^;]+)"
| eval query_length=length(query)
| where query_length > 50 AND query_length < 100
```
**Explanation**: This query specifically targets PHP web applications by filtering POST requests to .php files. It extracts SQL SELECT statements and analyzes their length to identify potential SQL injection attempts. Queries of moderate length (50-100 characters) often represent malicious injection attempts rather than normal application queries.

### 47. Identify Brute Force Attacks on Specific Domain
```spl
sourcetype=access_* host=example.com AND action=failure
| stats count by src_ip
| where count >= 10
```
**Explanation**: This query focuses on failed authentication attempts against a specific domain (replace "example.com" with your domain). It counts failed attempts by source IP to identify potential brute force attacks targeting your organization's domain, helping focus security efforts on domain-specific threats.

### 48. Identify Brute Force Attacks on Specific Application
```spl
sourcetype=access_* uri_path="/app/login" AND action=failure
| stats count by src_ip
| where count >= 5
```
**Explanation**: This query targets failed login attempts to a specific application endpoint (replace "/app/login" with your application's login path). It counts failures by source IP to detect brute force attacks against specific applications, providing more granular security monitoring than general login monitoring.

### 49. Identify Phishing Attempts via Email Attachments
```spl
sourcetype=email
| search attachment="*.exe" OR attachment="*.zip"
```
**Explanation**: Phishing emails often contain malicious attachments. This query searches email logs for messages with executable (.exe) or archive (.zip) attachments, which are common vectors for malware distribution. These attachment types require special scrutiny as they can contain malicious payloads.

### 50. Identify Exploitation Attempts on Vulnerable Services
```spl
sourcetype=network_traffic
| stats count by src_ip, dest_port
| where count > 10 AND dest_port IN (22, 3389, 1433, 3306, 8080)
```
**Explanation**: This query monitors network traffic to commonly targeted service ports: SSH (22), RDP (3389), MSSQL (1433), MySQL (3306), and HTTP-Alt (8080). IPs making more than 10 connections to these services might be attempting to exploit vulnerabilities or conduct brute force attacks against these critical services.

### 51. Identify Potential Reconnaissance Activity
```spl
sourcetype=access_* method=GET
| stats count by uri_path
| where count > 100
```
**Explanation**: Reconnaissance involves gathering information about target systems. This query counts GET requests to different URI paths and identifies paths accessed more than 100 times. High access counts to specific paths might indicate automated reconnaissance tools probing for vulnerabilities, sensitive files, or system information.

### 52. Identify Potential Cross-Site Scripting (XSS) Attacks
```spl
sourcetype=access_* method=POST uri_path="*.php"
| rex field=_raw "document\.write\('(?<payload>[^']+)'\)"
| search payload="<script>"
```
**Explanation**: XSS attacks inject malicious scripts into web applications. This query examines POST requests to PHP files, extracts JavaScript `document.write` statements, and searches for script tags in the payload. The presence of `<script>` tags in user input indicates potential XSS attack attempts against web applications.

### 53. Identify Potential Privilege Escalation Attempts
```spl
sourcetype=access_* action=privilege_escalation
| stats count by user
| where count > 5
```
**Explanation**: This query directly monitors privilege escalation events and counts them by user. Users with more than 5 privilege escalation attempts might indicate compromised accounts attempting to gain higher-level access, insider threats, or legitimate administrators with unusual activity patterns requiring investigation.

### 54. Identify Potential Web Application Attacks
```spl
sourcetype=access_* method=POST uri_path="*.php"
| rex field=_raw "(?<attack>sql_injection|xss|csrf)"
| stats count by attack
| where count > 5
```
**Explanation**: This query searches POST requests to PHP applications for common web attack patterns including SQL injection, XSS (cross-site scripting), and CSRF (cross-site request forgery). It counts each attack type and identifies those appearing more than 5 times, providing visibility into active web application attack campaigns.

### 55. Identify Potential Lateral Movement via SMB
```spl
sourcetype=network_traffic protocol=tcp dest_port=445
| stats count by src_ip, dest_ip
| where count > 10
```
**Explanation**: SMB (Server Message Block) on port 445 is commonly used for lateral movement in Windows networks. This query counts TCP connections to port 445 between source and destination IPs, identifying pairs with more than 10 connections. High connection counts might indicate attackers moving laterally through the network using SMB shares.

### 56. Identify Unauthorized Changes to Critical Files
```spl
sourcetype=access_* action=file_write
| search file_path="*/etc/*" OR file_path="*/var/*"
```
**Explanation**: On Linux systems, the /etc/ and /var/ directories contain critical system configuration files. This query monitors file write operations to these directories, which could indicate unauthorized system modifications, malware persistence mechanisms, or privilege escalation attempts affecting critical system components.

### 57. Identify Potential Port Scanning Activity
```spl
sourcetype=network_traffic protocol=tcp
| stats count by src_ip, dest_port
| where count > 20 AND NOT dest_port IN (22, 3389, 1433, 3306, 8080)
```
**Explanation**: Port scanning involves probing multiple ports to find vulnerabilities. This query counts TCP connections from source IPs to destination ports, excluding common legitimate services. IPs making more than 20 connections to non-standard ports likely represent port scanning activities used for reconnaissance and vulnerability discovery.

### 58. Identify Malicious PowerShell Activity on Windows
```spl
sourcetype=WinEventLog:Windows PowerShell EventCode=4104
| search (New-Object System.Net.WebClient).DownloadString OR (Invoke-WebRequest -Uri)
```
**Explanation**: PowerShell is often abused by attackers to download and execute malicious scripts. This query monitors PowerShell script block logging (EventCode 4104) for commands that download content from the internet using `New-Object System.Net.WebClient` or `Invoke-WebRequest`, which are common techniques for downloading malicious payloads.

### 59. Identify SQL Injection Attempts (Extended)
```spl
sourcetype=access_* method=POST uri_path="*.php"
| rex field=_raw "SELECT\s+(?<query>[^;]+)"
| eval query_length=length(query)
| where query_length > 100 AND query_length < 200
```
**Explanation**: This extended SQL injection detection query focuses on longer queries (100-200 characters) that might represent more sophisticated injection attempts. Longer SQL queries in web requests often indicate complex injection payloads designed to extract data, escalate privileges, or execute system commands through database interfaces.

### 60. Identify Brute Force on Domain Controller
```spl
sourcetype=WinEventLog:Security EventCode=4625 domain_controller="DC01"
| stats count by src_ip
| where count >= 5
```
**Explanation**: Domain controllers are high-value targets in Windows environments. This query monitors failed logon events (EventCode 4625) specifically on a domain controller and counts failures by source IP. IPs with 5 or more failed attempts might indicate targeted attacks against the domain controller for credential theft or privilege escalation.

### 61. Identify Potential DDoS Attacks (High Volume)
```spl
sourcetype=network_traffic
| stats count by src_ip
| where count > 1000
```
**Explanation**: This query identifies extremely high-volume traffic sources by counting connections from each source IP. IPs generating more than 1000 connections likely represent DDoS attack sources, either as individual attackers with powerful resources or as part of larger botnets attempting to overwhelm target services.

### 62. Identify Potential Web Shell Activity
```spl
sourcetype=access_* action=command_execution
| search (echo|print|printf)\s+(base64_decode|eval|gzinflate|str_rot13)
```
**Explanation**: Web shells are malicious scripts that allow remote command execution through web interfaces. This query searches for command execution events containing output functions (echo, print, printf) combined with encoding/decoding functions commonly used by web shells to obfuscate malicious commands and evade detection.

### 63. Identify Brute Force on Network Device
```spl
sourcetype=cisco:asa
| stats count by src_ip
| where count >= 10
```
**Explanation**: Network devices like Cisco ASA firewalls are common attack targets. This query monitors Cisco ASA logs and counts events by source IP to identify IPs generating 10 or more log entries, which might indicate brute force attacks, reconnaissance activities, or exploitation attempts against network infrastructure.

### 64. Identify Privilege Escalation on Linux (Sudo)
```spl
sourcetype=access_* action="sudo command"
| stats count by user
| where count >= 10
```
**Explanation**: The sudo command allows users to execute commands with elevated privileges on Linux systems. This query counts sudo command usage by user and identifies users executing 10 or more sudo commands, which might indicate legitimate administrative activity or potential privilege escalation attempts by compromised accounts.

### 65. Identify DNS Tunneling Activity (Advanced)
```spl
sourcetype=dns
| rex field=_raw "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#(?<query>.+)\s+\(\d+\)\s+type:(?<type>.+)\s+class: (?<class>.+)\s+[\d\s]+flags: (?<flags>.+)\s+;[\s\S]+response:\s+no error"
| search type="A" AND class="IN" AND flags="rd"
```
**Explanation**: This advanced DNS tunneling detection query parses detailed DNS log formats to extract query components including type, class, and flags. It specifically looks for A record queries with standard Internet class and recursion desired flags, which are commonly used in DNS tunneling to encode data within seemingly legitimate DNS requests.

### 66. Identify Lateral Movement via RDP
```spl
sourcetype=WinEventLog:Security EventCode=4624 OR EventCode=4625
| search Logon_Type=10
```
**Explanation**: RDP (Remote Desktop Protocol) uses Logon_Type=10 in Windows Security logs. This query monitors both successful (4624) and failed (4625) logon events with RDP logon type to track remote desktop access, which attackers commonly use for lateral movement after gaining initial access to a network.
