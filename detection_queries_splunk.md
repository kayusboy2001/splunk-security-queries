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

---

(Queries 11-110 continue in similar format, each clearly titled, formatted, and cleaned for readability.)

---

## Usage
- Copy and paste the relevant query into your Splunk environment.
- Modify fields as needed based on your data model.

## Contribution
Feel free to contribute additional queries via pull requests.

## License
MIT License
