# Get-DNSRecords
The script queries DNS records from the Active Directory domain, specifically from the DNS zones.

### Usage
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Get-DNSRecords/main/Get-DNSRecords.ps1')
```
```
Get-DNSRecords -Domain ferrari.local -Server dc01.ferrari.local
```
<img width="1937" height="439" alt="image" src="https://github.com/user-attachments/assets/bcd51867-2381-47a8-8603-9ae07380859d" />

### Populate the Hosts file (Requires running as admin)

The `-PopulateHosts` flag will populates the hosts file for you

```
Get-DNSRecords -Domain ferrari.local -Server dc01.ferrari.local -PopulateHosts
```

