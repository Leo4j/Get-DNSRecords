function DNSRecords {
    param(
        [string]$searchBase,
        [string]$Domain
    )

    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($searchBase)
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)

    $directorySearcher.Filter = "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))"
    $directorySearcher.SearchScope = "Subtree"
    $directorySearcher.PageSize = 1000
    $directorySearcher.PropertiesToLoad.Add("dnsRecord") | Out-Null
    $directorySearcher.PropertiesToLoad.Add("DC") | Out-Null
	$directorySearcher.PropertiesToLoad.Add("name") | Out-Null

    $results = $directorySearcher.FindAll()
    foreach ($result in $results) {
        $dnsRecords = $result.Properties["dnsRecord"]
        $hostname = $null
        if ($result.Properties["DC"] -and $result.Properties["DC"].Count -gt 0) {
            $hostname = $result.Properties["DC"][0]
        } elseif ($result.Properties["name"] -and $result.Properties["name"].Count -gt 0) {
            $hostname = $result.Properties["name"][0]
        }

        if ($dnsRecords) {
            $ips = @()

            foreach ($record in $dnsRecords) {
                $ip = Convert-DnsRecordToIP -recordBytes $record
                if ($ip) { $ips += $ip }
            }

            if ($ips.Count -gt 0) {
                [PSCustomObject]@{
                    Hostname = if ($hostname -eq "@") { "$Domain" } else { $hostname }
                    "IP Address" = ($ips -join ", ")
                    Domain = $Domain
                }
            }
        }
    }
}

function Convert-DnsRecordToIP {
    param(
        [byte[]]$recordBytes
    )

    if ($recordBytes[2] -eq 1) { # Type A record
        return "$($recordBytes[24]).$($recordBytes[25]).$($recordBytes[26]).$($recordBytes[27])"
    }

    return $null
}

function PopulateHosts {

	param(
		[Parameter(Mandatory=$true)]
		[Object[]]$Entries
	)

	if(!$Silent){Write-Output "[*] Populating Hosts file..."}

	$hostsPath    = "$env:SystemRoot\System32\drivers\etc\hosts"
	$currentHosts = Get-Content $hostsPath -ErrorAction SilentlyContinue | ForEach-Object { $_.ToLower() }
	$entriesToAdd = @()

	# Get domain root IPs (formerly "@")
	$domainEntry = $AllDNSEntries | Where-Object { $_.Hostname -eq $Domain }
	$domainIPs = @()
	if ($domainEntry) {
		$domainIPs = $domainEntry.'IP Address' -split ',\s*'
	}

	foreach ($entry in $AllDNSEntries) {
		$hostname = $entry.Hostname.ToLower()

		# Skip domain root and DNS infrastructure entries
		if ($hostname -eq $Domain.ToLower() -or $hostname -in @('domaindnszones', 'forestdnszones')) {
			continue
		}

		$domain   = $entry.Domain.ToLower()
		$fqdn     = "$hostname.$domain"
		$ips      = $entry.'IP Address' -split ',\s*'

		# Check if the FQDN already exists in hosts
		$pattern = "(^|\s)$fqdn($|\s)"
		$exists  = $currentHosts | Where-Object { $_ -match $pattern }

		if (-not $exists -and $ips.Count -gt 0) {
			# Sort IPs by closeness to domain IPs
			$sortedIps = $ips | Sort-Object {
				$ip = $_
				$maxMatch = 0
				foreach ($domIp in $domainIPs) {
					$ipBytes  = $ip -split '\.' | ForEach-Object { [int]$_ }
					$domBytes = $domIp -split '\.' | ForEach-Object { [int]$_ }
					$match = 0
					for ($i = 0; $i -lt 4; $i++) {
						if ($ipBytes[$i] -eq $domBytes[$i]) { $match++ } else { break }
					}
					if ($match -gt $maxMatch) { $maxMatch = $match }
				}
				return -$maxMatch
			}

			foreach ($ip in $sortedIps) {
				$line = "$ip`t$fqdn`t# Added by Get-DNSRecords"
				$entriesToAdd += $line
			}
		}
	}

	if ($entriesToAdd.Count -gt 0) {
		Add-Content -Path $hostsPath -Value "`n"
		foreach ($line in $entriesToAdd) {
			Add-Content -Path $hostsPath -Value $line
		}
	}
}

function Get-DNSRecords {
    param(
		[string]$Domain,
        [string]$Server,
		[switch]$PopulateHosts,
		[switch]$Silent
    )
	
	if($Silent){
		$ErrorActionPreference = "SilentlyContinue"
		$WarningPreference = "SilentlyContinue"
	}
	
	if(!$Domain){
		$Domain = try{[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()}catch{}
		if(!$Domain){$Domain = try{[System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}catch{}}
		if(!$Domain){$Domain = $env:USERDNSDOMAIN}
		if(!$Domain){$Domain = try{Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}catch{}}
		if(!$Domain){
			if(!$Silent){
				Write-Host "[!] Please specify a target domain and server" -ForegroundColor Red
				Write-Host ""
			}
			break
		}
	}
	
	if(!$Server){
		$currentDomain = try{[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)))}catch{}
		if($currentDomain){
			$domainControllers = $currentDomain.DomainControllers
			$Server = ($domainControllers | Where-Object {$_.Roles -like "*RidRole*"}).name
		}
		
		if(!$Server){
			$result = try{nslookup -type=all "_ldap._tcp.dc._msdcs.$Domain" 2>$null}catch{}
			if($result){$Server = try{($result | Where-Object { $_ -like '*svr hostname*' } | Select-Object -First 1).Split('=')[-1].Trim()}catch{}}
		}
	}

    $domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
    
	$prefix = if ($Domain -and $Server) { "LDAP://$Server/" } else { "LDAP://" }

    $searchBases = @(
        "${prefix}DC=DomainDnsZones,$domainDN",
        "${prefix}CN=MicrosoftDNS,CN=System,$domainDN"
    )
	
	$AllDNSEntries = @()

    foreach ($sb in $searchBases) {
        $AllDNSEntries += DNSRecords -searchBase $sb -Domain $Domain
    }
	
	if(!$Silent){$AllDNSEntries | ft -Autosize}
	
	if ($PopulateHosts) {
	
		$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	
		if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
			PopulateHosts -Entries $AllDNSEntries
		}
		
		else{
			if(!$Silent){
				Write-Host "[!] To populate the Host file you need to run from an elevated prompt" -ForegroundColor Red
				Write-Host ""
			}
		}
	}
}
