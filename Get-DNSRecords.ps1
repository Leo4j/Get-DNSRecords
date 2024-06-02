function Convert-DnsRecordToIP {
    param(
        [byte[]]$recordBytes
    )

    if ($recordBytes[2] -eq 1) { # Type A record
        $ip = "$($recordBytes[24]).$($recordBytes[25]).$($recordBytes[26]).$($recordBytes[27])"
        return $ip
    }

    return $null
}

function DNSRecords {
    param(
        [string]$searchBase
    )

    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($searchBase)
    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)

    $directorySearcher.Filter = "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))"

    $directorySearcher.SearchScope = "Subtree"
    $directorySearcher.PageSize = 1000
    $directorySearcher.PropertiesToLoad.Add("dnsRecord") | Out-Null
    $directorySearcher.PropertiesToLoad.Add("DC") | Out-Null

    try {
        $results = $directorySearcher.FindAll()
        foreach ($result in $results) {
            $dnsRecord = $result.Properties["dnsRecord"][0]
            $hostname = $result.Properties["DC"][0]

            if ($dnsRecord) {
                $ipAddress = Convert-DnsRecordToIP $dnsRecord
                # Only output if an IP address was successfully converted
                if ($ipAddress) {
                    [PSCustomObject]@{
                        Hostname = $hostname
                        "IP Address" = $ipAddress
                    }
                }
            }
        }
    } catch {
        Write-Warning "Failed to query or process DNS records: $_"
    }
}

function Get-DNSRecords {
    param(
        [string]$Domain,
        [string]$Mode
    )
    
    if($Domain){
        # Convert the domain into LDAP path format
        $domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
        $domainDNSZonesDN = "LDAP://DC=DomainDnsZones,$domainDN"
        $forestDNSZonesDN = "LDAP://DC=ForestDnsZones,$domainDN"

        if($Mode -eq "Domain"){
            Write-Host "Searching in Domain DNS Zones for $Domain..."
            DNSRecords -searchBase $domainDNSZonesDN | Sort-Object Hostname | Format-Table
        }

        elseif($Mode -eq "Forest"){
            Write-Host "Searching in Forest DNS Zones for $Domain..."
            DNSRecords -searchBase $forestDNSZonesDN | Sort-Object Hostname | Format-Table
        }

        else{
            Write-Host "Searching in Domain DNS Zones for $Domain..."
            DNSRecords -searchBase $domainDNSZonesDN | Sort-Object Hostname | Format-Table

            Write-Host "Searching in Forest DNS Zones for $Domain..."
            DNSRecords -searchBase $forestDNSZonesDN | Sort-Object Hostname | Format-Table
        }
    }
    
    else{
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $domainDN = $rootDSE.Properties["defaultNamingContext"].Value
        $forestDN = $rootDSE.Properties["rootDomainNamingContext"].Value

        $domainDNSZonesDN = "LDAP://DC=DomainDnsZones,$domainDN"
        $forestDNSZonesDN = "LDAP://DC=ForestDnsZones,$forestDN"
        
        if($Mode -eq "Domain"){
            DNSRecords -searchBase $domainDNSZonesDN | Sort-Object Hostname | ft
        }
        
        elseif($Mode -eq "Forest"){
            DNSRecords -searchBase $forestDNSZonesDN | Sort-Object Hostname | ft
        }
        
        else{
            Write-Host "Searching in Domain DNS Zones..."
            DNSRecords -searchBase $domainDNSZonesDN | Sort-Object Hostname | ft

            Write-Host "Searching in Forest DNS Zones..."
            DNSRecords -searchBase $forestDNSZonesDN | Sort-Object Hostname | ft
        }
    }
}
