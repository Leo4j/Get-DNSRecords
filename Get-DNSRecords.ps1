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

function FindDomainTrusts {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false)]
        [string]$Server
    )

    # Define the TrustAttributes mapping
    $TrustAttributesMapping = @{
        [uint32]'0x00000001' = 'NON_TRANSITIVE'
        [uint32]'0x00000002' = 'UPLEVEL_ONLY'
        [uint32]'0x00000004' = 'FILTER_SIDS'
        [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
        [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
        [uint32]'0x00000020' = 'WITHIN_FOREST'
        [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
        [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
        [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
        [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
        [uint32]'0x00000400' = 'PIM_TRUST'
    }

    try {
        # Construct the LDAP path and create the DirectorySearcher
        $ldapPath = if ($Server) { "LDAP://$Server/DC=$($Domain -replace '\.',',DC=')" } else { "LDAP://DC=$($Domain -replace '\.',',DC=')" }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $searcher.Filter = "(objectClass=trustedDomain)"
        $searcher.PropertiesToLoad.AddRange(@("name", "trustPartner", "trustDirection", "trustType", "trustAttributes", "whenCreated", "whenChanged"))
        
        # Execute the search
        $results = $searcher.FindAll()

        # Enumerate the results
        foreach ($result in $results) {
            # Resolve the trust direction
            $Direction = Switch ($result.Properties["trustdirection"][0]) {
                0 { 'Disabled' }
                1 { 'Inbound' }
                2 { 'Outbound' }
                3 { 'Bidirectional' }
            }

            # Resolve the trust type
            $TrustType = Switch ($result.Properties["trusttype"][0]) {
                1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                3 { 'MIT' }
            }

            # Resolve the trust attributes
            $TrustAttributes = @()
            foreach ($key in $TrustAttributesMapping.Keys) {
                if ($result.Properties["trustattributes"][0] -band $key) {
                    $TrustAttributes += $TrustAttributesMapping[$key]
                }
            }

            # Create and output the custom object
            $trustInfo = New-Object PSObject -Property @{
                SourceName      = $Domain
                TargetName      = $result.Properties["trustPartner"][0]
                TrustDirection  = $Direction
                TrustType       = $TrustType
                TrustAttributes = ($TrustAttributes -join ', ')
                WhenCreated     = $result.Properties["whenCreated"][0]
                WhenChanged     = $result.Properties["whenChanged"][0]
            }

            $trustInfo
        }
    }
    catch {
        Write-Error "An error occurred: $_"
    }
    finally {
        $searcher.Dispose()
        if ($results) { $results.Dispose() }
    }
}

function FindAllDomains{
	$FindCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	if(!$FindCurrentDomain){$FindCurrentDomain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName.Trim()}
	if(!$FindCurrentDomain){$FindCurrentDomain = $env:USERDNSDOMAIN}
	if(!$FindCurrentDomain){$FindCurrentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
		
	$ParentDomain = ($FindCurrentDomain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name)
	$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $ParentDomain)
	$ChildContext = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
	$ChildDomains = @($ChildContext | Select-Object -ExpandProperty Children | Select-Object -ExpandProperty Name)
		
	$AllDomains = @($ParentDomain)
		
	if($ChildDomains){
		foreach($ChildDomain in $ChildDomains){
			$AllDomains += $ChildDomain
		}
	}
		
	# Trust Domains (save to variable)
		
	$TrustTargetNames = @(foreach($AllDomain in $AllDomains){(FindDomainTrusts -Domain $AllDomain).TargetName})
	$TrustTargetNames = $TrustTargetNames | Sort-Object -Unique
	$TrustTargetNames = $TrustTargetNames | Where-Object { $_ -notin $AllDomains }
		
	foreach($TrustTargetName in $TrustTargetNames){
		$AllDomains += $TrustTargetName
	}
		
	$AllDomains = $AllDomains | Sort-Object -Unique
	
	$AllDomains
}

function Get-DNSRecords {
    param(
        [string]$Domain,
        [string]$Mode
    )

	$AllDomains = FindAllDomains
		
	Write-Host ""
	Write-Host "Domain Controllers:"
	$FinalDCs = @()
	$FinalDCs = foreach ($DM in $AllDomains) {
	    $result = nslookup -type=all "_ldap._tcp.dc._msdcs.$DM" 2>$null
	    if ($result) {
		$DomainControllers = @($result | Where-Object { $_ -like '*svr hostname*' } | ForEach-Object { $_.Split('=')[-1].Trim() })
		
		foreach ($dc in $DomainControllers) {
		    $dcIP = ($result | Where-Object { $_ -like "*$dc*" -AND $_ -like "*internet address*" } | Select-Object -First 1).Split('=')[-1].Trim()
		    $dcname = $dc -replace "\.$DM","$"
		    if ($dcIP) {
			[PSCustomObject]@{
				Name   = $dcname
				IP     = $dcIP
				Domain = $DM
			}
		    } else {
			[PSCustomObject]@{
			    Name   = $dcname
			    IP     = "Not found"
			    Domain = $DM
			}
		    }
		}
	    } else {
		Write-Host "No result for domain: $DM"
	    }
	}
	
	$FinalDCs | Sort-Object Domain,Name | ft -Autosize
    
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
