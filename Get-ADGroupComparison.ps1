function Get-ADGroupComparison {
    [CmdletBinding()]
    param (
        [Parameter(mandatory=$true)]$DomainA,
        [Parameter(mandatory=$true)]$GroupA,
        [Parameter(mandatory=$true)]$GroupB,
        [Parameter(mandatory=$true)]$Attribute,
        $DomainB
    )
    
    begin {
        # Get Start Time
        $utc = (get-date).ToUniversalTime()
        $StartTime = get-date $utc -format "yyyy-MM-ddTHHmmssK" # K is utc offset (Z)
        # Find a domain controller to query for each domain
        $DomainServerA = Get-ADDomainController -DomainName $DomainA -Discover -NextClosestSite | Select-Object -ExpandProperty HostName
        if (-not $DomainB) {
            Write-Verbose "`$DomainB not provided. Using $DomainA"
            $DomainServerB = $DomainServerA
        } else {
            $DomainServerB = Get-ADDomainController -DomainName $DomainB -Discover -NextClosestSite | Select-Object -ExpandProperty HostName
        }
    }
    
    process {
        # helper function to create a script block, query active directory group membership and sort
        function Get-ADGroupMemberCustom ($DomainServer, $GroupName) {
            $FilterScriptblock = [System.Management.Automation.ScriptBlock]::Create("Name -eq `"$GroupName`"")
            $GroupMembers = Get-ADGroup -Server $DomainServer -Filter $FilterScriptblock | Get-ADGroupMember | Sort-Object Name
            return $GroupMembers
        }
        $MembersA = Get-ADGroupMemberCustom -DomainServer $DomainServerA -GroupName $GroupA
        $MembersB = Get-ADGroupMemberCustom -DomainServer $DomainServerB -GroupName $GroupB
        $Report = [System.Collections.ArrayList]@()

        # Merge objects from group A and group B together based upon user object attributed used as a hashtable key
        $UniqueAttribute = ($MembersA.$Attribute + $MembersB.$Attribute) | Sort-Object | Get-Unique

        # Convert each Microsoft.ActiveDirectory.Management.ADPrincipal list to hashtable for fast lookup
        $hashA = @{}
        $hashB = @{}
        $MembersA | ForEach-Object {
            $hashA[$_.$Attribute] = $_
        }
        $MembersB | ForEach-Object {
            $hashB[$_.$Attribute] = $_
        }

        # loop through each unique account name to determine if account is in group a, group b or both.
        foreach ($Attribute in $UniqueAttribute) {
            $record = [PSCustomObject]@{
                Attribute = $Attribute
                Name = 'NA'
                $GroupA = $false
                $GroupB = $false
            }

            # if the attribute value exists in group A, this is true
            if ($hashA.ContainsKey($Attribute)) {
                $record.$GroupA = $true
                if ($record.name -eq 'NA') { # add user name if NA
                    $record.name = $hashA[$Attribute].name
                }
            }

            # if the attribute value exists in group B, this is true
            if ($hashB.ContainsKey($Attribute)) {
                $record.$GroupB = $true
                if ($record.name -eq 'NA') { # add user name if NA
                    $record.name = $hashB[$Attribute].name
                }
            }
            $Report.Add($record) | Out-Null # Add merged record to an arraylist
        }
        $Report | ForEach-Object { Export-Csv -Path "${GroupA}_${GroupB}_${StartTime}.csv" -InputObject $_ -Encoding UTF8 -Append -NoTypeInformation } # export merged group to csv
        return $report # return object for additional processing
    }
}
$DomainA = 'mydomain.com'
$GroupA = 'MyGroupA'
$GroupB = 'MyGroupB'
$report = Get-ADGroupComparison -DomainA $DomainA -GroupA $GroupA -GroupB $GroupB -Attribute 'SamAccountName'
