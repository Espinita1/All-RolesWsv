<#
.NOTES
    *****************************************************************************
	ETML
	Name: 	parassssss.ps1
    Author:	
    Date:	
 	*****************************************************************************
    Modifications
 	Date  : -
 	Author: -
 	Reason: -
 	*****************************************************************************
.SYNOPSIS
    
 	
.SUMMARY
    - aa
  	
.PARAMETER NewComputerName
    -NewComputerName
 	
.EXAMPLE
    -
 	
.LINK
    https://enseignement.section-inf.ch/moduleICT/122/Index.html
#>

Param (
    #Set Domain Controller Computer Name
    [Parameter(Mandatory = $true, HelpMessage="Enter a name for your DC" )]
    [Alias("pcn")]
    [ValidateNotNullOrEmpty()]
    [string]$NewComputerName,

    #Set IP address for your Domainc Controller
    [Parameter(Mandatory = $true, HelpMessage="Enter an IP address for your DC" )]
    [Alias("ip")]
    [ValidateNotNullOrEmpty()]
    [string]$NewIpAddress,

    #Set the direct DNS scope Name
    [Parameter(Mandatory = $true, HelpMessage="Enter a DNS scope name" )]
    [Alias("dnssn")]
    [ValidateNotNullOrEmpty()]
    [string]$DnsScopeName, 

    #Set the DHCP scope Name
    [Parameter(Mandatory = $true, HelpMessage="Enter a DHCP scope name" )]
    [Alias("dhcpsn")]
    [ValidateNotNullOrEmpty()]
    [string]$DhcpScopeName,

    #Set the dhcp start address IP
    [Parameter(Mandatory = $true, HelpMessage="Enter the needed DHCP address start pool for scope" )]
    [Alias("dhcpstap")]
    [ValidateNotNullOrEmpty()]
    [string[]]$DhcpStartAddressPool,

    #Set the DHCP end address IP
    [Parameter(Mandatory = $true, HelpMessage="Enter the needed DHCP address end pool for scope" )]
    [Alias("dhcpendap")]
    [ValidateNotNullOrEmpty()]
    [string[]]$DhcpEndAddressPool
    
    )

function Get-Password {
    param (
            #Set a password for the AD safe password
    [Parameter(Mandatory = $true, HelpMessage="Enter a safe password for your AD" )]
    [Alias("p")]
    [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]$SafePassword
    )
    return $SafePassword
}

$fileJsonParams = Test-Path -Path "$PSScriptRoot\storedVars.json" -PathType Leaf

if(!$fileJsonParams){

    Write-Host "Json file storing vars doesn't exist, first run to set and store variables"
    
    $PwdGet = Get-Password
    $EncryptedPassword = ConvertFrom-SecureString -SecureString $PwdGet

    $storeJsonVars = @{
        "setComputerName"= $NewComputerName;
        "setIpAddress"= $NewIpAddress;
        "setPWD"= $EncryptedPassword;
        "setDnsScopeName"= $DnsScopeName;
        "setDhcpScopeName"= $DhcpScopeName;
        "setDhcpStartPool"= $DhcpStartAddressPool;
        "setDhcpEndPool"= $DhcpEndAddressPool;
    }

    #Write-Host "Variables set" | Out-File log.txt -Append


    $storeJsonVars | ConvertTo-Json -Depth 1 | Out-File -Encoding UTF8 "storedVars.json" -Force

    #Write-Host "Stored variables in a json file in $PSScriptRoot, this file will be deleted after ending the script" | Out-File log.txt -Append
}

