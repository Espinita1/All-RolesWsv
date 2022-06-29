<#
.NOTES
    *****************************************************************************
    ETML
    Name:   Server-Install.ps1
    Author:	Jordy Guzman
    Date:	02.03.2022
 	*****************************************************************************
    Modifications
 	Date  : - 
	Author: - 
	Reason: - 
 	*****************************************************************************
.DESCRIPTION
    Script that installs a base server for p_appro project
.OUTPUTS
    Log output
.SYNOPSIS
    Following the module's course this script will get you through what is needed to
    install all the services under one machine

.SUMMARY
    Script installs AD, DHCP, DNS using an imported file from a previous
    configuration. Various parameters are needed to configure each one of
    these services

.PARAMETER NewComputerName
    - Enter your new DC Name
    
.PARAMETER NewIpAddress
    - Enter your new NewIPAddress

.PARAMETER DnsScopeName
    - Enter the DNS Scope Name for both direct and reverse zone

.PARAMETER DhcpScopeName
    - Enter the Dhcp Scope Name

.PARAMETER DhcpStartAddressPool
    - Enter the Dhcp start IP Address Pool

.PARAMETER DhcpEndAddressPool
    - Enter the Dhcp end IP Address Pool

.EXAMPLE
    -
#>


######################################################################## Get Parameters from the user ######################################################################
<#  #>
function Get-Params{
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
    
}

#This function gets the password by asking the user, retrieved as a secure string
<#                  Still need to revise the variables used for the main part, add the dhcp and dns creation part and everything else...    #>
function Get-Password {
    param (

    [Parameter(Mandatory = $true, HelpMessage="Enter a safe password for your AD" )]
    [Alias("p")]
    [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]$SafePassword
    )
    return $SafePassword
}

$fileJsonParams = Test-Path -Path "$PSScriptRoot\storedVars.json" -PathType Leaf

# Check if the json file with variables exists
if(!$fileJsonParams){
    
    Get-Params
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

    Write-Host "Variables set, now storing in " | Out-File log.txt -Append


    $storeJsonVars | ConvertTo-Json -Depth 1 | Out-File -Encoding UTF8 "storedVars.json" -Force

    #Write-Host "Stored variables in a json file in $PSScriptRoot, this file will be deleted after ending the script" | Out-File log.txt -Append
}

######################################################      Vars     ##################################################################

$DebugPreference = "Continue"                                                     #Adjust debug preference if an error is triggered

Write-Debug "Initializing vars"

"Initializing vars" | Out-File -FilePath .\log.txt -Append
$jsonFile = Get-Content "storedVars.json" | ConvertFrom-Json
$scriptDir = $PSScriptRoot                                                        #Current folder
$pcName = $env:COMPUTERNAME                                                       #Computer Name
$taskName = "exec_script_at_restart"                                              #Task Name
$fileXML = Get-Content .\imports\DeploymentConfigTemplate-dns-dhcp-create.xml     # Get the XML export file for DNS DHCP
$dirXML = Get-ChildItem .\imports\DeploymentConfigTemplate-dns-dhcp-create.xml    # Get the XML full path directory
$regexComputerName = '<S N="PSComputerName">\w*.{1}\w*<\/S>'                      # Regex to look for PSComputerName Attribute
$regexSvName = '<S N="ServerName">\w*.{1}\w*<\/S>'                                # Regex to look for ServerName Attribute
$domainExists = Get-ADDomain -Current LocalComputer                               #Get the current local computer domain
$diskSize = Get-Partition -DriveLetter C | Select-Object -ExpandProperty Size     #Get the disk that stores C: 
$DISKSTORAGEMIN = 40GB / 1                                                        #Convert 40GB into bytes
$diskNbr = Get-Disk | Select-Object -ExpandProperty Number                        #Get Disk Number
$desiredDiskSize = 20GB / 1                                                       #Convert 20GB into bytes
$xmlPath = $dirXML.FullName                                                       #Get XML full path name
$svName = $jsonFile.setComputerName                                               #Server Name to be changed in future updates
$newIpAddress = $jsonFile.setIpAddress                                            #Default Script IP address to be changed in future updates
$dnsScope = $jsonFile.setDnsScopeName                                             #Get the ddns scope from json file
$linePSComputerName = '<S N="PSComputerName">'+$svName+"</S>"                     # Replacement line for <PSComputer Name Attribute in XML file> to be changed in future updates
$lineSvName = '<S N="ServerName">'+$svName+"</S>"                                 # Replacement line for <Server Name Attribute in XML file> to be changed in future updates
$dnsZoneExists = Get-DnsServerZoneScope -ZoneName "$dnsScope"                     #Get this DNS Domain to be changed in future updates


#The disk size we want for the AD database is 20 GB that we'll get from the maximum space storage
$diskNewSize = $diskSize - $desiredDiskSize

##############################################################################################################################################################################

<#          
    This funciton can be modified for future purposes maybe, it can be reused for another script
    Still needs modifications if going to be used for another script
    Should be modified to accept the user that launched it, 
    concerning security if implemented right there should be no problem as for the task principal
    executing this script, only privileged users can start scripts but if in doubt create the adequate method to control this
#>
function ContinueAtRestart {
    if($pcName -cnotlike $svName)
    {   
        Rename-Computer $svName -Force -PassThru | Out-File -FilePath .\log.txt -Append
        $action = New-ScheduledTaskAction -Execute "Powershell.exe" -WorkingDirectory "$scriptDir" -Argument ".\server-install.ps1"
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "$pcName\administrator"
        $settings = New-ScheduledTaskSettingsSet
        $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings
        Register-ScheduledTask $taskName -InputObject $task
        Get-ScheduledTaskInfo -TaskName $taskName | Out-File -FilePath .\log.txt -Append
        Write-Debug "It is recommended to assign a gateway after the end of the script"
        Write-Debug "This script will continue at next logon"
        Start-Sleep -Seconds 5
        Restart-Computer
    }
}


#Get computer default ethernet net adapter and IP address
$netAdapter = Get-NetAdapter | Where-Object {$_.InterfaceAlias -eq 'Ethernet'}
$netIp = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -eq 'Ethernet'}
$ipAddress =  [string]$netIp.IPv4Address

if($ipAddress -ne $newIpAddress)
{
    #Modify Principal Net Adapter IP and DNS configuration
    Write-Debug "Changing IP Address to $newIpAddress"
    "Changing IP Address to $newIpAddress" | Out-File -FilePath .\log.txt -Append
    Remove-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $netAdapter.Name -Confirm:$false
    Remove-NetRoute -AddressFamily IPv4 -InterfaceAlias $netAdapter -Confirm:$false
    $netAdapter | New-NetIPAddress -IPAddress $newIpAddress -AddressFamily IPv4 -PrefixLength 24
    $_ | Out-File -FilePath .\log.txt -Append
    $netAdapter | Set-DnsClientServerAddress -ServerAddresses ("127.0.0.1")
    "$ipAddress and $newIpAddress" | Out-File -FilePath .\log.txt -Append
}

#Rename computer if the name isn't the script's default name
#Then create a scheduled task so it can continue the script after restarting at logon
Write-Debug "Changing computer name to $svName"
Write-Debug "Sheduling task to continue script after restart"

ContinueAtRestart()

#Register the task 
$taskIsRegistered = Get-ScheduledTask -TaskName $taskName

Write-Debug "Erasing scheduled task" | Out-File -FilePath .\log.txt -Append

#To later unregister it so it doesn't run each time at logon IF it already exists
if($taskIsRegistered)
{
    "Unregistering task" | Out-File -FilePath .\log.txt -Append 
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -PassThru
    "Resuming script" | Out-File -FilePath .\log.txt -Append
    Start-Sleep -Seconds 3
    #& $PSScriptRoot\Install-DHCP_DNS.ps1
}

#Try installing the dns if the DNS zone does not exist
Try{

    if(!($dnsZoneExists))
    {
        Write-Debug "Replacing Dns_Dhcp SN attributes in $xmlPath"
        "Replacing Dns_Dhcp SN attributes in $xmlPath" | Out-File -FilePath .\log.txt -Append 

        #Loop each line of the XML File then seek and replace the computer Name and server name attribute and finally make a copy of the modified content
        # and save it as an xml in the same folder
        $filexml | ForEach-Object{ 
        $_ -replace $regexComputerName, $linePSComputerName `
           -replace $regexSvName, $lineSvName } `
           | Set-Content .\imports\DeploymentConfig-dns-dchp.xml -Encoding UTF8 -Force

        "NS lines have been succesfully overwritten and replaced by the actual machine's name" | Out-File -FilePath .\log.txt -Append
        "Installing DHCP & DNS features" | Out-File -FilePath .\log.txt -Append

        Write-Debug "NS lines have been succesfully overwritten and replaced by the actual machine's name"
        Write-Debug "Installing DHCP & DNS features"

        #Install dhcp dns and AD services
        Install-WindowsFeature -ConfigurationFilePath .\imports\DeploymentConfig-dns-dchp.xml -ErrorAction Stop -Confirm:$false

        "`r`Copying DNS files... `r` " | Out-File -FilePath .\log.txt -Append

        #Copy necessary files for DNS creation, impartive to use the root dns folder
        Copy-Item .\imports\papprodns_local_dns -Destination "$env:windir\System32\dns" 
        Copy-Item .\imports\papprodns_local_dnsr -Destination "$env:windir\System32\dns" 

        "Importing dhcp configurations... `r` " | Out-File -FilePath .\log.txt -Append

        #Import dhcp config
        Import-DhcpServer -File .\imports\dhcpexport.xml -BackupPath "$env:TEMP" -Confirm:$false -Force

        "Adding primary dns zone..." | Out-File -FilePath .\log.txt -Append

        #Add primary DNS Zone
        Add-DnsServerPrimaryZone -Name pappro.local -ZoneFile papprodns_local_dns.dns -DynamicUpdate NonsecureAndSecure -PassThru -Confirm:$false

        "Addding reverse dns zone..." | Out-File -FilePath .\log.txt -Append

        #Add reverse DNS Zone
        Add-DnsServerPrimaryZone -NetworkId "10.10.110.0/24" -ZoneFile papprodns_local_dnsr.dns -PassThru -Confirm:$false

        "Adding server dns record A " | Out-File -FilePath .\log.txt -Append

        #Add DNS record A for local PC
        Add-DnsServerResourceRecordA -Name "PAPPRO-DC-1" -ZoneName "pappro.local" -AllowUpdateAny -IPv4Address "10.10.110.1"
    }
}Catch{
    $_ | Out-File .\log.txt -Append
    Write-Warning "Unexpected error: $_"
}

Write-Debug "Manually update A pointer in DNS after this step"
"Manually update A pointer for server in DNS after this step" | Out-File -FilePath .\log.txt -Append
Start-Sleep -Seconds 5


"Resizing disk (20GB for active directory)" | Out-File -FilePath .\log.txt -Append 

<#  Maybe add dynamic vars so the space can be modified from a minimum starting memory space
    1-DiskAllocation
#>
#If the disk size is over 40GB proceed, if not then skip and do nothing
#When proceeding, resize the disk to the new size then create a new partition in
#the unallocated size, format to NTFS and assign letter S to the new partition
#Last, create two folders that will contain AD Database
try{
    if($diskSize -gt $DISKSTORAGEMIN)
    {
        Resize-Partition -DriveLetter C -Size $diskNewSize -PassThru
        New-Partition -DiskNumber $diskNbr -Size $desiredDiskSize -DriveLetter S | Format-Volume -FileSystem NTFS -Confirm:$false
        New-Item -ItemType "directory" -Path "S:\SYSVOL"
        New-Item -ItemType "directory" -Path "S:\NTDS"
    }
}catch{
    $_ | Out-File .\log.txt -Append
    Write-Warning "Unexpected error $_"
}


"Installing Active Directory services" | Out-File -FilePath .\log.txt -Append 


<#  If there's not a domain present proceed to install Active directory #>
<#  Make this one dynamic params needed will be:
    1-DatabasePath
    2-DomainName
    3-DomanNetBiosName
    4-Sysvolpath (if specified)
#>
try {
    if(!($domainExists))
    {
        
        ContinueAtRestart
        #Default exported AD module when installing AD functions by GUI
        Import-Module ADDSDeployment
        Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -DatabasePath "S:\NTDS" `
        -DomainMode "WinThreshold" `
        -DomainName "pappro.local" `
        -DomainNetbiosName "PAPPRO" `
        -ForestMode "WinThreshold" `
        -InstallDns:$true `
        -LogPath "S:\NTDS" `
        -NoRebootOnCompletion:$false `
        -SysvolPath "S:\SYSVOL" `
        -Force:$true -ErrorAction Stop
    }
}catch{
    $errorMessage = $_ | Out-File 
    $errorMessage
}

Write-Debug "Continuing script from restart"
#Register the task 
$taskIsRegistered = Get-ScheduledTask -TaskName $taskName

Write-Debug "Erasing scheduled task" | Out-File -FilePath .\log.txt -Append
#To later unregister it so it doesn't run each time at logon IF it already exists
if($taskIsRegistered)
{
    "Unregistering task" | Out-File -FilePath .\log.txt -Append 
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -PassThru
    "Script has finished" | Out-File -FilePath .\log.txt -Append
}

Write-Debug "This script has finished"
Read-Host -Prompt "Script has finished press any key to exit..."

<#
             _,-._
        ; ___ :           ,------------------------------.
    ,--' (. .) '--.__    |   Yes this is a script        |
  _;      |||        \   |   Do what you want with it    |   
 '._,-----''';=.____,"   |                               |
   /// < o>   |##|       |   I didn't do this text art   |
   (o        \`--'       //`-----------------------------'
  ///\ >>>>  _\ <<<<    //
 --._>>>>>>>><<<<<<<<  / 
 ___() >>>[||||]<<<<
 `--'>>>>>>>><<<<<<<
      >>>>>>><<<<<<
        >>>>><<<<<
         >>ctr<<
#>