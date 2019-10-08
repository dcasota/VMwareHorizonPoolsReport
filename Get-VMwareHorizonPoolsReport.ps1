$outputdir="C:\ProgramData\my"
$Identifier="inserthere"
$hzConn="podb-con-in-1"
$hzPools="podb-con-in-1\PoolA1B=poda-con-in-1\PoolA1A;podb-con-in-1\PoolB1B=poda-con-in-1\PoolB1A;podb-con-in-1\Pool-Dbet"
$hzDomain="domain"
$hzUser="serviceadmin@domain.local"
$hzUserName="serviceadmin"
$hzPassword="Secure123!"
$delimiterStructure="\"
$delimiterList=";"
$delimiterIntegrity="="
$delimiterCheckSum="#"
function my.Find-Module {
# https://stackoverflow.com/questions/37486587/powershell-v5-how-to-install-modules-to-a-computer-having-no-internet-connecti
# Find-Module psreadline | Save-Module -Path c:\users\frode\Desktop
# https://github.com/PowerShell/PowerShellGet/issues/171
    param($Name,$proxy)
    if (($proxy -eq "") -or ($proxy -eq $null)){ invoke-restmethod "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$name' and IsLatestVersion" | 
    select-Object @{n='Name';ex={$_.title.'#text'}},
                  @{n='Version';ex={$_.properties.version}},
                  @{n='Uri';ex={$_.Content.src}}
   }
   else
   {
    invoke-restmethod "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$name' and IsLatestVersion" -proxy $proxy -ProxyUseDefaultCredentials| 
    select-Object @{n='Name';ex={$_.title.'#text'}},
                  @{n='Version';ex={$_.properties.version}},
                  @{n='Uri';ex={$_.Content.src}}    
   }
}

function my.Find-ModuleAllVersions {
# https://stackoverflow.com/questions/37486587/powershell-v5-how-to-install-modules-to-a-computer-having-no-internet-connecti
# Find-Module psreadline | Save-Module -Path c:\users\frode\Desktop
# https://github.com/PowerShell/PowerShellGet/issues/171
    param($Name,$proxy)
    if (($proxy -eq "") -or ($proxy -eq $null)){ invoke-restmethod "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$name'" | 
    select-Object @{n='Name';ex={$_.title.'#text'}},
                  @{n='Version';ex={$_.properties.version}},
                  @{n='Uri';ex={$_.Content.src}}
   }
   else
   {
    invoke-restmethod "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$name'" -proxy $proxy -ProxyUseDefaultCredentials| 
    select-Object @{n='Name';ex={$_.title.'#text'}},
                  @{n='Version';ex={$_.properties.version}},
                  @{n='Uri';ex={$_.Content.src}}    
   }
}

function my.Save-Module
{
    param(
        [Parameter(ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
        $Name,
        [Parameter(ValueFromPipelineByPropertyName=$true,Mandatory=$true)]$Uri,
        [Parameter(ValueFromPipelineByPropertyName=$true)]$Version="",
        [string]$Path = $pwd,
        [Parameter(ValueFromPipelineByPropertyName=$true,Mandatory=$false)]$proxy
    )
    $Path = (Join-Path $Path "$Name.$Version.nupkg")
    if ((get-command -name invoke-webrequest) -ne $null)
    {
        if (($proxy -eq "") -or ($proxy -eq $null)) {Invoke-WebRequest $Uri -OutFile $Path}
        else {Invoke-WebRequest $Uri -OutFile $Path -proxy $proxy -ProxyUseDefaultCredentials}
    }
    else
    {
        $webclient = new-object system.net.webclient
        $webclient.downloadfile($Uri,$Path)
    }
    $rc = Get-Item $Path
    return $rc
}

Function Get-OSVersion() { 
    # http://itnotesandscribblings.blogspot.ch/2014/06/powershell-os-detection.html
    # Version numbers as per http://www.gaijin.at/en/lstwinver.php
    $osVersion = "Version not listed"
    $os = (Get-WmiObject -class Win32_OperatingSystem)
    Switch (($os.Version).Substring(0,3)) { 
        "5.1" { $osVersion = "5.1" }
        "5.2" { $osVersion = "5.2" }
        "6.0" { If ($os.ProductType -eq 1) { $osVersion = "6" } Else { $osVersion = "2008" } }
        "6.1" { If ($os.ProductType -eq 1) { $osVersion = "6.1" } Else { $osVersion = "2008R2" } }
        "6.2" { If ($os.ProductType -eq 1) { $osVersion = "8" } Else { $osVersion = "2012" } } # 8.1/2012R2 version detection can be broken, and show up as "6.2", as per http://www.sapien.com/blog/2014/04/02/microsoft-windows-8-1-breaks-version-api/
        "6.3" { If ($os.ProductType -eq 1) { $osVersion = "8.1" } Else { $osVersion = "2012R2" } }
        "10." { $osversion = "10" }
    }
    return [string]$osVersion
}

Function Get-CurrentProcessBitness
{
    # This function finds the bitness of the powershell.exe process itself (ie can detect 32-bit powershell.exe on a win64)
    $thisProcessBitness = 0
    switch ([IntPtr]::Size) {
       "4" { $thisProcessBitness = 32 }
       "8" { $thisProcessBitness = 64 }
    }
    return $thisProcessBitness
}

Function Get-OSBitness
{
    # This function finds the bitness of the OS itself (ie will detect 64-bit even if you're somehow using 32-bit powershell.exe)
    $OSBitness = 0
    switch ((Get-WmiObject Win32_OperatingSystem).OSArchitecture) {
        "32-bit" { $OSBitness = 32 }
        "64-bit" { $OSBitness = 64 }
    }
    return $OSBitness
}

function my.SaveWMF51
{
    $osversion=get-osversion
    switch ($osversion) {
        "2012" {
                    $VendorRsrcPkgFileName="W2K12-KB3191565-x64.msu"
                    $Uri="https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/W2K12-KB3191565-x64.msu"
                    
                 }
        "7"      {
                    # TODO Check if .net 4.5.2
                    # https://docs.microsoft.com/en-us/powershell/wmf/5.1/install-configure
                    if ((get-OSBitness) -eq "32")
                    {
                        # win7-kb3134760-x86
                        $VendorRsrcPkgFileName="Win7-KB3191566-x86.zip"
                        $Uri="https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7-KB3191566-x86.zip"
                    }
                    else
                    {
                        # win7Andw2k8r2-kb3134760-x64
                        $VendorRsrcPkgFileName="Win7AndW2K8R2-KB3191566-x64.zip"
                        $Uri="https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip"     
                    }
                }
        "2008R2"{
                        # TODO Check if .net 4.5.2
                        # https://docs.microsoft.com/en-us/powershell/wmf/5.1/install-configure
                        # win7Andw2k8r2-kb3134760-x64
                        $VendorRsrcPkgFileName="Win7AndW2K8R2-KB3191566-x64.zip"
                        $Uri="https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip"     
                }
        "8.1"   {
                    if ((Get-OSBitness) -eq "32")
                    {
                        # Win8.1-kb3134758-x86
                        $VendorRsrcPkgFileName="Win8.1-KB3191564-x86.msu"
                        $Uri="https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1-KB3191564-x86.msu"
                    }
                    else
                    {
                        # win8.1Andw2k12r2-kb3134758-x64
                        $VendorRsrcPkgFileName="Win8.1AndW2K12R2-KB3191564-x64.msu"
                        $Uri="https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu"
                    }
                }
        "2012R2"{
                        # win8.1Andw2k12r2-kb3134758-x64
                        $VendorRsrcPkgFileName="Win8.1AndW2K12R2-KB3191564-x64.msu"
                        $Uri="https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu"
                }
    }
    $CacheRepository = "$env:temp"
    $targetfile = join-path $CacheRepository $VendorRsrcPkgFileName
    write-host $targetfile

	if (!(Test-Path $targetfile))
	{
	    if (!(Test-Path $CacheRepository)) {mkdir -path $CacheRepository}
	    Invoke-WebRequest $Uri -OutFile $targetfile
    	}
   	$sb={
	    $arglist=$targetfile,'/quiet','/norestart'
     	    Start-Process -FilePath 'c:\windows\system32\wusa.exe' -ArgumentList $arglist -NoNewWindow -Wait
	    }
	Invoke-Command -ScriptBlock $sb
}

function my.Choco
{
    Set-ExecutionPolicy unrestricted -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

function Install-NugetPkg($filename,$sourcepath,$destination){
    $PackageName = ([System.IO.Path]::GetFileNameWithoutExtension($filename))
    $NewFileName = $PackageName +".zip"
    $SourceFile = $sourcepath + "\" + $NewFileName

    if (test-path ($SourceFile)) {remove-item -path ($SourceFile) -force}
    dir ($sourcepath + "\" + $filename)| rename-item -newname {$_.name -replace ".nupkg",".zip"}
    [io.path]::changeextension($sourcefile,'.zip')

    [string]$destinationspace=$destination + "\" + ([System.IO.Path]::GetFileNameWithoutExtension($filename))
    if (test-path $destinationspace) {remove-item -path ($destinationspace) -force -recurse -confirm:$false}
    new-item -itemtype directory -force -path $destinationspace

    $destinationfile=$destination + "\" + $NewFileName
    $shell = new-object -comobject shell.application
    $tmpzip = $shell.namespace($sourcefile)
    foreach ($item in $tmpzip.items())
    {
        $vOptions = 16+512+1024
        $shell.namespace($destinationspace).copyhere($item),$vOptions #TODO
    }
    remove-item -path ($sourcefile) -force -recurse -confirm:$false
    $destinationspaceFile=$destinationspace + "\" + "*.psd1"
    dir $destinationspaceFile | %{
        $TmpFile = $destinationspace + "\" + $_.Name
        import-module -name $TmpFile -Verbose -force -scope global -erroraction silentlycontinue
    }
    return ($destinationspace)
}

function PowerCLIPrerequisites()
{
	$returncode= $false
    write-host "Check powershellget ..." #needed for different commands
    if ((-not (get-module -name powershellget -listavailable -ErrorAction SilentlyContinue)) -and (-not (get-module -name powershellget)))
    { 
        write-host "Installing powershellget ..."
        # https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module
        my.SaveWMF51
        $rc = my.Find-Module packagemanagement | my.Save-Module -Path $pshome\modules
        Install-NugetPkg $rc.name "$pshome\modules" "$pshome\modules"
        $rc = my.Find-Module powershellget | my.Save-Module -Path $pshome\modules
        Install-NugetPkg $rc.name "$pshome\modules" "$pshome\modules"
    }

    write-host "Check VMware modules ..."	
	if (((get-Module -Name VMware.VimAutomation.Common -listavailable) -eq $null) -or ((get-module -name VMware.Vimautomation.Horizonview -ListAvailable) -eq $null) -or ((get-module -name VMware.PowerCLI -Listavailable) -eq $null))
    {
        write-host "Check VMware Components incompatible with PowerCLI 6.5.x ..."	
	    $installed = Get-WmiObject -Class Win32_Product -Filter "name like '%VMware%'"
	    $PowerCLI = $installed | ? Name -eq 'VMware vSphere PowerCLI' | Select-Object -ExpandProperty IdentifyingNumber -First 1
	    $VMRC = $installed | ? Name -eq 'VMware Remote Console' | Select-Object -ExpandProperty IdentifyingNumber -First 1
	    $VIX = $installed | ? Name -eq 'VMware VIX' | Select-Object -ExpandProperty IdentifyingNumber -First 1
	    if ($PowerCLI)
	    {
		    write-host "[Uninstall PowerCLI]"
		    Start-Process -FilePath MsiExec.exe -ArgumentList "/uninstall $PowerCLI /qb!" -Wait
	    }
	    if ($VMRC)
	    {	
		    write-host "[Uninstall VMware Remote Console]"
		    Start-Process -FilePath MsiExec.exe -ArgumentList "/uninstall $VMRC /qb!" -Wait
	    }
	    if ($VIX)
	    {
		    write-host "[Uninstall VMware VIX]"
		    Start-Process -FilePath MsiExec.exe -ArgumentList "/uninstall $VIX /qb!" -Wait
        }

		write-host "Save VMware modules to $pshome\modules ..."
		# https://blogs.vmware.com/PowerCLI/2017/08/updating-powercli-powershell-gallery.html
		# http://www.unvalidatedtech.com/2017/06/14/vmware-powercli-6-5-2-upgrade-issue/    
		Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208 -Force -Confirm:$false -Scope AllUsers
        # https://richardspowershellblog.wordpress.com/2016/09/18/unregistering-the-default-repository-ps-version-dependent/
        # Register-PSRepository -Name PSGallery -SourceLocation "https://www.powershellgallery.com/api/v2/" -InstallationPolicy Trusted -Default
        if ((Get-PSRepository -name psgallery | %{ $_.InstallationPolicy -match "Untrusted" }) -eq $true) { set-psrepository -name PSGallery -InstallationPolicy Trusted }


        find-module -name VMware.PowerCLI -Repository PSGallery -requiredversion 6.5.4.7155375 -IncludeDependencies|install-module -force -confirm:$false

        if (get-command -name Set-PowerCLIConfiguration -ErrorAction SilentlyContinue) {
            Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false
        }


	    if ((get-Module -Name "VMware.VimAutomation.Common" -listavailable) -and (get-module -name vmware.vimautomation.horizonview -ListAvailable) -and (get-module -name vmware.PowerCLI -Listavailable)) {$returncode=$true}
   }
   else {$returncode = $true}

   $value = 0
   if ($returncode -eq $false) {$value=1}
   return ($value)
}

function Get-Hz7Report
{
param(
  [parameter(Mandatory=$true)]
  [string] $ConnectionServer,
  [parameter(Mandatory=$true)]
  [string] $username,
  [parameter(Mandatory=$true)]
  [string] $domain,
  [parameter(Mandatory=$true)]
  [string] $password
)
    #check First Horizon 7++ PowerCLI Connectivity
    if ((get-module -name VMware.VimAutomation.HorizonView -ListAvailable) -ne $null)
	{
		# Import the Horizon module
		try
		{
		   Import-Module VMware.VimAutomation.HorizonView
		}
		catch{}
		
		# Establish connection to Connection Server
        $fqdn=""
        if ($ConnectionServer -like '*.*') {$fqdn = $env:computername + "." + $env:userdnsdomain}
        if (($env:computername -ieq $ConnectionServer) -or ($ConnectionServer-ieq "localhost") -or ($fqdn -ieq $ConnectionServer))
            # {$hzServer = Connect-HVServer -server "localhost"} #klappt nicht -keine ?bergabe gefunden f?r ?bergabe der Credentials CurrentUser
            # https://gallery.technet.microsoft.com/scriptcenter/Impersonate-a-User-9bfeff82
            # https://searchcode.com/codesearch/view/8670292/
        {
            try
            {
		        $hzServer = Connect-HVServer -server $ConnectionServer -User $username -Password $password -Domain $domain
            }
            catch{}
            finally{}
        }
        else
        {
            try
            {
		        $hzServer = Connect-HVServer -server $ConnectionServer -User $username -Password $password -Domain $domain
            }
            catch{}
            finally{}
        }

        # https://github.com/vmware/PowerCLI-Example-Scripts/blob/master/Modules/VMware.Hv.Helper/VMware.HV.Helper.psm1
		if ($hzServer -ne $null)
		{
            $hzDefaultServices = $Global:DefaultHVServers.extensiondata

			# Assign a variable to obtain the API Extension Data
			<#Extension Data#>
			$xmloutput=@{}

            $hzServices = $hzServer.extensiondata
			$xmloutput["ExtensionData"]=@{}         
            try
            {
                $hzPodfederation = $hzServices.podfederation.podfederation_get()		
            }
            catch
            {
                $hzPodfederation=$null
            }
            finally {$xmloutput["ExtensionData"]["Podfederation"] = $hzPodfederation}

            #if any localpodstatus.status=enabled, retrieve pod information
            if ("ENABLED" -ieq $hzPodfederation.localpodstatus.status)
            {
			    # Retrieve Pod metrics
                try
                {
                    $hzPod = $hzServices.Pod.Pod_List()
                }
                catch {}
                finally {$xmloutput["ExtensionData"]["Pod"] = $hzPod}
            }

			# Retrieve Connection Server Health metrics
			$hzHealth = $hzDefaultServices.ConnectionServerHealth.ConnectionServerHealth_List()
			$xmloutput["ExtensionData"]["ConnectionServerHealth"] = $hzHealth

			# Retrieve Security Server Health metrics
			$SecurityServerHealth = $hzDefaultServices.SecurityServerHealth.SecurityServerHealth_List()
			$xmloutput["ExtensionData"]["SecurityServerHealth"] = $SecurityServerHealth

			# Retrieve Connection Server General metrics
			$hzGeneral = $hzDefaultServices.ConnectionServer.ConnectionServer_List()
			$xmloutput["ExtensionData"]["ConnectionServerGeneral"] = $hzGeneral

			# Display EventdatabaseHealth
			$EventdatabaseHealth = $hzDefaultServices.EventDatabaseHealth.EventDatabaseHealth_Get()
			$xmloutput["ExtensionData"]["EventDatabaseHealth"] = $EventdatabaseHealth

			# Display ViewComposerHealth
			$ViewComposerHealth = $hzDefaultServices.ViewComposerHealth.ViewComposerHealth_List()
			$xmloutput["ExtensionData"]["ViewComposerHealth"] = $ViewComposerHealth

			# Display VirtualCenterHealth
			$VirtualCenterHealth = $hzDefaultServices.VirtualCenterHealth.VirtualCenterHealth_List()
			$xmloutput["ExtensionData"]["VirtualCenterHealth"] = $VirtualCenterHealth

			# Display ADDomainHealth
            $ADDomainHealth = $hzDefaultServices.ADDomainHealth.ADDomainHealth_List()
			$xmloutput["ExtensionData"]["ADDomainHealth"] = $ADDomainHealth

	        return $xmloutput
		}
	}
}

function Get-Linkedclonereport
{
param(
  [parameter(Mandatory=$true)]
  [string] $ConnectionServer,
  [parameter(Mandatory=$true)]
  [string] $user,
  [parameter(Mandatory=$true)]
  [string] $username,
  [parameter(Mandatory=$true)]
  [string] $domain,
  [parameter(Mandatory=$true)]
  [string] $password
)
    $connsrvpools = @()
    if ($password -ne $null)
    {
        $secpassword = $password | ConvertTo-SecureString -asPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($user,$secpassword)
    }
	
	# Create an ADSI Search    
	$Searcher1 = New-Object -TypeName System.DirectoryServices.DirectorySearcher
	# LDAP Verbindungsstring VMware View ADAM Datenbank 'Server Group'
	$LDAPPath1 = "LDAP://" + $ConnectionServer + ":389/OU=Server Groups,DC=vdi,DC=vmware,DC=int"
    if ($password -ne $null)
    {
	    $LDAPEntry1 = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $LDAPPath1, $($Credential.UserName), $($Credential.GetNetworkCredential().password)
    }
	else
	{
	    $LDAPEntry1 = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $LDAPPath1
	}
	$Searcher1.SearchRoot = $LDAPEntry1
    $hzObjects1 = $Searcher1.FindAll()
    $pools = $hzObjects1 | where { $_.Properties.objectcategory -match "CN=pae-ServerPool" -and $_.Properties."pae-serverpooltype" -eq "4" }

	# Create an ADSI Search    
	$Searcher2 = New-Object -TypeName System.DirectoryServices.DirectorySearcher
	# LDAP Verbindungsstring VMware View ADAM Datenbank 'Servers'	
	$LDAPPath2 = "LDAP://" + $ConnectionServer + ":389/OU=Servers,DC=vdi,DC=vmware,DC=int"
    if ($password -ne $null)
	{
		$LDAPEntry2 = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $LDAPPath2, $($Credential.UserName), $($Credential.GetNetworkCredential().password)
	}
	else
	{
		$LDAPEntry2 = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $LDAPPath
	}
	$Searcher2.SearchRoot = $LDAPEntry2
    $hzObjects2 = $Searcher2.FindAll()
	$VMs = $hzObjects2 | where { $_.Properties.objectcategory -match "CN=pae-VM" }

	$a = 0
	$pool_ids = @()
	$available = 0
	$unavailable = 0

	# Array erstellung 'Anzahl Pools'
	$count = $pools.count
	for ($i = 0; $i -lt $count; $i++) { $pool_ids += @($i) }
	$hash_poolstatus = @{ }

	# Array erstellung 'Pool Name'
	foreach ($Pool in $Pools)
	{
		$attribute = $Pool.Properties

		$value = 'pae-disabled'
		$poolstatus = $attribute.$value

		$value = 'name'
		$poolname = $attribute.$value
		$pool_ids[$a] = $poolname

		if ([string]$poolstatus -eq "0") { $hash_poolstatus.add("$poolname", 0) } else { $hash_poolstatus.add("$poolname", 1) }

		$a++
	}

	# hashtables f?r VM status
	$hash = @{ }
	$hash_count = @{ }
	$hash_clon = @{ }
	$hash_cust = @{ }
	$hash_ready = @{ }
	$hash_Connected = @{ }
	$hash_disconnected = @{ }
	$hash_main = @{ }


	foreach ($id in $pool_ids)
	{
		$hash.add("$id", 0)
		$hash_count.add("$id", 0)
		$hash_clon.add("$id", 0)
		$hash_cust.add("$id", 0)
		$hash_ready.add("$id", 0)
		$hash_Connected.add("$id", 0)
		$hash_disconnected.add("$id", 0)
		$hash_main.add("$id", 0)
	}

	# Identifizierung VM Status 
	foreach ($VM in $VMs)
	{
		$attribute = $VM.Properties
		$ProvStatus = $attribute.$value
	
		if ($ProvStatus -eq "1") { $unavailable++ }
		else { $available++ }
	
		$attribute = $VM.Properties
		$Value = 'pae-vmpath'
		$path = $attribute.$value
	
		$value = 'pae-displayname'
		$name = "/" + $attribute.$value
		$path = $path -Replace ($name, "")
	
		$extPath = "/VSZH0004.uniqconsulting.local/vm/VDI/VDI-Pools/"	
	
		$path = $path -Replace ($dirname, "")
		$path = $path -Replace ($extPath, "")
	
		$value = 'pae-vmstate'
		$state = $attribute.$value
	
	
		if ($ProvStatus -ne "1")
		{
			foreach ($id in $pool_ids)
			{
				if ($path -eq $id)
				{
				
					if ($state -eq "READY")
					{
						$hash_ready["$id"]++
					}
					if ($state -eq "CUSTOMIZING")
					{
						$hash_cust["$id"]++
					}
					if ($state -eq "CLONING")
					{
						$hash_clon["$id"]++
					}
					if ($state -eq "MAINTENANCE")
					{
						$hash_main["$id"]++
					}
					$hash["$id"]++
				}
				Else
				{
				}
			}
		}
	}

	# hashtable erstellen des VM Status
	$exp = @("ConnectionServer,Pools,NMachine,Ready,Connected,Disconnected,Customizing,Cloning,Maintenance,Poolstatus")

    try
    {
        $session = new-pssession -computername $ConnectionServer -Credential $credential -ErrorAction SilentlyContinue
        Invoke-Command -ScriptBlock {
add-pssnapin vmware.view.broker
get-module -listavailable -name VMware.View.Broker | import-module -disablenamechecking -force
} -Session $session
        $null = Export-PSSession -Session $session -Module VMware.View.Broker -OutputModule Exported.VMware.View -AllowClobber -force
        import-module -disablenamechecking Exported.VMware.View -force

	    foreach ($id in $pool_ids)
	    {
		    $PoolConnected = Get-RemoteSession -Pool_id $id -state "CONNECTED" -ErrorAction SilentlyContinue| Measure-Object | Select -ExpandProperty Count -ErrorAction SilentlyContinue
		    $PoolDiscConnected = Get-RemoteSession -Pool_id $id -state "DISCONNECTED" -ErrorAction SilentlyContinue| Measure-Object | Select -ExpandProperty Count -ErrorAction SilentlyContinue
		    $hash_Connected["$id"] = $PoolConnected
		    $hash_disconnected["$id"] = $PoolDiscConnected
		    $VMCounts = Get-DesktopVM -Pool_id $id -ErrorAction SilentlyContinue
		    $hash_Count["$id"] = $VMCounts.count
		    $hash_ready["$id"] = $VMCounts.count - $hash_Connected["$id"] - $hash_disconnected["$id"] - $hash_cust["$id"] - $hash_clon["$id"] - $hash_main["$id"]
	    }
        Get-PSSession|remove-pssession
        get-module -name exported.vmware.view -listavailable|remove-module
        $tmppath = (get-module -name exported.vmware.view -listavailable).modulebase
        Remove-Item -Path $tmppath -Force -Recurse -confirm:$false
    }
    catch{}
    finally
    {
	    $hash.keys | sort | %{ $exp += (@($ConnectionServer) + $_ + $hash_Count.$_ + $hash_ready.$_ + $hash_Connected.$_ + $hash_disconnected.$_ + $hash_cust.$_ + $hash_clon.$_ + $hash_main.$_ + $hash_poolstatus.$_) -join "," }
    }
	return ($exp | convertfrom-csv)
}

$hz7ReportXML=@()
$global:outputdir=$env:programdata+"\my"
new-item -itemtype directory -force -path $global:outputdir | out-null	

if (($hzConn -eq "-") -or ($hzConn -eq $null)) {$hzConn=""}
if (($hzPools -eq "-") -or ($hzPools -eq $null)) {$hzPools=""}
#http://www.hakabo.com/web/2017/03/powershell-implicit-remoting-with-view-powercli-cmdlets/
$password = $hzpassword | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($hzUser,$password)

# Requires Run as Administrator
# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if ($myWindowsPrincipal.IsInRole($adminRole))
{
    write-host "We are running as Administrator. Import-module VMware.PowerCLI if not already done."
    $rc = PowerCLIPrerequisites
    if ($rc -eq 0)
    {
        if (($hzPools -imatch $hzConn) -or ($hzPools -eq ""))
        {
            $xmloutput=@{}
			$xmloutput["ConnectionServer"]=@{}
			$xmloutput["ConnectionServer"]=$hzConn
			$xmloutput["hz7Services"] =@{}
			$xmloutput["hz7Services"] = Get-Hz7Report -connectionserver $hzConn -username $hzUsername -domain $hzDomain -password $hzpassword
			$xmloutput["linkedclones"] =@{}
			$xmloutput["linkedclones"] = Get-linkedclonereport -connectionserver $hzConn -user $hzUser -username $hzUsername -domain $hzDomain -password $hzpassword 
			$hz7ReportXML += ,@($xmloutput)
        }
		# Loop through Pools
		if (($hzPools -ne "") -and ($hzPools -ne $null))
		{
			foreach ($PoolExpression in ($hzPools.split($delimiterList)))
			{
				$ConnSrvData=$null
				if ((!($Pool0Expression)) -or (!($Pool1Expression)) -or (!($Pool2Expression)))
				{
					foreach ($IntegrityExpression in ($PoolExpression.split($delimiterIntegrity)))
					{
						$pat = "[a-zA-Z0-9.\\]$"
						$check = $IntegrityExpression -imatch $pat
						if ($check -eq $false) {$regExpressionFailureCount++}
						else
						{
							$tmpObj = @()
							$tmpObj = $IntegrityExpression.split($delimiterStructure)
							$tmpObjConnSrv = $tmpObj[0]
                            try{$tmpObjPool = $tmpObj[1]}catch{$tmpObjPool=$null}

                            $check = $hz7ReportXML.ConnectionServer -imatch $tmpObjConnSrv # Data connection server already collected?
                            if ($check -eq $false)
                            {
								$pat = "[a-zA-Z0-9.]"
								$check = $tmpObjConnSrv -match $pat
								if ($check -eq $false) {$regExpressionFailureCount++}		
								else
								{
									try
									{
										$xmloutput=@{}
										$xmloutput["ConnectionServer"]=@{}
										$xmloutput["ConnectionServer"]=$tmpObjConnSrv
										$xmloutput["hz7Services"] =@{}
										$xmloutput["hz7Services"] = Get-Hz7Report -connectionserver $tmpObjConnSrv -username $hzUsername -domain $hzDomain -password $hzpassword
										$xmloutput["linkedclones"] =@{}
										$xmloutput["linkedclones"] = Get-linkedclonereport -connectionserver $tmpObjConnSrv -user $hzUser -username $hzUsername -domain $hzDomain -password $hzpassword 

										$hz7ReportXML += ,@($xmloutput)
									 }
									 catch {}
									 finally{}
								}
                            }
						}
					}
				}
			}
		}
        $hz7ReportXML | export-Clixml ($global:outputdir + "\hz7report" + $Identifier + ".xml") -force -confirm:$false
	}
}
