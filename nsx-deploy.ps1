param(
	[Parameter(Mandatory=$true)] [String]$configFile,
	[switch]$configureVDSwitch,
	[switch]$deployNSXManager,
	[switch]$configureNSX,
	[switch]$deployControllers
)
Get-Module -ListAvailable VMware*,PowerNSX | Import-Module
if ( !(Get-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) ) {
	throw "PowerCLI must be installed"
}
# Import the JSON Config File
$NSXConfig = (get-content $($configFile) -Raw) | ConvertFrom-Json

# Log File
$verboseLogFile = $NSXConfig.log

$StartTime = Get-Date

Function Write-Log {
	param(
		[Parameter(Mandatory=$true)]
		[String]$Message,
		[switch]$Warning,
		[switch]$Info
	)
	$timeStamp = Get-Date -Format "dd-MM-yyyy hh:mm:ss"
	Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
	if($Warning){
		Write-Host -ForegroundColor Yellow " WARNING: $message"
	} elseif($Info) {
		Write-Host -ForegroundColor White " $message"
	}else {
		Write-Host -ForegroundColor Green " $message"
	}
	$logMessage = "[$timeStamp] $message" | Out-File -Append -LiteralPath $verboseLogFile
}

function Get-VCSAConnection {
	param(
		[string]$vcsaName,
		[string]$vcsaUser,
		[string]$vcsaPassword
	)
	Write-Log "Getting connection for $($vcsaName)"
	$existingConnection =  $global:DefaultVIServers | where-object -Property Name -eq -Value $vcsaName
	if($existingConnection -ne $null) {
		return $existingConnection;
	} else {
        $connection = Connect-VIServer -Server $vcsaName -User $vcsaUser -Password $vcsaPassword -WarningAction SilentlyContinue;
		return $connection;
	}
}

function Close-VCSAConnection {
	param(
		[string]$vcsaName
	)
	if($vcsaName.Length -le 0) {
		if($Global:DefaultVIServers.count -ge 0) {
	        Write-Log -Message "Disconnecting from all vCenter Servers"
			Disconnect-VIServer -Server $Global:DefaultVIServers -Confirm:$false
		}
	} else {
		$existingConnection =  $global:DefaultVIServers | where-object -Property Name -eq -Value $vcsaName
        if($existingConnection -ne $null) {
            Write-Log -Message "Disconnecting from $($vcsaName)"
			Disconnect-VIServer -Server $existingConnection -Confirm:$false;
        } else {
            Write-Log -Message "Could not find an existing connection named $($vcsaName)" -Warning
        }
	}
}

function Get-VMFolder {
	param(
		$vcsaConnection,
		[string]$folderPath
	)
	$folderArray = $folderPath.split("/")
	$parentFolder = Get-Folder -Server $vcsaConnection -Name vm
	foreach($folder in $folderArray) {
		$folderExists = Get-Folder -Server $vcsaConnection | Where-Object -Property Name -eq -Value $folder
		if($folderExists -ne $null) {
			$parentFolder = $folderExists
		} else {
			$parentFolder = New-Folder -Name $folder -Location $parentFolder
		}
	}
	return $parentFolder
}

Write-Log "#### Validating Configuration ####"
Write-Log "### Validating Management"
$mgmtVCSA = Get-VCSAConnection -vcsaName $NSXConfig.vcenter.management.server -vcsaUser $NSXConfig.vcenter.management.user -vcsaPassword $NSXConfig.vcenter.management.password -ErrorAction SilentlyContinue
if($mgmtVCSA) { Write-Log "Management VCSA: OK" -Info } else { Write-Log "Management VCSA: Failed" -Warning; $preflightFailure = $true }
$mgmtCluster = Get-Cluster -Name $NSXConfig.vcenter.management.cluster -Server $mgmtVCSA -ErrorAction SilentlyContinue
if($mgmtCluster) { Write-Log "Management Cluster: OK" -Info } else { Write-Log "Management Cluster: Failed" -Warning; $preflightFailure = $true }
$mgmtDatastore = Get-Datastore -Name $NSXConfig.vcenter.management.datastore -Server $mgmtVCSA -ErrorAction SilentlyContinue
if($mgmtDatastore) { Write-Log "Management Datastore: OK" -Info } else { Write-Log "Management Datastore: Failed" -Warning; $preflightFailure = $true }
$mgmtPortgroup = Get-VDPortgroup -Name $NSXConfig.vcenter.management.portgroup -Server $mgmtVCSA -ErrorAction SilentlyContinue
if($mgmtPortgroup) { Write-Log "Management Portgroup: OK" -Info } else { Write-Log "Management Portgroup: Failed" -Warning; $preflightFailure = $true }
$mgmtFolder = Get-VMFolder -vcsaConnection $mgmtVCSA -folderPath $NSXConfig.vcenter.management.folder -ErrorAction SilentlyContinue
if($mgmtFolder) { Write-Log "Management Folder: OK" -Info } else { Write-Log "Management Folder: Failed" -Warning; $preflightFailure = $true }
$mgmtHost = $mgmtCluster | Get-VMHost -Server $mgmtVCSA  -ErrorAction SilentlyContinue | where { $_.ConnectionState -eq "Connected" } | Get-Random
if($mgmtHost) { Write-Log "Management Host: OK" -Info } else { Write-Log "Management Host: Failed" -Warning; $preflightFailure = $true }
Write-Log "### Validating Resource"
$resVCSA = Get-VCSAConnection -vcsaName $NSXConfig.vcenter.resource.server -vcsaUser $NSXConfig.vcenter.resource.user -vcsaPassword $NSXConfig.vcenter.resource.password -ErrorAction SilentlyContinue
if($resVCSA) { Write-Log "Resource VCSA: OK" -Info } else { Write-Log "Resource VCSA: Failed" -Warning; $preflightFailure = $true }
$resCluster = Get-Cluster -Name $NSXConfig.vcenter.resource.cluster -Server $resVCSA -ErrorAction SilentlyContinue
if($resCluster) { Write-Log "Resource Cluster: OK" -Info } else { Write-Log "Resource Cluster: Failed" -Warning; $preflightFailure = $true }
$resDatastore = Get-Datastore -Name $NSXConfig.vcenter.resource.datastore -Server $resVCSA -ErrorAction SilentlyContinue
if($resDatastore) { Write-Log "Resource Datastore: OK" -Info } else { Write-Log "Resource Datastore: Failed" -Warning; $preflightFailure = $true }
$resControllerPortgroup = Get-VDPortgroup -Name $NSXConfig.vcenter.resource.controllerportgroup -Server $resVCSA -ErrorAction SilentlyContinue
if($resControllerPortgroup) { Write-Log "Resource Controller Portgroup: OK" -Info } else { Write-Log "Resource Portgroup: Failed" -Warning; $preflightFailure = $true }
$resFolder = Get-VMFolder -vcsaConnection $resVCSA -folderPath $NSXConfig.vcenter.resource.folder -ErrorAction SilentlyContinue
if($resFolder) { Write-Log "Resource Folder: OK" -Info } else { Write-Log "Resource Folder: Failed" -Warning; $preflightFailure = $true }
$resHost = $resCluster | Get-VMHost -Server $resVCSA  -ErrorAction SilentlyContinue | where { $_.ConnectionState -eq "Connected" } | Get-Random
if($resHost) { Write-Log "Resource Host: OK" -Info } else { Write-Log "Resource Host: Failed" -Warning; $preflightFailure = $true }


if($preflightFailure) {
	Write-Log "#### Aborting - please fix pre-flight configuration errors ####" -Warning
	return;
}

if($DeployNSXManager) {
	Write-Log "#### Deploying NSX Manager ####"

	if((Get-VM -Server $mgmtVCSA | Where-Object -Property Name -eq -Value $NSXConfig.nsx.manager.name) -eq $null) {
		$ovfconfig = @{
			"vsm_cli_en_passwd_0" = "$($NSXConfig.nsx.manager.enablepass)"
			"NetworkMapping.VSMgmt" = "$($NSXConfig.vcenter.management.portgroup)"
			"vsm_gateway_0" = "$($NSXConfig.nsx.manager.network.gateway)"
			"vsm_cli_passwd_0" = "$($NSXConfig.nsx.manager.adminpass)"
			"vsm_isSSHEnabled" = "$($NSXConfig.nsx.manager.enableSSH)"
			"vsm_netmask_0" = "$($NSXConfig.nsx.manager.network.netmask)"
			"vsm_hostname" = "$($NSXConfig.nsx.manager.name).$($NSXConfig.nsx.manager.network.domain)"
			"vsm_ntp_0" = "$($NSXConfig.nsx.manager.network.ntp)"
			"vsm_ip_0" = "$($NSXConfig.nsx.manager.network.ip)"
			"vsm_dns1_0" = "$($NSXConfig.nsx.manager.network.dns)"
			"vsm_domain_0" = "$($NSXConfig.nsx.manager.network.domain)"
		}
		Write-Log "Deploying NSX Manager OVA"
		$importedVApp = Import-VApp -Server $mgmtVCSA -VMhost $mgmtHost -Source $NSXConfig.nsx.manager.source -OVFConfiguration $ovfconfig -Name $NSXConfig.nsx.manager.name -Datastore $mgmtDatastore -DiskStorageFormat thin
		$NSXManager = Get-VM -Name $NSXConfig.nsx.manager.name -Server $mgmtVCSA
		Write-Log "Moving $($NSXConfig.nsx.manager.name) to $($NSXConfig.vcenter.management.folder) folder"
		Move-VM -VM $NSXManager -Destination $mgmtFolder |  Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "Powering On NSX Manager VM" -Info
		Start-VM -Server $mgmtVCSA -VM $NSXManager -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "Waiting for VM Guest Tools (may take a few minutes)" -Info
		do {
			Sleep -Seconds 20
			$VM_View = Get-VM $NSXConfig.nsx.manager.name -Server $mgmtVCSA | Get-View
			$toolsStatus = $VM_View.Summary.Guest.ToolsRunningStatus
		} Until ($toolsStatus -eq "guestToolsRunning")
		Write-Log "NSX Manager has booted successfully, waiting for API (may take a few minutes)" -Info
		$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f "admin",$NSXConfig.nsx.manager.adminpass)))
		$header = @{Authorization=("Basic {0}" -f $base64AuthInfo)}
		$uri = "https://$($NSXConfig.nsx.manager.network.ip)/api/2.0/vdn/controller"
		do {
			Start-Sleep -Seconds 20
			$result = try { Invoke-WebRequest -Uri $uri -Headers $header -ContentType "application/xml"} catch { $_.Exception.Response}
		} Until ($result.statusCode -eq "200")
		Write-Log "Connected to NSX API successfully" -Info
	} else {
		Write-Log "NSX manager exists, skipping" -Warning
	}
}

if($configureNSX) {
	Write-Log "#### Configuring NSX Manager ####"
	Write-Log "Licensing NSX"
	$ServiceInstance = Get-View ServiceInstance -Server $resVCSA
	$LicenseManager = Get-View $ServiceInstance.Content.licenseManager
	$LicenseAssignmentManager = Get-View $LicenseManager.licenseAssignmentManager
	$LicenseAssignmentManager.UpdateAssignedLicense("nsx-netsec",$NSXConfig.license,$NULL)

	Write-Log "## Connect NSX Manager to vCenter ##"
	Connect-NSXServer $NSXConfig.nsx.manager.network.ip -Username "admin" -Password $NSXConfig.nsx.manager.adminpass |  Out-File -Append -LiteralPath $verboseLogFile
	$NSXVC = Get-NsxManagerVcenterConfig
	if($NSXVC.Connected -ne $true) {
		Set-NsxManager -vcenterusername $NSXConfig.vcenter.resource.user -vcenterpassword $NSXConfig.vcenter.resource.password -vcenterserver $NSXConfig.vcenter.resource.server |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX Manager is already connected to vCenter" -Warning
	}
	$NSXSSO = Get-NsxManagerSsoConfig
	if($NSXSSO.Connected -ne $true) {
		Set-NsxManager -ssousername $NSXConfig.vcenter.resource.user -ssopassword $NSXConfig.nsx.manager.adminpass -ssoserver $NSXConfig.vcenter.resource.sso |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX Manager is already connected to SSO" -Warning
	}
}
if($deployControllers) {
	Connect-NSXServer $NSXConfig.nsx.manager.network.ip -Username "admin" -Password $NSXConfig.nsx.manager.adminpass |  Out-File -Append -LiteralPath $verboseLogFile

	if((Get-NsxIpPool -Name $NSXConfig.nsx.controllers.pool.name) -eq $null) {
		New-NsxIPPool -Name "Controllers" -Gateway $NSXConfig.nsx.manager.network.gateway -SubnetPrefixLength $NSXConfig.nsx.manager.network.prefix -StartAddress $NSXConfig.nsx.controller.startIp -EndAddress $NSXConfig.nsx.controller.endIp -DnsServer1 $NSXConfig.nsx.manager.network.dns -DnsSuffix $NSXConfig.nsx.manager.network.domain |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX IP Pool exists, skipping" -Warning
	}
	if((Get-NSXController) -eq $null) {
		$NSXPool = Get-NSXIPPool "Controllers"
		$NSXPortGroup = Get-VDPortGroup -Name $NSXConfig.vcsa.portgroup -Server $nVCSA
		$NSXDatastore = Get-Datastore -Name "vsanDatastore" -Server $nVCSA
		Write-Log "Deploying NSX Controller"
		$NSXController = New-NsxController -Cluster $nCluster -datastore $NSXDatastore -PortGroup $NSXPortGroup -IpPool $NSXPool -Password $NSXConfig.nsx.controller.password -Confirm:$false
		do {
			Sleep -Seconds 20
			$ControllerStatus = (Get-NSXController -ObjectId $NSXController.id).status
		} Until (($ControllerStatus -eq "RUNNING") -or ($ControllerStatus -eq $null))
		if($ControllerStatus -eq $null) {
			Write-Log "Controller deployment failed" -Warning
		} else {
			Write-Log "Controller deployed successfully"
		}
	} else {
		Write-Log "NSX Controller Exists, skipping" -Warning
	}
}
if($prepareHosts) {
	Write-Log "## Preparing hosts ##"
	$clusterStatus = ($nCluster | Get-NsxClusterStatus | select -first 1).installed
	if($clusterStatus -eq "false") {
		Write-Log "Initiating installation of NSX agents"
		$nCluster | Install-NsxCluster | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "Cluster is already installed" -Warning
	}
	Write-Log "Creating VTEP IP Pool"
	if((Get-NsxIpPool -Name "VTEPs") -eq $null) {
		New-NsxIPPool -Name "VTEPs" -Gateway $NSXConfig.nsx.manager.network.gateway -SubnetPrefixLength $NSXConfig.nsx.manager.network.prefix -StartAddress $NSXConfig.nsx.vtep.startIp -EndAddress $NSXConfig.nsx.vtep.endIp -DnsServer1 $NSXConfig.nsx.manager.network.dns -DnsSuffix $NSXConfig.nsx.manager.network.domain |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "VTEP IP Pool exists, skipping" -Warning
	}
	$nVDSwitch = Get-VDSwitch -Server $nVCSA -Name $NSXConfig.vcsa.distributedSwitch
	if((Get-NsxVdsContext) -eq $null) {
		Write-Log "Creating VDS Context"
		New-NsxVdsContext -VirtualDistributedSwitch $nVDSwitch -Teaming LOADBALANCE_SRCID -Mtu 1600 | Out-File -Append -LiteralPath $verboseLogFile
	}
	$vxlanStatus =  (Get-NsxClusterStatus $nCluster | where {$_.featureId -eq "com.vmware.vshield.vsm.vxlan" }).status | Out-File -Append -LiteralPath $verboseLogFile
	if($vxlanStatus -ne "GREEN") {
		$nCluster | New-NsxClusterVxlanConfig -VirtualDistributedSwitch $nVDSwitch -ipPool (Get-NsxIpPool -Name "VTEPs") -VlanId 0 -VtepCount 2
	} else {
		Write-Log "VXLAN already configured, skipping" -Warning
	}
	# Change the NSX VXLAN UDP Port to enable nested ESXi, if you have NSX enabled on the
	# VDSwitch that hosts the nested environment, then you must change the port to something
	# that is different.
	Invoke-NsxRestMethod -Method PUT -URI "/api/2.0/vdn/config/vxlan/udp/port/8472"
	Write-Host "Creating Transport Zone"
	if((Get-NsxTransportZone -Name "TZ") -eq $null) {
		New-NSXTransportZone -Name "TZ" -Cluster $nCluster -ControlPlaneMode "UNICAST_MODE" | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "Transport Zone exists, skipping" -warning
	}
}

Close-VCSAConnection

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

Write-Log "Pod Deployment Tasks Completed in $($duration) minutes"