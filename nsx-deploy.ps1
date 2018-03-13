param(
	[Parameter(Mandatory=$true)] [String]$configFile,
	[switch]$deployNSXManager,
	[switch]$configureNSX,
	[switch]$deployControllers,
	[switch]$prepareHosts
)
try {
	Get-Module -ListAvailable VMware.PowerCLI,PowerNSX | Import-Module -ErrorAction SilentlyContinue
}
catch {}
finally {}

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
	} else {
		Write-Host -ForegroundColor Green " $message"
	}
	"[$($timeStamp)] $($message)" | Out-File -Append -LiteralPath $verboseLogFile
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
if($mgmtVCSA) { Write-Log "Management VCSA: OK" } else { Write-Log "Management VCSA: Failed" -Warning; $preflightFailure = $true }
$mgmtCluster = Get-Cluster -Name $NSXConfig.vcenter.management.cluster -Server $mgmtVCSA -ErrorAction SilentlyContinue
if($mgmtCluster) { Write-Log "Management Cluster: OK" } else { Write-Log "Management Cluster: Failed" -Warning; $preflightFailure = $true }
$mgmtDatastore = Get-Datastore -Name $NSXConfig.vcenter.management.datastore -Server $mgmtVCSA -ErrorAction SilentlyContinue
if($mgmtDatastore) { Write-Log "Management Datastore: OK" } else { Write-Log "Management Datastore: Failed" -Warning; $preflightFailure = $true }
$mgmtPortgroup = Get-VDPortgroup -Name $NSXConfig.vcenter.management.portgroup -Server $mgmtVCSA -ErrorAction SilentlyContinue
if($mgmtPortgroup) { Write-Log "Management Portgroup: OK" } else { Write-Log "Management Portgroup: Failed" -Warning; $preflightFailure = $true }
$mgmtFolder = Get-VMFolder -vcsaConnection $mgmtVCSA -folderPath $NSXConfig.vcenter.management.folder -ErrorAction SilentlyContinue
if($mgmtFolder) { Write-Log "Management Folder: OK" } else { Write-Log "Management Folder: Failed" -Warning; $preflightFailure = $true }
$mgmtHost = $mgmtCluster | Get-VMHost -Server $mgmtVCSA  -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionState -eq "Connected" } | Get-Random
if($mgmtHost) { Write-Log "Management Host: OK" } else { Write-Log "Management Host: Failed" -Warning; $preflightFailure = $true }
Write-Log "### Validating Resource"
$resVCSA = Get-VCSAConnection -vcsaName $NSXConfig.vcenter.resource.server -vcsaUser $NSXConfig.vcenter.resource.user -vcsaPassword $NSXConfig.vcenter.resource.password -ErrorAction SilentlyContinue
if($resVCSA) { Write-Log "Resource VCSA: OK" } else { Write-Log "Resource VCSA: Failed" -Warning; $preflightFailure = $true }
$resCluster = Get-Cluster -Name $NSXConfig.vcenter.resource.cluster -Server $resVCSA -ErrorAction SilentlyContinue
if($resCluster) { Write-Log "Resource Cluster: OK" } else { Write-Log "Resource Cluster: Failed" -Warning; $preflightFailure = $true }
$resDatastore = Get-Datastore -Name $NSXConfig.vcenter.resource.datastore -Server $resVCSA -ErrorAction SilentlyContinue
if($resDatastore) { Write-Log "Resource Datastore: OK" } else { Write-Log "Resource Datastore: Failed" -Warning; $preflightFailure = $true }
$resDistributedSwitch = Get-VDSwitch -Name $NSXConfig.vcenter.resource.vds -Server $resVCSA -ErrorAction SilentlyContinue
if($resDistributedSwitch) { Write-Log "Resource Distributed Switch: OK" } else { Write-Log "Resource Distributed Switch: Failed" -Warning; $preflightFailure = $true }
$resControllerPortgroup = Get-VDPortgroup -Name $NSXConfig.vcenter.resource.controllerportgroup -Server $resVCSA -ErrorAction SilentlyContinue
if($resControllerPortgroup) { Write-Log "Resource Controller Portgroup: OK" } else { Write-Log "Resource Portgroup: Failed" -Warning; $preflightFailure = $true }
$resFolder = Get-VMFolder -vcsaConnection $resVCSA -folderPath $NSXConfig.vcenter.resource.folder -ErrorAction SilentlyContinue
if($resFolder) { Write-Log "Resource Folder: OK" } else { Write-Log "Resource Folder: Failed" -Warning; $preflightFailure = $true }
$resHost = $resCluster | Get-VMHost -Server $resVCSA  -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionState -eq "Connected" } | Get-Random
if($resHost) { Write-Log "Resource Host: OK" } else { Write-Log "Resource Host: Failed" -Warning; $preflightFailure = $true }


if($preflightFailure) {
	Write-Log "#### Aborting - please fix pre-flight configuration errors ####" -Warning
	return;
}

if($DeployNSXManager) {
	Write-Log "#### Deploying NSX Manager ####"

	if((Get-VM -Server $mgmtVCSA | Where-Object -Property Name -eq -Value $NSXConfig.nsx.manager.name) -eq $null) {
		Write-Log "Deploying NSX Manager OVA"
		$Param = @{
			NsxManagerOVF		=	$NSXConfig.nsx.manager.source
			Name				=	$NSXConfig.nsx.manager.name 
			ClusterName			=	$NSXConfig.vcenter.management.cluster
			ManagementPortGroupName	=	$NSXConfig.vcenter.management.portgroup
			DatastoreName		=	$NSXConfig.vcenter.management.datastore
			FolderName			=	($NSXConfig.vcenter.management.folder.split("/") | Select-Object -Last 1)
			CliPassword			=	$NSXConfig.nsx.manager.adminpass
			CliEnablePassword	=	$NSXConfig.nsx.manager.enablepass
			Hostname			=	$NSXConfig.nsx.manager.name
			IpAddress			=	$NSXConfig.nsx.manager.network.ip
			Netmask 			=	$NSXConfig.nsx.manager.network.netmask
			Gateway 			=	$NSXConfig.nsx.manager.network.gateway
			DnsServer			=	$NSXConfig.nsx.manager.network.dns
			DnsDomain			=	$NSXConfig.nsx.manager.network.domain
			NtpServer			=	$NSXConfig.nsx.manager.network.ntp
			EnableSsh			=	$NSXConfig.nsx.manager.enableSSH
		}

		if(!(New-NSXManager @Param -StartVM -Wait)) {
			throw "Unable to deploy NSX Manager OVF! $_"
		}
	} else {
		Write-Log "NSX manager exists, skipping" -Warning
	}
}

if($configureNSX) {
	Write-Log "#### Configuring NSX Manager ####"

	Write-Log "## Connect NSX Manager to vCenter ##"
	Connect-NSXServer -NsxServer $NSXConfig.nsx.manager.network.ip -Username "admin" -Password $NSXConfig.nsx.manager.adminpass -DisableViAutoConnect -WarningAction SilentlyContinue |  Out-File -Append -LiteralPath $verboseLogFile
	$NSXVC = Get-NsxManagerVcenterConfig

	if($NSXVC.Connected -eq $true) {
		Write-Log "NSX Manager is already connected to vCenter" -Warning
	} else {
		Set-NsxManager -vcenterusername $NSXConfig.vcenter.resource.user -vcenterpassword $NSXConfig.vcenter.resource.password -vcenterserver $NSXConfig.vcenter.resource.server -WarningAction SilentlyContinue |  Out-File -Append -LiteralPath $verboseLogFile
	}
	$NSXSSO = Get-NsxManagerSsoConfig
	if($NSXSSO.Connected -ne $true) {
		Set-NsxManager -ssousername $NSXConfig.vcenter.resource.user -ssopassword $NSXConfig.nsx.manager.adminpass -ssoserver $NSXConfig.vcenter.resource.sso -SsoPort $NSXConfig.vcenter.resource.ssoport -WarningAction SilentlyContinue |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX Manager is already connected to SSO" -Warning
	}

	Write-Log "Licensing NSX"
	$ServiceInstance = Get-View ServiceInstance -Server $resVCSA
	$LicenseManager = Get-View $ServiceInstance.Content.licenseManager
	$LicenseAssignmentManager = Get-View $LicenseManager.licenseAssignmentManager
	$LicenseAssignmentManager.UpdateAssignedLicense("nsx-netsec",$NSXConfig.license,$NULL) | Out-Null
}
if($deployControllers) {
	$NSX = Connect-NSXServer -NsxServer $NSXConfig.nsx.manager.network.ip -Username "admin" -Password $NSXConfig.nsx.manager.adminpass -WarningAction SilentlyContinue

	if((Get-NsxIpPool -Name $NSXConfig.nsx.controllers.pool.name) -eq $null) {
		New-NsxIPPool -Name $NSXConfig.nsx.controllers.pool.name -Gateway $NSXConfig.nsx.manager.network.gateway -SubnetPrefixLength $NSXConfig.nsx.manager.network.prefix -StartAddress $NSXConfig.nsx.controllers.pool.startIp -EndAddress $NSXConfig.nsx.controllers.pool.endIp -DnsServer1 $NSXConfig.nsx.manager.network.dns -DnsSuffix $NSXConfig.nsx.manager.network.domain |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX Controller IP Pool exists, skipping" -Warning
	}
	$NSXPool = Get-NSXIPPool $NSXConfig.nsx.controllers.pool.name
	foreach($controller in $NSXConfig.nsx.controllers.controller) {
		if((Get-NSXController | where-object {$_.name -eq $controller.name}) -ne $null) {
			Write-Log "NSX Controller $($controller.name) Exists, skipping" -Warning
		} else {
			Write-Log "Deploying NSX Controller ($($controller.name))"
			$Param = @{
				ControllerName = $($controller.name)
				Cluster = $resCluster
				Datastore = $resDatastore
				PortGroup = $resControllerPortgroup
				IpPool = $NSXPool
				Connection = $NSX
				Confirm = $false
				Wait = $true
			}
			# Only add the password for the primary controller
			if((Get-NSXController -connection $NSX | measure-object).count -eq 0) {
				$Param.Add("Password", $NSXConfig.nsx.controllers.password)
			}
			New-NSXController @Param | Out-File -Append -LiteralPath $verboseLogFile
			Write-Log "Controller deployed successfully"
		}

	}
}
if($prepareHosts) {
	$NSX = Connect-NSXServer -NsxServer $NSXConfig.nsx.manager.network.ip -Username "admin" -Password $NSXConfig.nsx.manager.adminpass -WarningAction SilentlyContinue
	Write-Log "## Preparing hosts ##"
	Write-Log "Initiating installation of NSX agents"
	$clusterStatus = ($resCluster | Get-NsxClusterStatus | Select-Object -first 1).installed
	if($clusterStatus -eq "false") {
		$resCluster | Install-NsxCluster -VxlanPrepTimeout 360 | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "Cluster is already installed" -Warning
	}
	Write-Log "Creating VTEP IP Pool"
	$vtepPool = $NSXConfig.nsx.vxlan.pool
	if((Get-NsxIpPool -Name $vtepPool.name) -eq $null) {
		New-NsxIPPool -Name $vtepPool.name -Gateway $vtepPool.gateway -SubnetPrefixLength $vtepPool.prefix -StartAddress $vtepPool.startIp -EndAddress $vtepPool.endIp |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "VTEP IP Pool exists, skipping" -Warning
	}
	Write-Log "Creating VDS Context"
	if((Get-NsxVdsContext) -eq $null) {
		New-NsxVdsContext -VirtualDistributedSwitch $resDistributedSwitch -Teaming $NSXConfig.nsx.vxlan.teaming -Mtu $NSXConfig.nsx.vxlan.mtu | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "VDS Context already configured, skipping" -Warning
	}
	Write-Log "Creating VXLAN configurations"
	$vxlanStatus = (Get-NsxClusterStatus $resCluster | Where-Object {$_.featureId -eq "com.vmware.vshield.vsm.vxlan" }).status # | Out-File -Append -LiteralPath $verboseLogFile
	if($vxlanStatus -ne "GREEN") {
		$resCluster | New-NsxClusterVxlanConfig -VirtualDistributedSwitch $resDistributedSwitch -ipPool (Get-NsxIpPool -Name $vtepPool.name) -VlanId $NSXConfig.nsx.vxlan.vlan | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "VXLAN already configured, skipping" -Warning
	}
	Write-Log "Creating Segment ID Range"
	if((Get-NSXsegmentidrange) -eq $null) {
		New-NSXsegmentidrange -Name $NSXConfig.nsx.transport.segmentidrange.name -Begin $NSXConfig.nsx.transport.segmentidrange.begin -End $NSXConfig.nsx.transport.segmentidrange.end | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "Segment ID Range exists, skipping" -Warning
	}
	# Change the NSX VXLAN UDP Port to enable nested ESXi, if you have NSX enabled on the
	# VDSwitch that hosts the nested environment, then you must change the port to something
	# that is different.
	# Invoke-NsxRestMethod -Method PUT -URI "/api/2.0/vdn/config/vxlan/udp/port/8472"
	Write-Log "Creating Transport Zone"
	if((Get-NsxTransportZone -Name $NSXConfig.nsx.transport.name) -eq $null) {
		New-NSXTransportZone -Name $NSXConfig.nsx.transport.name -Cluster $resCluster -ControlPlaneMode $NSXConfig.nsx.transport.mode | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "Transport Zone exists, skipping" -warning
	}
}

if($deployComponents) {
	$NSX = Connect-NSXServer -NsxServer $NSXConfig.nsx.manager.network.ip -Username "admin" -Password $NSXConfig.nsx.manager.adminpass -WarningAction SilentlyContinue
	Write-Log "Creating Logical Switches"
	foreach ($logicalSwitch in $NSXConfig.components.logicalswitches) {
		Write-Host "Creating $($logicalswitch.name)" -Info
		if((Get-NSXLogicalSwitch -Name $logicalSwitch.name) -eq $null) {
				Get-NSXTransportZone $NSXConfig.nsx.transport.name | New-NSXLogicalSwitch $logicalSwitch.name | Out-File -Append -LiteralPath $verboseLogFile
		} else {
			Write-log "Logical Switch $($logicalSwitch.name) exists, skipping" -Warning
		}
	}

	Write-log "Creating Provider Logical Router Edge(s)"
	foreach($plr in $NSXConfig.components.edges.plr) {
		if($plr.interfaces[0]) {
			#$int0 = New-NsxEdgeinterfacespec -index 0 -Name  -type Uplink -ConnectedTo $EdgeUplinkNetwork -PrimaryAddress $EdgeUplinkPrimaryAddress -SecondaryAddress $EdgeUplinkSecondaryAddress -SubnetPrefixLength $DefaultSubnetBits
		}
		if($plr.interfaces[1]) {
			#$int1 = New-NsxEdgeinterfacespec -index 1 -Name  -type Uplink -ConnectedTo $EdgeUplinkNetwork -PrimaryAddress $EdgeUplinkPrimaryAddress -SecondaryAddress $EdgeUplinkSecondaryAddress -SubnetPrefixLength $DefaultSubnetBits
		}
	}
}
if($DefaultNSXConnection) {
	Disconnect-NSXServer -ErrorAction SilentlyContinue
}
Close-VCSAConnection

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

Write-Log "Pod Deployment Tasks Completed in $($duration) minutes"