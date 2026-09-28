#Requires -Version 7.2
#Requires -Modules Az.Accounts, Az.Compute, Az.Network, Az.Resources, Az.Storage

<#
.SYNOPSIS
    Safely removes expired SRVTAPP session-host VMs and their owned resources.

.DESCRIPTION
    Designed for an Azure Automation PowerShell 7.2 runbook using the
    Automation Account's system-assigned managed identity.

    Scope is deliberately limited to VMs in one subscription and one resource
    group whose names start with SRVTAPP and whose Azure creation time is at
    least MinimumAgeHours old.

    Execute mode performs these phases in order:
      1. Put each selected Citrix machine in maintenance mode and request a
         forced logoff of all sessions without waiting for a zero session count.
      2. Remove each selected machine from the configured Citrix Delivery Group.
      3. Remove it from the configured Citrix machine catalog.
      4. Use one selected deletion candidate as an Active Directory proxy to
         delete all selected computer objects. If no candidate is running, the
         newest selected VM is started temporarily.
      5. Gracefully stop/deallocate the selected Azure VMs.
      6. Delete the VMs and only their exclusively owned managed disks, NICs,
         and public IP addresses.
      7. Refresh dreports/reports/Scripts/ServerList.txt.

    Preview mode is the default and makes no changes.
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$TargetResourceGroupName = 'sage300',
    [ValidateSet('SRVTAPP')]
    [string]$VMNamePrefix = 'SRVTAPP',
    [ValidateRange(12, 720)]
    [int]$MinimumAgeHours = 12,
    [ValidateRange(1, 100)]
    [int]$MaximumVMsPerRun = 20,
    [ValidateSet('Preview', 'Execute')]
    [string]$ExecutionMode = 'Execute',
    [string[]]$ExcludedVMNames = @(),
    [string]$DomainName = 'oilibya.com',
    [string]$DomainNetBIOSName = 'OILIBYA',
    [string]$DomainCredentialAssetName = 'PnPAccount',
    [string]$CitrixCredentialAssetName = 'CitrixApiClient',
    [string]$CitrixCustomerIdVariableName = 'CitrixCustomerId',
    [string]$CitrixSiteIdVariableName = 'CitrixSiteId',
    [string]$CitrixMachineCatalogVariableName = 'CitrixMachineCatalog',
    [string]$CitrixDeliveryGroupVariableName = 'CitrixDeliveryGroup',
    [string]$CitrixApiHostVariableName = 'CitrixApiHost',
    [ValidateRange(1, 60)]
    [int]$CitrixWaitMinutes = 10,
    [ValidateRange(1, 60)]
    [int]$GuestAgentWaitMinutes = 20,
    [string]$ServerListStorageAccountName = 'dreports',
    [string]$ServerListShareName = 'reports',
    [string]$ServerListPath = 'Scripts/ServerList.txt'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-RunbookLog {
    param([Parameter(Mandatory)][string]$Message)
    Write-Output ('[{0:u}] {1}' -f (Get-Date).ToUniversalTime(), $Message)
}

function Get-AzureResourceIdParts {
    param([Parameter(Mandatory)][string]$ResourceId)

    $match = [regex]::Match(
        $ResourceId,
        '^/subscriptions/(?<SubscriptionId>[^/]+)/resourceGroups/(?<ResourceGroupName>[^/]+)/providers/(?<ProviderNamespace>[^/]+)/(?<ResourceType>[^/]+)/(?<Name>[^/]+)(?:/.*)?$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $match.Success) {
        throw "Could not parse Azure resource ID '$ResourceId'."
    }

    [pscustomobject]@{
        SubscriptionId    = $match.Groups['SubscriptionId'].Value
        ResourceGroupName = $match.Groups['ResourceGroupName'].Value
        ProviderNamespace = $match.Groups['ProviderNamespace'].Value
        ResourceType      = $match.Groups['ResourceType'].Value
        Name              = $match.Groups['Name'].Value
    }
}

function Get-AzVMPowerState {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$VMName
    )

    $vmStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status
    return [string](
        $vmStatus.Statuses |
            Where-Object Code -Like 'PowerState/*' |
            Select-Object -ExpandProperty DisplayStatus -First 1
    )
}

function Wait-AzVMGuestAgent {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$VMName,
        [ValidateRange(1, 60)]
        [int]$TimeoutMinutes = 20
    )

    $deadline = (Get-Date).ToUniversalTime().AddMinutes($TimeoutMinutes)
    do {
        $vmWithStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status
        $powerState = [string](
            $vmWithStatus.Statuses |
                Where-Object Code -Like 'PowerState/*' |
                Select-Object -ExpandProperty DisplayStatus -First 1
        )
        $agentReady = @(
            $vmWithStatus.VMAgent.Statuses |
                Where-Object Code -EQ 'ProvisioningState/succeeded'
        ).Count -gt 0

        if ($powerState -eq 'VM running' -and $agentReady) {
            Write-RunbookLog "Azure VM Agent is ready on '$VMName'."
            return
        }

        Write-RunbookLog "Waiting for Azure VM Agent on '$VMName'. PowerState='$powerState'."
        Start-Sleep -Seconds 30
    } while ((Get-Date).ToUniversalTime() -lt $deadline)

    throw "Azure VM Agent on '$VMName' did not become ready within $TimeoutMinutes minutes."
}

function Get-CitrixAccessToken {
    param(
        [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][string]$CustomerId,
        [Parameter(Mandatory)][string]$ApiHost
    )

    $clientSecret = $Credential.GetNetworkCredential().Password
    if ([string]::IsNullOrWhiteSpace($Credential.UserName) -or
        [string]::IsNullOrWhiteSpace($clientSecret)) {
        throw "Citrix credential asset '$CitrixCredentialAssetName' has an empty Client ID or secret."
    }

    $tokenResponse = Invoke-RestMethod `
        -Uri "https://$ApiHost/cctrustoauth2/$CustomerId/tokens/clients" `
        -Method Post `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{
            grant_type    = 'client_credentials'
            client_id     = $Credential.UserName
            client_secret = $clientSecret
        }

    $clientSecret = $null
    if ([string]::IsNullOrWhiteSpace([string]$tokenResponse.access_token)) {
        throw 'Citrix Cloud did not return an access token.'
    }
    return [string]$tokenResponse.access_token
}

function New-CitrixHeaders {
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$CustomerId,
        [Parameter(Mandatory)][string]$SiteId
    )

    return @{
        Accept              = 'application/json'
        'Content-Type'      = 'application/json'
        Authorization       = "CWSAuth Bearer=$AccessToken"
        'Citrix-CustomerId' = $CustomerId
        'Citrix-InstanceId' = $SiteId
    }
}

function Get-CitrixMachine {
    param(
        [Parameter(Mandatory)][string]$MachineName,
        [Parameter(Mandatory)][string]$ApiHost,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $searchBody = @{
        SearchFilters = @(
            @{
                Property = 'MachineName'
                Value    = $MachineName
                Operator = 'Equals'
            }
        )
    } | ConvertTo-Json -Depth 5

    $response = Invoke-RestMethod `
        -Uri "https://$ApiHost/cvad/manage/Machines/`$search" `
        -Method Post `
        -Headers $Headers `
        -Body $searchBody

    return @($response.Items) |
        Where-Object Name -IEQ $MachineName |
        Select-Object -First 1
}

function Wait-CitrixMachineCondition {
    param(
        [Parameter(Mandatory)][string]$MachineName,
        [Parameter(Mandatory)][ValidateSet('InMaintenanceMode', 'NotInDeliveryGroup', 'Absent')]
        [string]$Condition,
        [Parameter(Mandatory)][string]$ApiHost,
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][int]$TimeoutMinutes
    )

    $deadline = (Get-Date).ToUniversalTime().AddMinutes($TimeoutMinutes)
    do {
        $machine = Get-CitrixMachine -MachineName $MachineName -ApiHost $ApiHost -Headers $Headers
        if ($Condition -eq 'Absent' -and -not $machine) {
            return
        }
        if ($Condition -eq 'InMaintenanceMode' -and
            $machine -and
            [bool]$machine.InMaintenanceMode) {
            return
        }
        if ($Condition -eq 'NotInDeliveryGroup' -and
            $machine -and
            [string]::IsNullOrWhiteSpace([string]$machine.DeliveryGroup.Name)) {
            return
        }

        Start-Sleep -Seconds 10
    } while ((Get-Date).ToUniversalTime() -lt $deadline)

    throw "Citrix machine '$MachineName' did not reach condition '$Condition' within $TimeoutMinutes minutes."
}

function Get-VMCreationTimeUtc {
    param([Parameter(Mandatory)][object]$VM)

    if ($VM.TimeCreated) {
        return ([datetimeoffset]$VM.TimeCreated).UtcDateTime
    }

    $resource = Get-AzResource -ResourceId $VM.Id -ExpandProperties
    if ($resource.Properties.timeCreated) {
        return ([datetimeoffset]$resource.Properties.timeCreated).UtcDateTime
    }

    throw "Azure did not return a creation time for VM '$($VM.Name)'. The runbook will not infer age from the VM name."
}

function Get-OwnedVMResources {
    param([Parameter(Mandatory)][object]$VM)

    $diskIds = @()
    if ($VM.StorageProfile.OsDisk.ManagedDisk.Id) {
        $diskIds += [string]$VM.StorageProfile.OsDisk.ManagedDisk.Id
    }
    $diskIds += @(
        $VM.StorageProfile.DataDisks |
            ForEach-Object { [string]$_.ManagedDisk.Id } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    $ownedDisks = @()
    foreach ($diskId in ($diskIds | Sort-Object -Unique)) {
        $parts = Get-AzureResourceIdParts -ResourceId $diskId
        if ($parts.SubscriptionId -ine $script:TargetSubscriptionId) {
            throw "Disk '$diskId' is outside target subscription '$script:TargetSubscriptionId'."
        }
        $disk = Get-AzDisk -ResourceGroupName $parts.ResourceGroupName -DiskName $parts.Name
        $managedBy = [string]$disk.ManagedBy
        $managedByExtended = @($disk.ManagedByExtended | Where-Object { $_ })
        if ($managedBy -ine $VM.Id -or
            ($managedByExtended.Count -gt 0 -and @($managedByExtended | Where-Object { $_ -ine $VM.Id }).Count -gt 0)) {
            throw "Disk '$diskId' is not exclusively owned by VM '$($VM.Name)'."
        }
        $ownedDisks += [pscustomobject]@{
            Id                = $diskId
            ResourceGroupName = $parts.ResourceGroupName
            Name              = $parts.Name
        }
    }

    $ownedNics = @()
    $ownedPublicIps = @()
    foreach ($nicReference in @($VM.NetworkProfile.NetworkInterfaces)) {
        $nicId = [string]$nicReference.Id
        $parts = Get-AzureResourceIdParts -ResourceId $nicId
        if ($parts.SubscriptionId -ine $script:TargetSubscriptionId) {
            throw "NIC '$nicId' is outside target subscription '$script:TargetSubscriptionId'."
        }

        $nic = Get-AzNetworkInterface -ResourceGroupName $parts.ResourceGroupName -Name $parts.Name
        if ([string]$nic.VirtualMachine.Id -ine $VM.Id) {
            throw "NIC '$nicId' is not owned by VM '$($VM.Name)'."
        }

        $ownedNics += [pscustomobject]@{
            Id                = $nicId
            ResourceGroupName = $parts.ResourceGroupName
            Name              = $parts.Name
        }

        foreach ($ipConfiguration in @($nic.IpConfigurations)) {
            $publicIpId = [string]$ipConfiguration.PublicIpAddress.Id
            if ([string]::IsNullOrWhiteSpace($publicIpId)) {
                continue
            }

            $publicIpParts = Get-AzureResourceIdParts -ResourceId $publicIpId
            if ($publicIpParts.SubscriptionId -ine $script:TargetSubscriptionId) {
                throw "Public IP '$publicIpId' is outside target subscription '$script:TargetSubscriptionId'."
            }
            $publicIp = Get-AzPublicIpAddress `
                -ResourceGroupName $publicIpParts.ResourceGroupName `
                -Name $publicIpParts.Name
            $expectedIpConfigurationPrefix = "$nicId/ipConfigurations/"
            if ([string]$publicIp.IpConfiguration.Id -notlike "$expectedIpConfigurationPrefix*") {
                throw "Public IP '$publicIpId' is not exclusively attached to NIC '$nicId'."
            }

            $ownedPublicIps += [pscustomobject]@{
                Id                = $publicIpId
                ResourceGroupName = $publicIpParts.ResourceGroupName
                Name              = $publicIpParts.Name
            }
        }
    }

    [pscustomobject]@{
        VMId      = [string]$VM.Id
        VMName    = [string]$VM.Name
        Disks     = @($ownedDisks | Sort-Object Id -Unique)
        Nics      = @($ownedNics | Sort-Object Id -Unique)
        PublicIps = @($ownedPublicIps | Sort-Object Id -Unique)
    }
}

function Test-AzureResourceAbsent {
    param([Parameter(Mandatory)][string]$ResourceId)
    return -not (Get-AzResource -ResourceId $ResourceId -ErrorAction SilentlyContinue)
}

function Update-ServerListFile {
    param(
        [Parameter(Mandatory)][object]$LoginContext,
        [Parameter(Mandatory)][string]$OriginalSubscriptionId,
        [Parameter(Mandatory)][string]$TenantId
    )

    Write-RunbookLog "Refreshing '$ServerListShareName/$ServerListPath' with all Azure VMs starting with '$VMNamePrefix'."
    $subscriptions = @(
        Get-AzSubscription -TenantId $TenantId -DefaultProfile $LoginContext |
            Where-Object State -EQ 'Enabled'
    )
    if ($subscriptions.Count -eq 0) {
        throw 'No enabled Azure subscriptions are accessible to the managed identity. ServerList.txt was not changed.'
    }

    $serverNames = @()
    foreach ($subscription in $subscriptions) {
        try {
            $subscriptionContext = Set-AzContext `
                -SubscriptionId $subscription.Id `
                -TenantId $TenantId `
                -DefaultProfile $LoginContext
            $serverNames += @(
                Get-AzVM -DefaultProfile $subscriptionContext |
                    Where-Object Name -Like "$VMNamePrefix*" |
                    Select-Object -ExpandProperty Name
            )
        }
        catch {
            Write-Warning "Could not query subscription '$($subscription.Name)': $($_.Exception.Message)"
        }
    }

    $serverNames = @(
        $serverNames |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            Sort-Object -Unique
    )

    $temporaryFile = Join-Path $env:TEMP ("ServerList-{0}.txt" -f [guid]::NewGuid())
    try {
        $content = $serverNames -join [Environment]::NewLine
        [System.IO.File]::WriteAllText(
            $temporaryFile,
            $content,
            [System.Text.UTF8Encoding]::new($false)
        )

        $storageContext = New-AzStorageContext `
            -StorageAccountName $ServerListStorageAccountName `
            -UseConnectedAccount `
            -EnableFileBackupRequestIntent
        Set-AzStorageFileContent `
            -ShareName $ServerListShareName `
            -Source $temporaryFile `
            -Path $ServerListPath `
            -Context $storageContext `
            -Force |
            Out-Null
    }
    finally {
        Remove-Item -Path $temporaryFile -Force -ErrorAction SilentlyContinue
        $script:AzureContext = Set-AzContext `
            -SubscriptionId $OriginalSubscriptionId `
            -TenantId $TenantId `
            -DefaultProfile $LoginContext
    }

    Write-RunbookLog "ServerList.txt now contains $($serverNames.Count) SRVTAPP VM(s)."
    return $serverNames
}

try {
    Write-RunbookLog 'Signing in with the Azure Automation managed identity.'
    Disable-AzContextAutosave -Scope Process | Out-Null
    $loginContext = (Connect-AzAccount -Identity).Context
    $tenantId = [string]$loginContext.Tenant.Id

    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        $SubscriptionId = [string]$loginContext.Subscription.Id
    }
    $script:AzureContext = Set-AzContext `
        -SubscriptionId $SubscriptionId `
        -TenantId $tenantId `
        -DefaultProfile $loginContext
    $script:TargetSubscriptionId = [string]$script:AzureContext.Subscription.Id
    Write-RunbookLog "Using subscription '$($script:AzureContext.Subscription.Name)' ($script:TargetSubscriptionId)."

    $null = Get-AzResourceGroup -Name $TargetResourceGroupName
    $utcNow = (Get-Date).ToUniversalTime()
    $cutoffUtc = $utcNow.AddHours(-$MinimumAgeHours)

    $prefixVMs = @(
        Get-AzVM -ResourceGroupName $TargetResourceGroupName |
            Where-Object {
                $_.Name -like "$VMNamePrefix*" -and
                $_.Name -notin $ExcludedVMNames
            }
    )

    $vmInventory = foreach ($vm in $prefixVMs) {
        $createdUtc = Get-VMCreationTimeUtc -VM $vm
        [pscustomobject]@{
            VM         = $vm
            Name       = [string]$vm.Name
            Id         = [string]$vm.Id
            CreatedUtc = $createdUtc
            AgeHours   = [math]::Round(($utcNow - $createdUtc).TotalHours, 2)
        }
    }

    $candidates = @(
        $vmInventory |
            Where-Object CreatedUtc -LE $cutoffUtc |
            Sort-Object CreatedUtc
    )

    Write-RunbookLog "Selection scope: subscription '$script:TargetSubscriptionId', resource group '$TargetResourceGroupName', prefix '$VMNamePrefix', created on or before '$($cutoffUtc.ToString('u'))'."
    if ($candidates.Count -eq 0) {
        Write-RunbookLog 'No expired SRVTAPP VMs matched. No changes are required.'
        [pscustomobject]@{
            Mode            = $ExecutionMode
            CutoffUtc       = $cutoffUtc
            CandidateCount  = 0
            CandidateNames  = @()
            Status          = 'No matching VMs'
        }
        return
    }

    if ($candidates.Count -gt $MaximumVMsPerRun) {
        throw "Safety stop: $($candidates.Count) VMs matched, exceeding MaximumVMsPerRun=$MaximumVMsPerRun. Nothing was changed."
    }

    Write-RunbookLog "Selected $($candidates.Count) VM(s):"
    foreach ($candidate in $candidates) {
        Write-RunbookLog "TARGET Name='$($candidate.Name)'; CreatedUtc='$($candidate.CreatedUtc.ToString('u'))'; AgeHours='$($candidate.AgeHours)'; Id='$($candidate.Id)'."
    }

    if ($ExecutionMode -eq 'Preview') {
        Write-RunbookLog 'Preview completed. No Citrix, AD, Azure, or ServerList changes were made.'
        [pscustomobject]@{
            Mode            = 'Preview'
            CutoffUtc       = $cutoffUtc
            CandidateCount  = $candidates.Count
            CandidateNames  = @($candidates.Name)
            Status          = 'Preview only; no changes made'
        }
        return
    }

    # Validate every dependency before performing the first destructive action.
    Write-RunbookLog "Validating domain credential asset '$DomainCredentialAssetName'."
    $domainCredential = Get-AutomationPSCredential -Name $DomainCredentialAssetName
    if (-not $domainCredential) {
        throw "Automation credential asset '$DomainCredentialAssetName' was not found."
    }

    Write-RunbookLog 'Validating Citrix DaaS credentials and configured targets.'
    $citrixCredential = Get-AutomationPSCredential -Name $CitrixCredentialAssetName
    if (-not $citrixCredential) {
        throw "Automation credential asset '$CitrixCredentialAssetName' was not found."
    }
    $citrixCustomerId = [string](Get-AutomationVariable -Name $CitrixCustomerIdVariableName)
    $citrixSiteId = [string](Get-AutomationVariable -Name $CitrixSiteIdVariableName)
    $citrixCatalogName = [string](Get-AutomationVariable -Name $CitrixMachineCatalogVariableName)
    $citrixDeliveryGroupName = [string](Get-AutomationVariable -Name $CitrixDeliveryGroupVariableName)
    $citrixApiHost = [string](Get-AutomationVariable -Name $CitrixApiHostVariableName)

    $requiredValues = @{
        $CitrixCustomerIdVariableName     = $citrixCustomerId
        $CitrixSiteIdVariableName         = $citrixSiteId
        $CitrixMachineCatalogVariableName = $citrixCatalogName
        $CitrixDeliveryGroupVariableName  = $citrixDeliveryGroupName
    }
    foreach ($entry in $requiredValues.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            throw "Automation variable '$($entry.Key)' is missing or empty."
        }
    }
    if ([string]::IsNullOrWhiteSpace($citrixApiHost)) {
        $citrixApiHost = 'api.cloud.com'
    }
    $citrixApiHost = ($citrixApiHost.Trim() -replace '^https?://', '').TrimEnd('/')

    $citrixToken = Get-CitrixAccessToken `
        -Credential $citrixCredential `
        -CustomerId $citrixCustomerId `
        -ApiHost $citrixApiHost
    $citrixHeaders = New-CitrixHeaders `
        -AccessToken $citrixToken `
        -CustomerId $citrixCustomerId `
        -SiteId $citrixSiteId

    $catalogResponse = Invoke-RestMethod `
        -Uri "https://$citrixApiHost/cvad/manage/MachineCatalogs" `
        -Method Get `
        -Headers $citrixHeaders
    $citrixCatalog = @($catalogResponse.Items) |
        Where-Object Name -EQ $citrixCatalogName |
        Select-Object -First 1
    if (-not $citrixCatalog) {
        throw "Citrix machine catalog '$citrixCatalogName' was not found."
    }

    $deliveryGroupResponse = Invoke-RestMethod `
        -Uri "https://$citrixApiHost/cvad/manage/DeliveryGroups" `
        -Method Get `
        -Headers $citrixHeaders
    $citrixDeliveryGroup = @($deliveryGroupResponse.Items) |
        Where-Object Name -EQ $citrixDeliveryGroupName |
        Select-Object -First 1
    if (-not $citrixDeliveryGroup) {
        throw "Citrix Delivery Group '$citrixDeliveryGroupName' was not found."
    }

    $citrixMachines = @{}
    foreach ($candidate in $candidates) {
        $citrixMachineName = "$DomainNetBIOSName\$($candidate.Name)"
        $machine = Get-CitrixMachine `
            -MachineName $citrixMachineName `
            -ApiHost $citrixApiHost `
            -Headers $citrixHeaders
        if (-not $machine) {
            Write-RunbookLog "Citrix machine '$citrixMachineName' is already absent."
            continue
        }
        if ([string]$machine.MachineCatalog.Name -ne $citrixCatalogName) {
            throw "Safety stop: Citrix machine '$citrixMachineName' is in catalog '$($machine.MachineCatalog.Name)', not '$citrixCatalogName'."
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$machine.DeliveryGroup.Name) -and
            [string]$machine.DeliveryGroup.Name -ne $citrixDeliveryGroupName) {
            throw "Safety stop: Citrix machine '$citrixMachineName' is in Delivery Group '$($machine.DeliveryGroup.Name)', not '$citrixDeliveryGroupName'."
        }
        if ([int]$machine.SessionCount -gt 0) {
            Write-RunbookLog "Citrix machine '$citrixMachineName' has $($machine.SessionCount) session(s); they will be force-logged off before deletion."
        }
        $citrixMachines[$candidate.Name] = $machine
    }

    # Snapshot and validate resource ownership before any VM is removed.
    $ownedResources = @{}
    foreach ($candidate in $candidates) {
        $ownedResources[$candidate.Name] = Get-OwnedVMResources -VM $candidate.VM
    }

    # Prove that an AD-capable guest command path exists before changing Citrix.
    # The proxy must itself be one of the selected deletion candidates.
    $candidateNames = @($candidates.Name)
    $proxyVM = $null
    $proxyStartedByRunbook = $false
    $proxySearchOrder = @(
        $candidates |
            Sort-Object CreatedUtc -Descending
    )

    foreach ($possibleProxy in $proxySearchOrder) {
        $powerState = Get-AzVMPowerState `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $possibleProxy.Name
        Write-RunbookLog "AD proxy candidate '$($possibleProxy.Name)' power state: '$powerState'."
        if ($powerState -ne 'VM running') {
            continue
        }

        try {
            Wait-AzVMGuestAgent `
                -ResourceGroupName $TargetResourceGroupName `
                -VMName $possibleProxy.Name `
                -TimeoutMinutes $GuestAgentWaitMinutes
            $proxyVM = $possibleProxy
            break
        }
        catch {
            Write-Warning "Running VM '$($possibleProxy.Name)' cannot be used as the AD proxy: $($_.Exception.Message)"
        }
    }

    if (-not $proxyVM) {
        foreach ($possibleProxy in ($candidates | Sort-Object CreatedUtc -Descending)) {
            $powerState = Get-AzVMPowerState `
                -ResourceGroupName $TargetResourceGroupName `
                -VMName $possibleProxy.Name
            if ($powerState -eq 'VM running') {
                continue
            }

            Write-RunbookLog "No usable deletion candidate is running. Starting newest available candidate '$($possibleProxy.Name)' temporarily for AD cleanup."
            Start-AzVM `
                -ResourceGroupName $TargetResourceGroupName `
                -Name $possibleProxy.Name |
                Out-Null
            Wait-AzVMGuestAgent `
                -ResourceGroupName $TargetResourceGroupName `
                -VMName $possibleProxy.Name `
                -TimeoutMinutes $GuestAgentWaitMinutes
            $proxyVM = $possibleProxy
            $proxyStartedByRunbook = $true
            break
        }
    }

    if (-not $proxyVM) {
        throw 'No selected deletion candidate has a usable Azure VM Agent, and no stopped candidate was available to start as the AD proxy.'
    }
    Write-RunbookLog "Validated '$($proxyVM.Name)' as the Active Directory cleanup proxy."

    $forcedLogoffSessionCount = 0
    Write-RunbookLog 'Phase 1/6: placing selected Citrix machines in maintenance mode and requesting forced session logoff.'
    foreach ($candidate in $candidates) {
        if (-not $citrixMachines.ContainsKey($candidate.Name)) {
            continue
        }

        $citrixMachineName = "$DomainNetBIOSName\$($candidate.Name)"
        $machine = Get-CitrixMachine `
            -MachineName $citrixMachineName `
            -ApiHost $citrixApiHost `
            -Headers $citrixHeaders
        if (-not $machine) {
            Write-RunbookLog "Citrix machine '$citrixMachineName' is already absent."
            continue
        }

        $machineId = [uri]::EscapeDataString([string]$machine.Id)
        if (-not [bool]$machine.InMaintenanceMode) {
            $maintenanceBody = @{
                InMaintenanceMode = $true
            } | ConvertTo-Json
            Invoke-RestMethod `
                -Uri "https://$citrixApiHost/cvad/manage/Machines/$machineId" `
                -Method Patch `
                -Headers $citrixHeaders `
                -Body $maintenanceBody |
                Out-Null
            Wait-CitrixMachineCondition `
                -MachineName $citrixMachineName `
                -Condition InMaintenanceMode `
                -ApiHost $citrixApiHost `
                -Headers $citrixHeaders `
                -TimeoutMinutes $CitrixWaitMinutes
            Write-RunbookLog "Citrix machine '$citrixMachineName' is in maintenance mode."
        }
        else {
            Write-RunbookLog "Citrix machine '$citrixMachineName' is already in maintenance mode."
        }

        $machine = Get-CitrixMachine `
            -MachineName $citrixMachineName `
            -ApiHost $citrixApiHost `
            -Headers $citrixHeaders
        $sessionCount = [int]$machine.SessionCount
        if ($sessionCount -gt 0) {
            $forcedLogoffSessionCount += $sessionCount
            Write-RunbookLog "Force-logging off $sessionCount Citrix session(s) from '$citrixMachineName'."
            Invoke-RestMethod `
                -Uri "https://$citrixApiHost/cvad/manage/Machines/$machineId/`$logoff?detailResponseRequired=false&async=false" `
                -Method Post `
                -Headers $citrixHeaders |
                Out-Null
            Write-RunbookLog "Forced logoff was submitted for '$citrixMachineName'. Continuing without waiting for SessionCount to reach zero."
        }
        else {
            Write-RunbookLog "Citrix machine '$citrixMachineName' has no sessions."
        }
    }

    Write-RunbookLog 'Phase 2/6: removing selected machines from the Citrix Delivery Group.'
    foreach ($candidate in $candidates) {
        if (-not $citrixMachines.ContainsKey($candidate.Name)) {
            continue
        }
        $machine = $citrixMachines[$candidate.Name]
        $citrixMachineName = "$DomainNetBIOSName\$($candidate.Name)"
        if ([string]::IsNullOrWhiteSpace([string]$machine.DeliveryGroup.Name)) {
            Write-RunbookLog "Citrix machine '$citrixMachineName' is already outside a Delivery Group."
            continue
        }

        $deliveryGroupId = [uri]::EscapeDataString([string]$citrixDeliveryGroup.Id)
        $machineId = [uri]::EscapeDataString([string]$machine.Id)
        Invoke-RestMethod `
            -Uri "https://$citrixApiHost/cvad/manage/DeliveryGroups/$deliveryGroupId/Machines/$machineId" `
            -Method Delete `
            -Headers $citrixHeaders |
            Out-Null
        Wait-CitrixMachineCondition `
            -MachineName $citrixMachineName `
            -Condition NotInDeliveryGroup `
            -ApiHost $citrixApiHost `
            -Headers $citrixHeaders `
            -TimeoutMinutes $CitrixWaitMinutes
        Write-RunbookLog "Removed '$citrixMachineName' from Delivery Group '$citrixDeliveryGroupName'."
    }

    Write-RunbookLog 'Phase 3/6: removing selected machines from the Citrix machine catalog.'
    foreach ($candidate in $candidates) {
        if (-not $citrixMachines.ContainsKey($candidate.Name)) {
            continue
        }
        $citrixMachineName = "$DomainNetBIOSName\$($candidate.Name)"
        $machine = Get-CitrixMachine `
            -MachineName $citrixMachineName `
            -ApiHost $citrixApiHost `
            -Headers $citrixHeaders
        if (-not $machine) {
            Write-RunbookLog "Citrix machine '$citrixMachineName' is already absent."
            continue
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$machine.DeliveryGroup.Name)) {
            throw "Citrix machine '$citrixMachineName' still belongs to Delivery Group '$($machine.DeliveryGroup.Name)'."
        }

        $catalogId = [uri]::EscapeDataString([string]$citrixCatalog.Id)
        $machineId = [uri]::EscapeDataString([string]$machine.Id)
        Invoke-RestMethod `
            -Uri "https://$citrixApiHost/cvad/manage/MachineCatalogs/$catalogId/Machines/$machineId" `
            -Method Delete `
            -Headers $citrixHeaders |
            Out-Null
        Wait-CitrixMachineCondition `
            -MachineName $citrixMachineName `
            -Condition Absent `
            -ApiHost $citrixApiHost `
            -Headers $citrixHeaders `
            -TimeoutMinutes $CitrixWaitMinutes
        Write-RunbookLog "Removed '$citrixMachineName' from machine catalog '$citrixCatalogName'."
    }

    $citrixToken = $null
    $citrixHeaders = $null

    Write-RunbookLog "Phase 4/6: deleting Active Directory computer objects through proxy '$($proxyVM.Name)'."

    $domainUserName = [string]$domainCredential.UserName
    if ($domainUserName -notmatch '[@\\]') {
        $domainUserName = "$DomainNetBIOSName\$domainUserName"
    }
    $domainPassword = $domainCredential.GetNetworkCredential().Password

    # Delete the proxy's own AD object last if it is also a deletion target.
    $orderedADComputerNames = @(
        $candidateNames | Where-Object { $_ -ine $proxyVM.Name }
    )
    if ($proxyVM.Name -in $candidateNames) {
        $orderedADComputerNames += $proxyVM.Name
    }

$deleteADScript = @'
param(
    [Parameter(Mandatory)][string]$ComputerNamesJson,
    [Parameter(Mandatory)][string]$DomainName,
    [Parameter(Mandatory)][string]$DomainUserName,
    [Parameter(Mandatory)][string]$DomainPassword
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices

function Escape-LdapFilterValue {
    param([Parameter(Mandatory)][string]$Value)
    $builder = [System.Text.StringBuilder]::new()
    foreach ($character in $Value.ToCharArray()) {
        switch ([int][char]$character) {
            0      { [void]$builder.Append('\00') }
            40     { [void]$builder.Append('\28') }
            41     { [void]$builder.Append('\29') }
            42     { [void]$builder.Append('\2a') }
            92     { [void]$builder.Append('\5c') }
            default { [void]$builder.Append($character) }
        }
    }
    return $builder.ToString()
}

function Find-ComputerObject {
    param(
        [Parameter(Mandatory)][System.DirectoryServices.DirectoryEntry]$SearchRoot,
        [Parameter(Mandatory)][string]$ComputerName
    )
    $escapedSamAccountName = Escape-LdapFilterValue -Value "$ComputerName`$"
    $searcher = [System.DirectoryServices.DirectorySearcher]::new($SearchRoot)
    try {
        $searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=$escapedSamAccountName))"
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.PageSize = 1000
        return $searcher.FindOne()
    }
    finally {
        $searcher.Dispose()
    }
}

try {
    $decodedComputerNames = ConvertFrom-Json -InputObject $ComputerNamesJson
    $computerNames = @(
        $decodedComputerNames |
            ForEach-Object { [string]$_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )
    if ($computerNames.Count -eq 0) {
        throw 'No AD computer names were supplied.'
    }
    $invalidComputerNames = @(
        $computerNames |
            Where-Object { $_ -notmatch '^SRVTAPP[A-Za-z0-9-]*$' }
    )
    if ($invalidComputerNames.Count -gt 0) {
        throw "Refusing unexpected AD computer name(s): $($invalidComputerNames -join ', ')."
    }

    $dcRecord = Resolve-DnsName `
        -Name "_ldap._tcp.dc._msdcs.$DomainName" `
        -Type SRV `
        -ErrorAction Stop |
        Sort-Object Priority, Weight |
        Select-Object -First 1
    $domainController = ([string]$dcRecord.NameTarget).TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($domainController)) {
        throw "No domain controller was found for '$DomainName'."
    }

    $authenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::Signing -bor [System.DirectoryServices.AuthenticationTypes]::Sealing
    $rootDse = [System.DirectoryServices.DirectoryEntry]::new(
        "LDAP://$domainController/RootDSE",
        $DomainUserName,
        $DomainPassword,
        $authenticationType
    )
    $defaultNamingContext = [string]$rootDse.Properties['defaultNamingContext'][0]
    $rootDse.Dispose()
    if ([string]::IsNullOrWhiteSpace($defaultNamingContext)) {
        throw "Domain controller '$domainController' did not return a default naming context."
    }

    $searchRoot = [System.DirectoryServices.DirectoryEntry]::new(
        "LDAP://$domainController/$defaultNamingContext",
        $DomainUserName,
        $DomainPassword,
        $authenticationType
    )
    try {
        foreach ($computerName in $computerNames) {
            $result = Find-ComputerObject -SearchRoot $searchRoot -ComputerName $computerName
            if (-not $result) {
                Write-Output "AD_ABSENT=$computerName"
                continue
            }

            $computerEntry = [System.DirectoryServices.DirectoryEntry]::new(
                $result.Path,
                $DomainUserName,
                $DomainPassword,
                $authenticationType
            )
            try {
                $computerEntry.DeleteTree()
            }
            finally {
                $computerEntry.Dispose()
            }

            $verificationResult = Find-ComputerObject -SearchRoot $searchRoot -ComputerName $computerName
            if ($verificationResult) {
                throw "AD computer object '$computerName' still exists after deletion."
            }
            Write-Output "AD_DELETED=$computerName"
        }
    }
    finally {
        $searchRoot.Dispose()
    }

    Write-Output "DOMAIN_CONTROLLER=$domainController"
    exit 0
}
catch {
    Write-Error "Active Directory cleanup failed: $($_.Exception.Message)"
    exit 1
}
'@

    $adParameters = @(
        @{
            Name  = 'ComputerNamesJson'
            Value = (ConvertTo-Json -InputObject ([string[]]$orderedADComputerNames) -Compress)
        },
        @{
            Name  = 'DomainName'
            Value = $DomainName
        },
        @{
            Name  = 'DomainUserName'
            Value = $domainUserName
        }
    )
    $protectedADParameters = @(
        @{
            Name  = 'DomainPassword'
            Value = $domainPassword
        }
    )

    $adRunCommandName = 'DeleteExpiredADComputerObjects'
    $null = Set-AzVMRunCommand `
        -ResourceGroupName $TargetResourceGroupName `
        -VMName $proxyVM.Name `
        -RunCommandName $adRunCommandName `
        -Location $proxyVM.VM.Location `
        -SourceScript $deleteADScript `
        -Parameter $adParameters `
        -ProtectedParameter $protectedADParameters `
        -TimeoutInSecond 900

    $domainPassword = $null
    $protectedADParameters = $null
    $adCommand = Get-AzVMRunCommand `
        -ResourceGroupName $TargetResourceGroupName `
        -VMName $proxyVM.Name `
        -RunCommandName $adRunCommandName `
        -Expand InstanceView
    $adOutput = [string]$adCommand.InstanceView.Output
    if (-not [string]::IsNullOrWhiteSpace($adOutput)) {
        Write-RunbookLog "AD cleanup guest output: $adOutput"
    }
    if ($adCommand.InstanceView.ExecutionState -ne 'Succeeded' -or
        $adCommand.InstanceView.ExitCode -ne 0) {
        throw "AD cleanup failed on proxy '$($proxyVM.Name)'. ExecutionState='$($adCommand.InstanceView.ExecutionState)'; ExitCode='$($adCommand.InstanceView.ExitCode)'; Guest error: $($adCommand.InstanceView.Error)"
    }
    Write-RunbookLog "Active Directory cleanup succeeded through proxy '$($proxyVM.Name)'."

    Write-RunbookLog 'Phase 5/6: gracefully stopping and deallocating selected Azure VMs.'
    foreach ($candidate in $candidates) {
        $powerState = Get-AzVMPowerState `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $candidate.Name
        if ($powerState -ne 'VM deallocated') {
            Write-RunbookLog "Stopping VM '$($candidate.Name)' from state '$powerState'."
            Stop-AzVM `
                -ResourceGroupName $TargetResourceGroupName `
                -Name $candidate.Name `
                -Force |
                Out-Null
        }
        else {
            Write-RunbookLog "VM '$($candidate.Name)' is already deallocated."
        }
    }

    Write-RunbookLog 'Phase 6/6: deleting Azure VMs and exclusively owned resources.'
    $deletedDiskCount = 0
    $deletedNicCount = 0
    $deletedPublicIpCount = 0
    foreach ($candidate in $candidates) {
        Write-RunbookLog "Deleting Azure VM '$($candidate.Name)'."
        Remove-AzVM `
            -ResourceGroupName $TargetResourceGroupName `
            -Name $candidate.Name `
            -ForceDeletion $true `
            -Force |
            Out-Null

        if (Get-AzVM -ResourceGroupName $TargetResourceGroupName -Name $candidate.Name -ErrorAction SilentlyContinue) {
            throw "Azure VM '$($candidate.Name)' still exists after deletion."
        }

        $resources = $ownedResources[$candidate.Name]
        foreach ($nic in $resources.Nics) {
            if (-not (Test-AzureResourceAbsent -ResourceId $nic.Id)) {
                Remove-AzNetworkInterface `
                    -ResourceGroupName $nic.ResourceGroupName `
                    -Name $nic.Name `
                    -Force |
                    Out-Null
            }
            if (-not (Test-AzureResourceAbsent -ResourceId $nic.Id)) {
                throw "NIC '$($nic.Id)' still exists after deletion."
            }
            $deletedNicCount++
        }

        foreach ($publicIp in $resources.PublicIps) {
            if (-not (Test-AzureResourceAbsent -ResourceId $publicIp.Id)) {
                Remove-AzPublicIpAddress `
                    -ResourceGroupName $publicIp.ResourceGroupName `
                    -Name $publicIp.Name `
                    -Force |
                    Out-Null
            }
            if (-not (Test-AzureResourceAbsent -ResourceId $publicIp.Id)) {
                throw "Public IP '$($publicIp.Id)' still exists after deletion."
            }
            $deletedPublicIpCount++
        }

        foreach ($disk in $resources.Disks) {
            if (-not (Test-AzureResourceAbsent -ResourceId $disk.Id)) {
                Remove-AzDisk `
                    -ResourceGroupName $disk.ResourceGroupName `
                    -DiskName $disk.Name `
                    -Force |
                    Out-Null
            }
            if (-not (Test-AzureResourceAbsent -ResourceId $disk.Id)) {
                throw "Managed disk '$($disk.Id)' still exists after deletion."
            }
            $deletedDiskCount++
        }

        Write-RunbookLog "Azure cleanup completed for '$($candidate.Name)'."
    }

    $remainingServers = Update-ServerListFile `
        -LoginContext $loginContext `
        -OriginalSubscriptionId $script:TargetSubscriptionId `
        -TenantId $tenantId

    [pscustomobject]@{
        Mode                    = 'Execute'
        CutoffUtc               = $cutoffUtc
        DeletedVMCount          = $candidates.Count
        DeletedVMNames          = @($candidates.Name)
        ADProxyVM               = $proxyVM.Name
        ADProxyStartedByRunbook = $proxyStartedByRunbook
        ForcedLogoffSessions    = $forcedLogoffSessionCount
        DeletedDiskCount        = $deletedDiskCount
        DeletedNICCount         = $deletedNicCount
        DeletedPublicIPCount    = $deletedPublicIpCount
        RemainingServerList     = @($remainingServers)
        Status                  = 'Completed'
    }
}
catch {
    Write-Error "SRVTAPP cleanup runbook failed: $($_.Exception.Message)"
    throw
}
