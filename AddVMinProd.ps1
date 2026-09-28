#Requires -Version 7.2
#Requires -Modules Az.Accounts, Az.Compute, Az.Network, Az.RecoveryServices, Az.Resources, Az.Storage

<#
.SYNOPSIS
    Restores SRVCTXNOAD, configures Windows, and registers it in Citrix DaaS.

.DESCRIPTION
    Designed for an Azure Automation PowerShell 7.2 runbook using the
    Automation Account's system-assigned managed identity.

    Target:
      Recovery Services vault : VAULTSAGE300
      Source protected VM     : SRVCTXNOAD
      Target resource group   : sage300
      Target VNet/subnet      : accpac/default
      Staging storage account : accpac
      New VM name             : SRVTAPPddHHmmss (GMT+4, Windows-compatible)

    After the restore, the runbook renames the Windows computer while it is
    still in a workgroup, restarts and verifies the active hostname, then joins
    oilibya.com without combining the join with a rename. It restarts again and
    verifies the final guest configuration. It then adds the exact restored
    machine to the configured Citrix DaaS manual machine catalog and Delivery
    Group and waits for the VDA to register. The source VM is not replaced or
    modified.
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$RecoveryServicesVaultName = 'VAULTSAGE300',
    [string]$SourceVMName = 'SRVCTXNOAD',
    [string]$TargetResourceGroupName = 'sage300',
    [string]$TargetVNetName = 'accpac',
    [string]$TargetVNetResourceGroupName = 'sage300',
    [string]$TargetSubnetName = 'default',
    [string]$StagingStorageAccountName = 'accpac',
    [string]$StagingStorageResourceGroupName = 'sage300',
    [string]$DomainName = 'oilibya.com',
    [string]$DomainNetBIOSName = 'OILIBYA',
    [string]$DomainCredentialAssetName = 'PnPAccount',
    [string]$DomainOUPath,
    [string]$ComputerDescription,
    [string]$CitrixCredentialAssetName = 'CitrixApiClient',
    [string]$CitrixCustomerIdVariableName = 'CitrixCustomerId',
    [string]$CitrixSiteIdVariableName = 'CitrixSiteId',
    [string]$CitrixMachineCatalogVariableName = 'CitrixMachineCatalog',
    [string]$CitrixDeliveryGroupVariableName = 'CitrixDeliveryGroup',
    [string]$CitrixApiHostVariableName = 'CitrixApiHost',
    [ValidateRange(1, 60)]
    [int]$CitrixRegistrationWaitMinutes = 20,
    [ValidateRange(1, 3650)]
    [int]$RecoveryPointLookbackDays = 30,
    [ValidateRange(1, 24)]
    [int]$MaximumWaitHours = 2
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-RunbookLog {
    param([Parameter(Mandatory)][string]$Message)
    Write-Output ('[{0:u}] {1}' -f (Get-Date).ToUniversalTime(), $Message)
}

function Wait-AzVMGuestAgent {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$VMName,
        [ValidateRange(1, 60)]
        [int]$TimeoutMinutes = 20,
        [ValidateRange(0, 300)]
        [int]$InitialDelaySeconds = 0
    )

    if ($InitialDelaySeconds -gt 0) {
        Start-Sleep -Seconds $InitialDelaySeconds
    }

    $deadline = (Get-Date).ToUniversalTime().AddMinutes($TimeoutMinutes)

    do {
        $vmWithStatus = Get-AzVM `
            -ResourceGroupName $ResourceGroupName `
            -Name $VMName `
            -Status

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
    if ([string]::IsNullOrWhiteSpace($tokenResponse.access_token)) {
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

    # Do not put DOMAIN\MACHINE directly in a URI path. Some Citrix gateways
    # do not consistently resolve the encoded backslash. The supported search
    # endpoint handles domain-qualified machine names reliably.
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

function Wait-CitrixJob {
    param(
        [Parameter(Mandatory)][object]$Job,
        [Parameter(Mandatory)][string]$ApiHost,
        [Parameter(Mandatory)][hashtable]$Headers,
        [int]$TimeoutMinutes = 20
    )

    if ([string]::IsNullOrWhiteSpace([string]$Job.Id)) {
        throw "Citrix returned a catalog-operation response without a job ID: $($Job | ConvertTo-Json -Depth 6 -Compress)"
    }

    $deadline = (Get-Date).ToUniversalTime().AddMinutes($TimeoutMinutes)
    $currentJob = $Job
    $terminalStates = @('Complete', 'CompleteWithWarning', 'Failed', 'Canceled', 'NonTerminatingError')

    do {
        Write-RunbookLog "Citrix job '$($currentJob.Id)' status: '$($currentJob.Status)'."
        if ($currentJob.Status -in $terminalStates) {
            break
        }

        Start-Sleep -Seconds 10
        $jobId = [uri]::EscapeDataString([string]$currentJob.Id)
        $currentJob = Invoke-RestMethod `
            -Uri "https://$ApiHost/cvad/manage/Jobs/$jobId" `
            -Method Get `
            -Headers $Headers
    } while ((Get-Date).ToUniversalTime() -lt $deadline)

    if ($currentJob.Status -notin @('Complete', 'CompleteWithWarning')) {
        $errorDetails = @(
            $currentJob.ErrorString
            $currentJob.ErrorCode
            (@($currentJob.ErrorParameters | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ')
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }

        if ($currentJob.Status -notin $terminalStates) {
            throw "Citrix job '$($currentJob.Id)' did not finish within $TimeoutMinutes minutes. Last status: '$($currentJob.Status)'."
        }
        throw "Citrix job '$($currentJob.Id)' failed with status '$($currentJob.Status)'. $($errorDetails -join ' | ')"
    }

    return $currentJob
}

try {
    Disable-AzContextAutosave -Scope Process | Out-Null

    Write-RunbookLog 'Signing in with the Azure Automation managed identity.'
    $context = (Connect-AzAccount -Identity).Context

    if ($SubscriptionId) {
        $context = Set-AzContext -SubscriptionId $SubscriptionId
    }

    Write-RunbookLog "Using subscription '$($context.Subscription.Name)' ($($context.Subscription.Id))."

    # Resolve and validate all target resources before starting the restore.
    $vaultMatches = @(
        Get-AzRecoveryServicesVault |
            Where-Object Name -EQ $RecoveryServicesVaultName
    )

    if ($vaultMatches.Count -eq 0) {
        throw "Recovery Services vault '$RecoveryServicesVaultName' was not found in subscription '$($context.Subscription.Id)'."
    }
    if ($vaultMatches.Count -gt 1) {
        throw "More than one vault named '$RecoveryServicesVaultName' was found. Specify the correct subscription with -SubscriptionId."
    }
    $vault = $vaultMatches[0]

    $targetResourceGroup = Get-AzResourceGroup -Name $TargetResourceGroupName
    $vnet = Get-AzVirtualNetwork `
        -Name $TargetVNetName `
        -ResourceGroupName $TargetVNetResourceGroupName

    if ($TargetSubnetName -notin $vnet.Subnets.Name) {
        throw "Subnet '$TargetSubnetName' does not exist in VNet '$TargetVNetName'."
    }

    $storageAccount = Get-AzStorageAccount `
        -Name $StagingStorageAccountName `
        -ResourceGroupName $StagingStorageResourceGroupName

    if ($storageAccount.Sku.Name -ne 'Standard_LRS') {
        throw "Staging account '$StagingStorageAccountName' uses '$($storageAccount.Sku.Name)', not Standard_LRS."
    }

    if ($vault.Location -ne $targetResourceGroup.Location) {
        throw "Vault location '$($vault.Location)' and target resource-group location '$($targetResourceGroup.Location)' differ."
    }

    Write-RunbookLog "Validating Automation credential asset '$DomainCredentialAssetName'."
    $domainCredential = Get-AutomationPSCredential -Name $DomainCredentialAssetName
    if (-not $domainCredential) {
        throw "Automation credential asset '$DomainCredentialAssetName' was not found. No restore was started."
    }

    # Validate Citrix authentication and all target objects before creating a VM.
    Write-RunbookLog 'Validating Citrix DaaS Automation assets and targets.'
    $citrixCredential = Get-AutomationPSCredential -Name $CitrixCredentialAssetName
    if (-not $citrixCredential) {
        throw "Automation credential asset '$CitrixCredentialAssetName' was not found. No restore was started."
    }

    $citrixCustomerId = Get-AutomationVariable -Name $CitrixCustomerIdVariableName
    $citrixSiteId = Get-AutomationVariable -Name $CitrixSiteIdVariableName
    $citrixCatalogName = Get-AutomationVariable -Name $CitrixMachineCatalogVariableName
    $citrixDeliveryGroupName = Get-AutomationVariable -Name $CitrixDeliveryGroupVariableName
    $citrixApiHost = Get-AutomationVariable -Name $CitrixApiHostVariableName

    $requiredCitrixValues = @{
        $CitrixCustomerIdVariableName     = $citrixCustomerId
        $CitrixSiteIdVariableName         = $citrixSiteId
        $CitrixMachineCatalogVariableName = $citrixCatalogName
        $CitrixDeliveryGroupVariableName  = $citrixDeliveryGroupName
    }
    foreach ($entry in $requiredCitrixValues.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            throw "Automation variable '$($entry.Key)' is missing or empty. No restore was started."
        }
    }

    if ([string]::IsNullOrWhiteSpace($citrixApiHost)) {
        $citrixApiHost = 'api.cloud.com'
    }
    $citrixApiHost = ([string]$citrixApiHost).Trim() -replace '^https?://', ''
    $citrixApiHost = $citrixApiHost.TrimEnd('/')

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
        throw "Citrix machine catalog '$citrixCatalogName' was not found. No restore was started."
    }
    if ($citrixCatalog.ProvisioningType -ne 'Manual') {
        throw "Citrix catalog '$citrixCatalogName' has provisioning type '$($citrixCatalog.ProvisioningType)'. This restore workflow requires a Manual catalog."
    }

    $citrixHypervisorConnection = $null
    if ($citrixCatalog.IsPowerManaged) {
        $catalogUriName = [uri]::EscapeDataString([string]$citrixCatalog.Id)
        $catalogMachines = Invoke-RestMethod `
            -Uri "https://$citrixApiHost/cvad/manage/MachineCatalogs/$catalogUriName/Machines?limit=1000&fields=Name%2CHosting" `
            -Method Get `
            -Headers $citrixHeaders

        $referenceMachine = @($catalogMachines.Items) |
            Where-Object {
                (-not [string]::IsNullOrWhiteSpace([string]$_.Hosting.HypervisorConnection.Id) -or
                 -not [string]::IsNullOrWhiteSpace([string]$_.Hosting.HypervisorConnection.Name)) -and
                -not [string]::IsNullOrWhiteSpace([string]$_.Hosting.HostedMachineId)
            } |
            Select-Object -First 1

        if (-not $referenceMachine) {
            throw "Catalog '$citrixCatalogName' is power-managed, but no existing catalog machine exposed its Hypervisor Connection."
        }

        $citrixHypervisorConnection = if ($referenceMachine.Hosting.HypervisorConnection.Id) {
            [string]$referenceMachine.Hosting.HypervisorConnection.Id
        }
        else {
            [string]$referenceMachine.Hosting.HypervisorConnection.Name
        }
        $citrixHostedMachineIdSample = [string]$referenceMachine.Hosting.HostedMachineId
        Write-RunbookLog "Power-managed Citrix catalog detected. Hypervisor connection: '$citrixHypervisorConnection'; HostedMachineId sample format: '$citrixHostedMachineIdSample'."
    }

    $deliveryGroupResponse = Invoke-RestMethod `
        -Uri "https://$citrixApiHost/cvad/manage/DeliveryGroups" `
        -Method Get `
        -Headers $citrixHeaders
    $citrixDeliveryGroup = @($deliveryGroupResponse.Items) |
        Where-Object Name -EQ $citrixDeliveryGroupName |
        Select-Object -First 1
    if (-not $citrixDeliveryGroup) {
        throw "Citrix Delivery Group '$citrixDeliveryGroupName' was not found. No restore was started."
    }

    Write-RunbookLog "Citrix targets validated: catalog '$citrixCatalogName'; Delivery Group '$citrixDeliveryGroupName'."
    $citrixToken = $null
    $citrixHeaders = $null

    Write-RunbookLog "Searching vault '$RecoveryServicesVaultName' for protected VM '$SourceVMName'."

    $allBackupItems = @(
        Get-AzRecoveryServicesBackupItem `
            -BackupManagementType AzureVM `
            -WorkloadType AzureVM `
            -VaultId $vault.ID
    )

    # Azure Backup can expose the VM as a friendly name, a resource ID, or an
    # internal semicolon-delimited item/container name. Match all known forms.
    $escapedSourceVMName = [regex]::Escape($SourceVMName)
    $backupItems = @(
        $allBackupItems | Where-Object {
            $candidateValues = @(
                $_.Name
                $_.FriendlyName
                $_.ContainerName
                $_.VirtualMachineId
                $_.SourceResourceId
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }

            @(
                $candidateValues | Where-Object {
                    [string]$_ -eq $SourceVMName -or
                    [string]$_ -match "(?i)(^|[;/])$escapedSourceVMName$"
                }
            ).Count -gt 0
        }
    )

    if ($backupItems.Count -eq 0) {
        $availableItems = @(
            $allBackupItems | ForEach-Object {
                $displayName = if ($_.FriendlyName) {
                    $_.FriendlyName
                }
                elseif ($_.VirtualMachineId) {
                    ([string]$_.VirtualMachineId -split '/')[-1]
                }
                else {
                    $_.Name
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$displayName)) {
                    [string]$displayName
                }
            } | Sort-Object -Unique
        )

        $availableText = if ($availableItems.Count -gt 0) {
            $availableItems -join ', '
        }
        else {
            '<the vault returned no protected Azure VM items>'
        }

        throw "No protected Azure VM matching '$SourceVMName' was found in vault '$RecoveryServicesVaultName'. Items returned by the vault: $availableText"
    }
    if ($backupItems.Count -gt 1) {
        throw "Multiple protected items matched '$SourceVMName'. Remove stale/duplicate backup items or make the selection more specific."
    }
    $backupItem = $backupItems[0]

    $endTime = (Get-Date).ToUniversalTime()
    $startTime = $endTime.AddDays(-$RecoveryPointLookbackDays)

    Write-RunbookLog "Finding the latest recovery point from the last $RecoveryPointLookbackDays days."
    $recoveryPoints = @(
        Get-AzRecoveryServicesBackupRecoveryPoint `
            -Item $backupItem `
            -StartDate $startTime `
            -EndDate $endTime `
            -VaultId $vault.ID
    )

    if ($recoveryPoints.Count -eq 0) {
        throw "No recovery point was found for '$SourceVMName' between $startTime and $endTime."
    }

    $latestRecoveryPoint = $recoveryPoints |
        Sort-Object RecoveryPointTime -Descending |
        Select-Object -First 1

    # Keep the Azure VM and Windows computer names identical. Windows computer
    # names are limited to 15 characters, so use a compact GMT+4 timestamp.
    $newVMName = 'SRVTAPP{0}' -f (Get-Date).ToUniversalTime().AddHours(4).ToString('ddHHmmss')

    if (Get-AzVM -ResourceGroupName $TargetResourceGroupName -Name $newVMName -ErrorAction SilentlyContinue) {
        throw "A VM named '$newVMName' already exists."
    }

    Write-RunbookLog "Latest recovery point: $($latestRecoveryPoint.RecoveryPointTime.ToUniversalTime().ToString('u'))."
    Write-RunbookLog "Starting alternate-location restore as new VM '$newVMName'."

    $restoreJob = Restore-AzRecoveryServicesBackupItem `
        -RecoveryPoint $latestRecoveryPoint `
        -StorageAccountName $StagingStorageAccountName `
        -StorageAccountResourceGroupName $StagingStorageResourceGroupName `
        -TargetResourceGroupName $TargetResourceGroupName `
        -TargetVMName $newVMName `
        -TargetVNetName $TargetVNetName `
        -TargetVNetResourceGroup $TargetVNetResourceGroupName `
        -TargetSubnetName $TargetSubnetName `
        -VaultId $vault.ID `
        -VaultLocation $vault.Location

    Write-RunbookLog "Restore submitted. Job ID: $($restoreJob.JobId)"

    $deadline = (Get-Date).ToUniversalTime().AddHours($MaximumWaitHours)
    do {
        Start-Sleep -Seconds 30
        $job = Get-AzRecoveryServicesBackupJob `
            -Job $restoreJob `
            -VaultId $vault.ID

        Write-RunbookLog "Restore status: $($job.Status)"

        if ($job.Status -in @('Completed', 'CompletedWithWarnings', 'Failed', 'Cancelled')) {
            break
        }
    } while ((Get-Date).ToUniversalTime() -lt $deadline)

    if ($job.Status -eq 'Completed') {
        $restoredVM = Get-AzVM `
            -ResourceGroupName $TargetResourceGroupName `
            -Name $newVMName `
            -ErrorAction SilentlyContinue

        if (-not $restoredVM) {
            throw "Azure Backup reports completion, but VM '$newVMName' could not be found."
        }

        Write-RunbookLog "Restore completed successfully. New VM: '$newVMName'."

        if ($newVMName.Length -gt 15) {
            throw "New VM name '$newVMName' exceeds the Windows 15-character computer-name limit."
        }

        $domainUserName = [string]$domainCredential.UserName
        if ($domainUserName -notmatch '[@\\]') {
            $domainUserName = "$domainUserName@$DomainName"
        }
        Write-RunbookLog "Using domain credential username '$domainUserName'."
        $effectiveComputerDescription = if ([string]::IsNullOrWhiteSpace($ComputerDescription)) {
            $newVMName
        }
        else {
            $ComputerDescription
        }

        # Ensure the restored VM is running.
        $vmWithStatus = Get-AzVM `
            -ResourceGroupName $TargetResourceGroupName `
            -Name $newVMName `
            -Status
        $powerState = ($vmWithStatus.Statuses | Where-Object Code -Like 'PowerState/*').DisplayStatus

        if ($powerState -ne 'VM running') {
            Write-RunbookLog "Starting restored VM '$newVMName'."
            Start-AzVM `
                -ResourceGroupName $TargetResourceGroupName `
                -Name $newVMName |
                Out-Null
        }

        # Wait until the Azure VM Agent can accept Run Command.
        Write-RunbookLog 'Waiting for the restored Windows VM Agent.'
        Wait-AzVMGuestAgent `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $newVMName `
            -TimeoutMinutes 20

        # Phase 1: rename the workgroup computer before creating an AD object.
        $renameScript = @'
param(
    [Parameter(Mandatory)][string]$TargetComputerName,
    [Parameter(Mandatory)][string]$ComputerDescription
)

$ErrorActionPreference = 'Stop'

try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $currentName = $env:COMPUTERNAME

    if ($computerSystem.PartOfDomain) {
        throw "Computer '$currentName' is already joined to domain '$($computerSystem.Domain)'. Expected a workgroup computer before rename."
    }

    Set-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'srvcomment' `
        -Value $ComputerDescription `
        -Type String `
        -Force

    if ($currentName -ieq $TargetComputerName) {
        Write-Output "Computer is already named '$TargetComputerName'; no rename restart is required."
        exit 0
    }

    Write-Output "Renaming workgroup computer from '$currentName' to '$TargetComputerName'."
    Rename-Computer `
        -NewName $TargetComputerName `
        -Force `
        -ErrorAction Stop

    Write-Output "Rename to '$TargetComputerName' accepted. An Azure-controlled restart is required."
    exit 0
}
catch {
    [Console]::Error.WriteLine("Computer rename failed: $($_.Exception.Message)")
    exit 1
}
'@

        $renameParameters = @(
            @{
                Name  = 'TargetComputerName'
                Value = $newVMName
            },
            @{
                Name  = 'ComputerDescription'
                Value = $effectiveComputerDescription
            }
        )

        Write-RunbookLog "Phase 1/2: renaming Windows computer to '$newVMName' while it is still in a workgroup."
        $null = Set-AzVMRunCommand `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $newVMName `
            -RunCommandName 'RenameWindowsComputer' `
            -Location $restoredVM.Location `
            -SourceScript $renameScript `
            -Parameter $renameParameters `
            -TimeoutInSecond 600

        $renameCommand = Get-AzVMRunCommand `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $newVMName `
            -RunCommandName 'RenameWindowsComputer' `
            -Expand InstanceView

        $renameExecutionState = $renameCommand.InstanceView.ExecutionState
        $renameExitCode = $renameCommand.InstanceView.ExitCode
        $renameOutput = [string]$renameCommand.InstanceView.Output
        $renameError = [string]$renameCommand.InstanceView.Error

        if (-not [string]::IsNullOrWhiteSpace($renameOutput)) {
            Write-RunbookLog "Rename guest output: $renameOutput"
        }

        if ($renameExecutionState -ne 'Succeeded' -or $renameExitCode -ne 0) {
            throw "Windows rename failed. ExecutionState='$renameExecutionState'; ExitCode='$renameExitCode'; Guest error: $renameError"
        }

        Write-RunbookLog "Windows accepted the rename. Restarting Azure VM '$newVMName'."
        Restart-AzVM `
            -ResourceGroupName $TargetResourceGroupName `
            -Name $newVMName |
            Out-Null

        Write-RunbookLog 'Azure restart after rename completed. Waiting for the Windows VM Agent.'
        Wait-AzVMGuestAgent `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $newVMName `
            -TimeoutMinutes 20 `
            -InitialDelaySeconds 30

        # Phase 2: verify the active hostname, then join the domain without
        # passing NewName to Add-Computer.
        $domainJoinScript = @'
param(
    [Parameter(Mandatory)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][string]$DomainName,
    [Parameter(Mandatory)][string]$DomainUserName,
    [Parameter(Mandatory)][string]$DomainPassword,
    [string]$OUPath
)

$ErrorActionPreference = 'Stop'

try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $currentName = $env:COMPUTERNAME

    if ($currentName -ine $ExpectedComputerName) {
        throw "Computer name is '$currentName'; expected '$ExpectedComputerName' before domain join."
    }

    if ($computerSystem.PartOfDomain) {
        if ($computerSystem.Domain -ieq $DomainName) {
            Write-Output "Computer '$currentName' is already joined to '$DomainName'."
            exit 0
        }

        throw "Computer '$currentName' is already joined to unexpected domain '$($computerSystem.Domain)'."
    }

    Resolve-DnsName `
        -Name "_ldap._tcp.dc._msdcs.$DomainName" `
        -Type SRV `
        -ErrorAction Stop |
        Select-Object -First 1 |
        Out-Null

    $securePassword = ConvertTo-SecureString `
        $DomainPassword `
        -AsPlainText `
        -Force
    $credential = [pscredential]::new($DomainUserName, $securePassword)

    $joinParameters = @{
        DomainName  = $DomainName
        Credential  = $credential
        Force       = $true
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($OUPath)) {
        $joinParameters.OUPath = $OUPath
    }

    Add-Computer @joinParameters
    Write-Output "Computer '$currentName' joined to '$DomainName'. An Azure-controlled restart is required."
    exit 0
}
catch {
    [Console]::Error.WriteLine("Domain join failed: $($_.Exception.Message)")

    $netSetupLog = 'C:\Windows\debug\NetSetup.log'
    if (Test-Path $netSetupLog) {
        [Console]::Error.WriteLine('Latest NetSetup.log entries:')
        [Console]::Error.WriteLine((Get-Content $netSetupLog -Tail 80 | Out-String))
    }

    exit 1
}
'@

        $domainPassword = $domainCredential.GetNetworkCredential().Password
        if ([string]::IsNullOrWhiteSpace($domainPassword)) {
            throw "Automation credential asset '$DomainCredentialAssetName' has an empty password."
        }

        $domainJoinParameters = @(
            @{
                Name  = 'ExpectedComputerName'
                Value = $newVMName
            },
            @{
                Name  = 'DomainName'
                Value = $DomainName
            },
            @{
                Name  = 'DomainUserName'
                Value = $domainUserName
            },
            @{
                Name  = 'OUPath'
                Value = [string]$DomainOUPath
            }
        )

        $protectedDomainJoinParameters = @(
            @{
                Name  = 'DomainPassword'
                Value = $domainPassword
            }
        )

        Write-RunbookLog "Phase 2/2: joining renamed computer '$newVMName' to '$DomainName'."
        $null = Set-AzVMRunCommand `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $newVMName `
            -RunCommandName 'JoinOilibyaDomain' `
            -Location $restoredVM.Location `
            -SourceScript $domainJoinScript `
            -Parameter $domainJoinParameters `
            -ProtectedParameter $protectedDomainJoinParameters `
            -TimeoutInSecond 900

        # Drop the clear-text parameter references from the Automation worker.
        $domainPassword = $null
        $protectedDomainJoinParameters = $null

        # ProvisioningState only confirms that Azure deployed Run Command. Read
        # InstanceView to obtain the actual PowerShell exit code from Windows.
        $domainJoinCommand = Get-AzVMRunCommand `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $newVMName `
            -RunCommandName 'JoinOilibyaDomain' `
            -Expand InstanceView

        $joinExecutionState = $domainJoinCommand.InstanceView.ExecutionState
        $joinExitCode = $domainJoinCommand.InstanceView.ExitCode
        $joinOutput = [string]$domainJoinCommand.InstanceView.Output
        $joinError = [string]$domainJoinCommand.InstanceView.Error

        if (-not [string]::IsNullOrWhiteSpace($joinOutput)) {
            Write-RunbookLog "Domain-join guest output: $joinOutput"
        }

        if ($joinExecutionState -ne 'Succeeded' -or $joinExitCode -ne 0) {
            throw "Windows domain join failed. ExecutionState='$joinExecutionState'; ExitCode='$joinExitCode'; Guest error: $joinError"
        }

        Write-RunbookLog "Windows accepted the domain join. Restarting Azure VM '$newVMName'."
        Restart-AzVM `
            -ResourceGroupName $TargetResourceGroupName `
            -Name $newVMName |
            Out-Null

        Write-RunbookLog 'Azure restart after domain join completed. Waiting for the Windows VM Agent.'
        Wait-AzVMGuestAgent `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $newVMName `
            -TimeoutMinutes 20 `
            -InitialDelaySeconds 30

        # Confirm from inside the restarted guest that both changes persisted.
        $verificationScript = @'
param(
    [Parameter(Mandatory)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][string]$ExpectedDomainName,
    [Parameter(Mandatory)][string]$ExpectedComputerDescription
)

$ErrorActionPreference = 'Stop'
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$actualName = $env:COMPUTERNAME
$actualDomain = [string]$computerSystem.Domain

if ($actualName -ine $ExpectedComputerName) {
    Write-Error "Computer name is '$actualName'; expected '$ExpectedComputerName'."
    exit 10
}

if (-not $computerSystem.PartOfDomain) {
    Write-Error "Computer '$actualName' is not joined to a domain."
    exit 11
}

if ($actualDomain -ine $ExpectedDomainName) {
    Write-Error "Computer is joined to '$actualDomain'; expected '$ExpectedDomainName'."
    exit 12
}

$actualDescription = [string](Get-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
    -Name 'srvcomment').srvcomment
if ($actualDescription -ine $ExpectedComputerDescription) {
    Write-Error "Computer description is '$actualDescription'; expected '$ExpectedComputerDescription'."
    exit 13
}

Write-Output "Verified: '$actualName' is joined to '$actualDomain' with description '$actualDescription'."
exit 0
'@

        $verificationParameters = @(
            @{
                Name  = 'ExpectedComputerName'
                Value = $newVMName
            },
            @{
                Name  = 'ExpectedDomainName'
                Value = $DomainName
            },
            @{
                Name  = 'ExpectedComputerDescription'
                Value = $effectiveComputerDescription
            }
        )

        Write-RunbookLog 'Verifying the Windows name and domain membership after restart.'
        $null = Set-AzVMRunCommand `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $newVMName `
            -RunCommandName 'VerifyRenameAndDomainJoin' `
            -Location $restoredVM.Location `
            -SourceScript $verificationScript `
            -Parameter $verificationParameters `
            -TimeoutInSecond 600

        $verificationCommand = Get-AzVMRunCommand `
            -ResourceGroupName $TargetResourceGroupName `
            -VMName $newVMName `
            -RunCommandName 'VerifyRenameAndDomainJoin' `
            -Expand InstanceView

        $verificationState = $verificationCommand.InstanceView.ExecutionState
        $verificationExitCode = $verificationCommand.InstanceView.ExitCode
        $verificationOutput = [string]$verificationCommand.InstanceView.Output
        $verificationError = [string]$verificationCommand.InstanceView.Error

        if ($verificationState -ne 'Succeeded' -or $verificationExitCode -ne 0) {
            throw "Post-restart verification failed. ExecutionState='$verificationState'; ExitCode='$verificationExitCode'; Guest error: $verificationError"
        }

        Write-RunbookLog "Domain verification succeeded: $verificationOutput"

        # Obtain a fresh token because the restore and restart can take hours.
        Write-RunbookLog 'Authenticating to Citrix DaaS after guest verification.'
        $citrixToken = Get-CitrixAccessToken `
            -Credential $citrixCredential `
            -CustomerId $citrixCustomerId `
            -ApiHost $citrixApiHost
        $citrixHeaders = New-CitrixHeaders `
            -AccessToken $citrixToken `
            -CustomerId $citrixCustomerId `
            -SiteId $citrixSiteId

        $citrixMachineName = "$DomainNetBIOSName\$newVMName"
        $citrixMachine = Get-CitrixMachine `
            -MachineName $citrixMachineName `
            -ApiHost $citrixApiHost `
            -Headers $citrixHeaders

        if (-not $citrixMachine) {
            Write-RunbookLog "Adding exact machine '$citrixMachineName' to Citrix catalog '$citrixCatalogName'."
            $catalogUriName = [uri]::EscapeDataString([string]$citrixCatalog.Id)
            $catalogAddParameters = @{
                MachineName = $citrixMachineName
            }
            if ($citrixCatalog.IsPowerManaged) {
                $sampleGuid = [guid]::Empty
                if ([guid]::TryParse($citrixHostedMachineIdSample, [ref]$sampleGuid)) {
                    $hostedMachineId = [string]$restoredVM.VmId
                }
                elseif ($citrixHostedMachineIdSample -match '(?i)^/subscriptions/') {
                    $hostedMachineId = [string]$restoredVM.Id
                }
                elseif ($citrixHostedMachineIdSample -match '^[^/]+/[^/]+$') {
                    $hostedMachineId = '{0}/{1}' -f $restoredVM.ResourceGroupName, $restoredVM.Name
                }
                else {
                    throw "Unsupported Citrix HostedMachineId format '$citrixHostedMachineIdSample'."
                }
                $catalogAddParameters.HypervisorConnection = $citrixHypervisorConnection
                $catalogAddParameters.HostedMachineId = $hostedMachineId
                Write-RunbookLog "Using HostedMachineId '$hostedMachineId'."
            }
            $catalogAddBody = $catalogAddParameters | ConvertTo-Json

            $catalogJob = Invoke-RestMethod `
                -Uri "https://$citrixApiHost/cvad/manage/MachineCatalogs/$catalogUriName/Machines" `
                -Method Post `
                -Headers $citrixHeaders `
                -Body $catalogAddBody

            $null = Wait-CitrixJob `
                -Job $catalogJob `
                -ApiHost $citrixApiHost `
                -Headers $citrixHeaders `
                -TimeoutMinutes 20
        }
        else {
            Write-RunbookLog "Machine '$citrixMachineName' already exists in Citrix."
        }

        $machineDeadline = (Get-Date).ToUniversalTime().AddMinutes(10)
        do {
            $citrixMachine = Get-CitrixMachine `
                -MachineName $citrixMachineName `
                -ApiHost $citrixApiHost `
                -Headers $citrixHeaders
            if ($citrixMachine) {
                break
            }
            Start-Sleep -Seconds 15
        } while ((Get-Date).ToUniversalTime() -lt $machineDeadline)

        if (-not $citrixMachine) {
            throw "Citrix did not return '$citrixMachineName' after adding it to catalog '$citrixCatalogName'."
        }
        if ($citrixMachine.MachineCatalog.Name -ne $citrixCatalogName) {
            throw "Citrix machine '$citrixMachineName' belongs to catalog '$($citrixMachine.MachineCatalog.Name)', not '$citrixCatalogName'."
        }

        if ($citrixMachine.DeliveryGroup.Name -ne $citrixDeliveryGroupName) {
            Write-RunbookLog "Adding exact machine '$citrixMachineName' to Delivery Group '$citrixDeliveryGroupName'."
            $deliveryGroupUriName = [uri]::EscapeDataString([string]$citrixDeliveryGroup.Id)
            $deliveryGroupBody = @{
                MachineCatalog       = [string]$citrixCatalog.Id
                AssignMachinesToUsers = @(
                    @{
                        Machine = $citrixMachineName
                    }
                )
            } | ConvertTo-Json -Depth 5

            $null = Invoke-RestMethod `
                -Uri "https://$citrixApiHost/cvad/manage/DeliveryGroups/$deliveryGroupUriName/Machines" `
                -Method Post `
                -Headers $citrixHeaders `
                -Body $deliveryGroupBody
        }
        else {
            Write-RunbookLog "Machine '$citrixMachineName' is already in Delivery Group '$citrixDeliveryGroupName'."
        }

        $registrationDeadline = (Get-Date).ToUniversalTime().AddMinutes($CitrixRegistrationWaitMinutes)
        do {
            Start-Sleep -Seconds 30
            $citrixMachine = Get-CitrixMachine `
                -MachineName $citrixMachineName `
                -ApiHost $citrixApiHost `
                -Headers $citrixHeaders

            $actualDeliveryGroup = [string]$citrixMachine.DeliveryGroup.Name
            $registrationState = [string]$citrixMachine.RegistrationState
            $citrixPowerState = [string]$citrixMachine.PowerState
            $citrixFaultState = [string]$citrixMachine.FaultState
            Write-RunbookLog "Citrix status: DeliveryGroup='$actualDeliveryGroup'; RegistrationState='$registrationState'; PowerState='$citrixPowerState'; FaultState='$citrixFaultState'."

            if ($actualDeliveryGroup -eq $citrixDeliveryGroupName -and
                $registrationState -eq 'Registered' -and
                $citrixPowerState -ne 'VirtualMachineNotFound' -and
                $citrixFaultState -ne 'VirtualMachineNotFound') {
                break
            }
        } while ((Get-Date).ToUniversalTime() -lt $registrationDeadline)

        if ($actualDeliveryGroup -ne $citrixDeliveryGroupName) {
            throw "Citrix machine '$citrixMachineName' was not assigned to Delivery Group '$citrixDeliveryGroupName'. Current group: '$actualDeliveryGroup'."
        }
        if ($registrationState -ne 'Registered') {
            throw "Citrix machine '$citrixMachineName' is in the correct catalog and Delivery Group but did not register within $CitrixRegistrationWaitMinutes minutes. Current state: '$registrationState'."
        }
        if ($citrixPowerState -eq 'VirtualMachineNotFound' -or
            $citrixFaultState -eq 'VirtualMachineNotFound') {
            throw "Citrix registered '$citrixMachineName', but the hosting connection still reports VirtualMachineNotFound."
        }

        Write-RunbookLog "Citrix verification succeeded. '$citrixMachineName' is registered."
        $citrixToken = $null
        $citrixHeaders = $null

        # ============================================================
        # REFRESH ServerList.txt WITH ALL SRVTAPP VMs
        # Storage account : dreports
        # File share      : reports
        # File            : Scripts/ServerList.txt
        # ============================================================

        Write-RunbookLog "Refreshing ServerList.txt with all Azure VMs starting with 'SRVTAPP'."

        # Refresh the managed-identity sign-in because this runbook can run for
        # a long time while restoring, restarting, and waiting for Citrix.
        $serverListLoginContext = (Connect-AzAccount -Identity).Context
        $serverListTenantId = $serverListLoginContext.Tenant.Id

        Write-RunbookLog "Getting subscriptions accessible to the managed identity in tenant '$serverListTenantId'."

        $serverListSubscriptions = @(
            Get-AzSubscription `
                -TenantId $serverListTenantId `
                -DefaultProfile $serverListLoginContext |
                Where-Object { $_.State -eq 'Enabled' }
        )

        if ($serverListSubscriptions.Count -eq 0) {
            throw 'No enabled Azure subscriptions are accessible to the Automation Account managed identity. ServerList.txt will not be changed.'
        }

        Write-RunbookLog "Found $($serverListSubscriptions.Count) accessible subscription(s)."

        $srvtAppServers = @()

        foreach ($serverListSubscription in $serverListSubscriptions) {
            Write-RunbookLog "Searching subscription '$($serverListSubscription.Name)' for SRVTAPP VMs."

            try {
                $serverListSubscriptionContext = Set-AzContext `
                    -SubscriptionId $serverListSubscription.Id `
                    -TenantId $serverListTenantId `
                    -DefaultProfile $serverListLoginContext

                $serverListMatchingVMs = @(
                    Get-AzVM `
                        -DefaultProfile $serverListSubscriptionContext |
                        Where-Object { $_.Name -like 'SRVTAPP*' }
                )

                foreach ($serverListVM in $serverListMatchingVMs) {
                    Write-RunbookLog "ServerList VM found: '$($serverListVM.Name)'."
                    $srvtAppServers += [string]$serverListVM.Name
                }
            }
            catch {
                Write-Warning "Could not query subscription '$($serverListSubscription.Name)': $($_.Exception.Message)"
            }
        }

        $srvtAppServers = @(
            $srvtAppServers |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                Sort-Object -Unique
        )

        if ($srvtAppServers.Count -eq 0) {
            throw 'No SRVTAPP VMs were found. ServerList.txt will not be changed.'
        }

        # Safety check: the VM created by this runbook must be present in the
        # freshly discovered list before the existing ServerList.txt is replaced.
        if ($newVMName -notin $srvtAppServers) {
            throw "The newly created VM '$newVMName' was not found in the SRVTAPP server list. ServerList.txt will not be changed."
        }

        Write-RunbookLog "Total SRVTAPP VMs to write: $($srvtAppServers.Count)."

        $serverListStorageAccountName = 'dreports'
        $serverListShareName = 'reports'
        $serverListPath = 'Scripts/ServerList.txt'
        $serverListTempFile = Join-Path $env:TEMP 'ServerList.txt'

        try {
            # Build the file as plain UTF-8 text without BOM, one server per line.
            $serverListContent = $srvtAppServers -join [Environment]::NewLine
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            [System.IO.File]::WriteAllText(
                $serverListTempFile,
                $serverListContent,
                $utf8NoBom
            )

            Write-RunbookLog "Connecting to Azure Files storage account '$serverListStorageAccountName'."

            # Azure Files OAuth/FileREST access with the connected managed identity.
            $serverListStorageContext = New-AzStorageContext `
                -StorageAccountName $serverListStorageAccountName `
                -UseConnectedAccount `
                -EnableFileBackupRequestIntent

            Write-RunbookLog "Uploading $($srvtAppServers.Count) server(s) to '$serverListShareName/$serverListPath'."

            Set-AzStorageFileContent `
                -ShareName $serverListShareName `
                -Source $serverListTempFile `
                -Path $serverListPath `
                -Context $serverListStorageContext `
                -Force |
                Out-Null

            Write-RunbookLog 'ServerList.txt updated successfully.'
        }
        finally {
            if (Test-Path $serverListTempFile) {
                Remove-Item `
                    -Path $serverListTempFile `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }

        # Restore the original subscription context used by the provisioning runbook.
        $context = Set-AzContext `
            -SubscriptionId $context.Subscription.Id `
            -TenantId $context.Tenant.Id `
            -DefaultProfile $serverListLoginContext

        Write-RunbookLog 'ServerList refresh completed successfully.'

        [pscustomobject]@{
            SourceVM            = $SourceVMName
            NewVM               = $newVMName
            WindowsName         = $newVMName
            ResourceGroup       = $TargetResourceGroupName
            RecoveryPointUTC    = $latestRecoveryPoint.RecoveryPointTime.ToUniversalTime()
            RestoreJobId        = $restoreJob.JobId
            RestoreStatus       = $job.Status
            Domain              = $DomainName
            ComputerDescription = $effectiveComputerDescription
            DomainJoinStatus    = 'Verified'
            RenameExitCode      = $renameExitCode
            JoinExitCode        = $joinExitCode
            VerifyExitCode      = $verificationExitCode
            RestartCompleted    = $true
            CitrixMachine       = $citrixMachineName
            CitrixCatalog       = $citrixCatalogName
            CitrixDeliveryGroup = $citrixDeliveryGroupName
            CitrixRegistration  = $registrationState
            CitrixPowerState    = $citrixPowerState
            CitrixFaultState    = $citrixFaultState
        }
        return
    }

    if ($job.Status -eq 'CompletedWithWarnings') {
        throw "Restore job '$($restoreJob.JobId)' completed with warnings. Review it in the Recovery Services vault before using '$newVMName'."
    }

    if ($job.Status -in @('Failed', 'Cancelled')) {
        $jobDetails = Get-AzRecoveryServicesBackupJobDetail `
            -Job $job `
            -VaultId $vault.ID
        throw "Restore job '$($restoreJob.JobId)' ended with status '$($job.Status)'. Details: $($jobDetails | Out-String)"
    }

    throw "Restore job '$($restoreJob.JobId)' did not finish within $MaximumWaitHours hours. It may still be running in Azure."
}
catch {
    Write-Error "VM restore runbook failed: $($_.Exception.Message)"
    throw
}
