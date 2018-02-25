
Param(
    [parameter(Mandatory=$true)]
    [string] $aadAppName,
    [parameter(Mandatory=$true)]
    [string] $resourceGroupName
)


$subscription=(Get-AzureRmContext).Subscription
if (-not $subscription)
{
    Write-Host "Authenticate to Azure subscription"
    Add-AzureRmAccount
}

#AzureAD
Write-Host "Finding AAD App"
$AADs = (Get-AzureRmADApplication -DisplayNameStartWith $aadAppName);
if($AADs)
{
    Write-Host "AAD App found...Deleting"
    foreach($aad in $AADs)
    {
        try{
            Write-Host "Removing " $aad.DisplayName
             Remove-AzureRMADApplication -ObjectId $aad.objectId -Force }
             catch{}
    }
    Write-Host "Job Done"
}

###############


##############Recovery Vault############################


Write-Host "Getting the Recovery Vault"

Get-AzureRmRecoveryServicesVault

$vaults=Get-AzureRmRecoveryServicesVault -Name AZ-RCV-01

foreach($vault in $vaults)
{
Set-AzureRmRecoveryServicesVaultContext -Vault $vault

$containers=Get-AzureRmRecoveryServicesBackupContainer -ContainerType AzureVM


Write-Host "This recovery vault has "+ $containers.Count + " containers"
Write-Host "Deleting containers..."
foreach($c in $containers)
{
 $item=Get-AzureRmRecoveryServicesBackupItem -Container $c -WorkloadType AzureVM
 Disable-AzureRmRecoveryServicesBackupProtection -Item $item -RemoveRecoveryPoints -Force   
}

Remove-AzureRmRecoveryServicesVault -Vault $vault 
}



########################################################

Remove-AzureRmResourceGroup -Name $resourceGroupName -Force 




