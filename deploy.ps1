
#
# deploy.ps1
#

#Login-AzureRmAccount

$subscriptionId = '3a4af7b3-b7ac-463d-9940-1d80445961a8'
Set-AzureRmContext -SubscriptionId $subscriptionId
$timestamp = Get-Date -Format "yyyy-MM-dd_hh-mm-ss"
$resourceGroupName = 'GCbluePrintUser1'

#
# Provision Basic Services / OMS Workspaces
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy01.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 
#
# Provision Domain Controllers
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy02.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

Restart-AzureRmVM -ResourceGroupName $resourceGroupName -Name "AZ-PDC-VMprod" -Verbose
Restart-AzureRmVM -ResourceGroupName $resourceGroupName -Name "AZ-BDC-VMprod" -Verbose
#
# Provision Domain Controllers Backups
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy03.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

#
# App GW, other VMs
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy04.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

#
# Everything else
#
#New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName $resourceGroupName `
#-TemplateFile .\azuredeploy05.json -TemplateParameterFile .\azuredeploy.parameters.json `
#-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

#
# Encryption
#

$aadClientID = '79322cff-7f2d-4ed0-b171-15fe9459bbac'
$aadClientSecret = 'a505e035-4c29-49ae-8f90-7efae0252fdf'
$diskEncryptionKeyVaultUrl = 'https://gckeystoreuser1.vault.azure.net/'
$keyVaultResourceId = '/subscriptions/3a4af7b3-b7ac-463d-9940-1d80445961a8/resourceGroups/GCbluePrintUser1/providers/Microsoft.KeyVault/vaults/GCKeystoreUser1'
Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'AZ-PDC-VMprod' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force
Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'AZ-BDC-VMprod' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force

