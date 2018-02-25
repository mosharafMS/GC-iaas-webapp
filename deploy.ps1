
#
# deploy.ps1
#

#Login-AzureRmAccount

#$subscriptionId = 'xxx'
#Set-AzureRmContext -SubscriptionId $subscriptionId
$timestamp = Get-Date -Format "yyyy-MM-dd_hh-mm-ss"
$resourceGroupName = 'GCBlueprint'
$keyvaultName="GCBlueprint1982"
$parametersFile='.\azuredeploy.parameters.testing'

#
# Provision Basic Services / OMS Workspaces
#
New-AzureRmResourceGroupDeployment -Name "AS_Vault_Nework_OMS" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy01.json -TemplateParameterFile $parametersFile `
-Mode Incremental -Verbose 
#
# Provision Domain Controllers
#
New-AzureRmResourceGroupDeployment -Name "DomainControllers" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy02.json -TemplateParameterFile $parametersFile `
-Mode Incremental -Verbose 

Restart-AzureRmVM -ResourceGroupName $resourceGroupName -Name "AZ-PDC-VMprod" -Verbose
Restart-AzureRmVM -ResourceGroupName $resourceGroupName -Name "AZ-BDC-VMprod" -Verbose

Start-Sleep -Seconds 120

#
# Provision Domain Controllers Backups
#
New-AzureRmResourceGroupDeployment -Name "BackupDomainControllers" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy03.json -TemplateParameterFile $parametersFile `
-Mode Incremental -Verbose 

#
# App GW, other VMs
#
New-AzureRmResourceGroupDeployment -Name "NICsApplicationGateway" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy04.json -TemplateParameterFile $parametersFile `
-Mode Incremental -Verbose 

#
# Everything else
#
New-AzureRmResourceGroupDeployment -Name "RestOfMachines" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy05.json -TemplateParameterFile $parametersFile `
-Mode Incremental -Verbose 

#
# Encryption
#


$keyvault=Get-AzureRmKeyVault -VaultName $keyvaultName
$aadClientID= (Get-AzureKeyVaultSecret -VaultName $keyvaultName -Name "aadClientID").SecretValueText
$aadClientSecret=(Get-AzureKeyVaultSecret -VaultName $keyvaultName -Name "aadClientSecret").SecretValueText
$keyVaultResourceId=$keyvault.ResourceId
$diskEncryptionKeyVaultUrl=$keyvault.VaultUri

Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'AZ-PDC-VMprod' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force
Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'AZ-BDC-VMprod' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force
Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'AZ-MGT-VMprod' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force

Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'AZ-WEB-VMprod0' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force
Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'AZ-WEB-VMprod1' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force

Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'cluster-fswprod' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force

Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'sqlserver0prod' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force
Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $resourceGroupName -VMName 'sqlserver1prod' -AadClientID $aadClientID -AadClientSecret $aadClientSecret -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $keyVaultResourceId -VolumeType All -Verbose -Force


