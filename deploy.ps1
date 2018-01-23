#
# deploy.ps1
#

#Login-AzureRmAccount

$subscriptionId = '3a4af7b3-b7ac-463d-9940-1d80445961a8'
Set-AzureRmContext -SubscriptionId $subscriptionId
$timestamp = Get-Date -Format "yyyy-MM-dd_hh-mm-ss"
$resourceGroupName = 'GCbluePrint'

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

Restart-AzureRmVM -ResourceGroupName "GCbluePrint" -Name "AZ-PDC-VMprod" -Verbose
Restart-AzureRmVM -ResourceGroupName "GCbluePrint" -Name "AZ-BDC-VMprod" -Verbose

#
# Provision Domain Controllers Backups
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy03.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

#
#
#
#
# Everything else
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName $resourceGroupName `
-TemplateFile .\azuredeploy04.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 