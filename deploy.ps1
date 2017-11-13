#
# deploy.ps1
#

$timestamp = Get-Date -Format "yyyy-MM-dd_hh-mm-ss"
#
# Original deployment
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName GCbluePrint `
-TemplateFile .\azuredeploy.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

#
# First deployment - Storage Accounts
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName GCbluePrint `
-TemplateFile .\azuredeploy1.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

#
# Second deployment - Active Directory VMs
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName GCbluePrint `
-TemplateFile .\azuredeploy2.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

#
# Second deployment - Active Directory VMs Encryption
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName GCbluePrint `
-TemplateFile .\azuredeploy21.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

#
# Third deployment - Networking
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName GCbluePrint `
-TemplateFile .\azuredeploy3.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 

#
# Fourth deployment - all the rest
#
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName GCbluePrint `
-TemplateFile .\azuredeploy4.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 