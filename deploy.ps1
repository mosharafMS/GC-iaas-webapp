#
# deploy.ps1
#

$timestamp = Get-Date -Format "yyyy-MM-dd_hh-mm-ss"
New-AzureRmResourceGroupDeployment -Name "D_$timestamp" -ResourceGroupName GCbluePrint `
-TemplateFile .\azuredeploy.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose 
