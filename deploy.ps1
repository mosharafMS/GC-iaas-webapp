#
# deploy.ps1
#

$timestamp = Get-Date -Format "yyyy-MM-dd_hh:mm:ss"
New-AzureRmResourceGroupDeployment -Name "deployment-$timestamp" -ResourceGroupName GCbluePrint `
-TemplateFile .\azuredeploy.json -TemplateParameterFile .\azuredeploy.parameters.json `
-Mode Incremental -DeploymentDebugLogLevel ResponseContent -Verbose
