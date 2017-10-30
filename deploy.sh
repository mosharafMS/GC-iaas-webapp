#use with bash
#make sure to execute ./predeply/Orchestration_InitialSetup.ps1 in a powershell session first


az group deployment create --template-file azuredeploy.json --parameters azuredeploy.parameters.json --resource-group GCbluePrint  --verbose