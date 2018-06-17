#use with bash
#NOT COMLETE. Currently supporting only the Powershell installation 


az group deployment create --template-file azuredeploy.json --parameters azuredeploy.parameters.json --resource-group GCbluePrint  --verbose