
az group deployment create --debug --template-file azuredeploy.json \ 
--parameters azuredeploy.parameters.json \ 
--resource-group GCbluePrint  --verbose