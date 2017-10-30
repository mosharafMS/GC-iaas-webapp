
Param(
    [parameter(Mandatory=$true)]
    [string] $aadAppName,
    [parameter(Mandatory=$true)]
    [string] $resourceGroupName
)



Remove-AzureRmResourceGroup -Name $resourceGroupName -Force 


$AADs = (Get-AzureRmADApplication -DisplayNameStartWith $aadAppName);
if($SvcPrincipals)
{
    foreach($aad in $AADs)
    {
             Remove-AzureADApplication -ObjectId $aad.objectId
    }
}

