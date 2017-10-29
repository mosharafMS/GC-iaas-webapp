
$aadAppName="BlueprintGCWin"
$resourceGroupName="GCbluePrint"
Remove-AzureRmResourceGroup -Name $resourceGroupName -Force 


Connect-AzureAD -
$SvcPrincipals = (Get-AzureRmADServicePrincipal -SearchString $aadAppName);
if($SvcPrincipals)
{
    foreach($svcPrincipal in $SvcPrincipals)
    {
        Remove-AzureADServicePrincipal -ObjectId $svcPrincipal.Id
        Start-Sleep -Seconds 5
        Remove-AzureADApplication -ObjectId $svcPrincipal.ApplicationId 
    }
}

