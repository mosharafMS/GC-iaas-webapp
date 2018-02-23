
Param(
    [parameter(Mandatory=$true)]
    [string] $aadAppName,
    [parameter(Mandatory=$true)]
    [string] $resourceGroupName
)


try
{
    $subscription = Get-AzureRmSubscription  
    Write-Host "----Using existing authentication-----"
}
catch {

}

if (-not $subscription)
{
    Write-Host "Authenticate to Azure subscription"
    Add-AzureRmAccount
}
Remove-AzureRmResourceGroup -Name $resourceGroupName -Force 


$AADs=(Get-AzureRmADApplication -DisplayNameStartWith $aadAppName)
foreach($aad in $AADs)
{
    try{
    Remove-AzureADApplication -ObjectId $aad.ObjectId -ErrorAction SilentlyContinue
    }
    catch{}
}

