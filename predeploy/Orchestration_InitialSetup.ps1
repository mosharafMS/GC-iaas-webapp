#Requires -Modules AzureRM,AzureRM.Profile


<#
.Description
This script will create a Key Vault with a Key Encryption Key for VM DIsk Encryption and Azure AD Application Service Principal inside a specified Azure subscription

.Parameter adminPassword
Must meet complexity requirements
14+ characters, 2 numbers, 2 upper and lower case, and 2 special chars

.Parameter sqlServerServiceAccountPassword
Must meet complexity requirements
14+ characters, 2 numbers, 2 upper and lower case, and 2 special chars
#>

Write-Host "`n `n AZURE BLUEPRINT MULTI-TIER WEB APPLICATION SOLUTION FOR FEDRAMP: Pre-Deployment Script `n" -foregroundcolor green
Write-Host "This script can be used for creating the necessary preliminary resources to deploy a multi-tier web application architecture with pre-configured security controls to help customers achieve compliance with FedRAMP requirements. See https://github.com/mosharafMS/GC-iaas-webapp for more information. `n " -foregroundcolor yellow

Write-Host "Press Enter key to continue ..."
Read-Host


########################################################################################################################
# PASSWORD VALIDATION FUNCTION
########################################################################################################################
function checkPasswords
{
	Param(
		[Parameter(Mandatory=$true)]
		[string]$name
	)

	$password = Read-Host -assecurestring "Enter $($name)"
  $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($password)
  $pw2test = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
  [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)

	$passLength = 14
	$isGood = 0
	if ($pw2test.Length -ge $passLength) {
		$isGood = 1
    If ($pw2test -match " "){
      "Password does not meet complexity requirements. Password cannot contain spaces"
      checkPasswords -name $name
      return
    } Else {
      $isGood = 2
    }
		If ($pw2test -match "[^a-zA-Z0-9]"){
			$isGood = 3
    } Else {
        "Password does not meet complexity requirements. Password must contain a special character"
        checkPasswords -name $name
        return
    }
		If ($pw2test -match "[0-9]") {
			$isGood = 4
    } Else {
        "Password does not meet complexity requirements. Password must contain a numerical character"
        checkPasswords -name $name
        return
    }
		If ($pw2test -cmatch "[a-z]") {
			$isGood = 5
    } Else {
      "Password must contain a lowercase letter"
        "Password does not meet complexity requirements"
        checkPasswords -name $name
        return
    }
		If ($pw2test -cmatch "[A-Z]"){
			$isGood = 6
    } Else {
      "Password must contain an uppercase character"
        "Password does not meet complexity requirements"
        checkPasswords -name $name
    }
		If ($isGood -ge 6) {
      $passwords | Add-Member -MemberType NoteProperty -Name $name -Value $password
      return
    } Else {
      "Password does not meet complexity requirements"
      checkPasswords -name $name
      return
    }
  } Else {

    "Password is not long enough - Passwords must be at least " + $passLength + " characters long"
    checkPasswords -name $name
    return

  }
}

########################################################################################################################
# GENERATE RANDOM PASSWORD FOR CERT FUNCTION
########################################################################################################################
Function New-RandomPassword() {
    [CmdletBinding()]
    param(
        [int]$Length = 14
    )
    $ascii=$NULL;For ($a=33;$a -le 126;$a++) {$ascii+=,[char][byte]$a }
    For ($loop=1; $loop -le $length; $loop++) {
        $RandomPassword+=($ascii | GET-RANDOM)
    }
    return $RandomPassword
}

########################################################################################################################
# Create KeyVault or setup existing keyVault
########################################################################################################################
function orchestration
{
	Param(
		[string]$environmentName = "AzureCloud",
		[string]$location = "CanadaCentral",
		[Parameter(Mandatory=$true)]
		[string]$subscriptionId,
		[Parameter(Mandatory=$true)]
		[string]$resourceGroupName,
		[Parameter(Mandatory=$true)]
		[string]$keyVaultName,
		[Parameter(Mandatory=$true)]
		[string]$adminUsername,
		[Parameter(Mandatory=$true)]
		[SecureString]$adminPassword,
		[Parameter(Mandatory=$true)]
		[SecureString]$sqlServerServiceAccountPassword,
		[Parameter(Mandatory=$true)]
		[string]$domain
	)

	$errorActionPreference = 'stop'
	Write-Host "`n LOGIN TO AZURE `n" -foregroundcolor green
	try
	{
		$subscription = Get-AzureRmSubscription  -SubscriptionId $SubscriptionId
		Write-Host "----Using existing authentication-----"
	}
	catch {

	}

	if (-not $subscription)
	{
		Write-Host "Authenticate to Azure subscription"
		Add-AzureRmAccount -EnvironmentName $EnvironmentName | Out-String | Write-Verbose
	}

	Write-Host "Selecting subscription as default"
	Select-AzureRmSubscription -SubscriptionId $SubscriptionId | Out-String | Write-Verbose
	$subscription = Get-AzureRmSubscription  -SubscriptionId $SubscriptionId

	#confirmation before creating resources
	Write-Host "This is the context in which the resources will be created"
	Get-AzureRmContext
	Read-Host "If you are sure to continue, press ENTER otherwise use CTRL+C now" 
	
	#Create the resource group
	Write-Host "Creating resource group '$($resourceGroupName)' to hold key vault"
	
		if (-not (Get-AzureRmResourceGroup -Name $resourceGroupName -Location $location -ErrorAction SilentlyContinue)) {
			New-AzureRmResourceGroup -Name $resourceGroupName -Location $location  | Out-String | Write-Verbose
		}
	


	# Create AAD app . Fill in $aadClientSecret variable if AAD app was already created

            $guid = [Guid]::NewGuid().toString();

            $aadAppName = "BlueprintGCWin" + $guid ;
			# Check if AAD app with $aadAppName was already created
			$SvcPrincipals = (Get-AzureRmADServicePrincipal -SearchString $aadAppName);
			if(-not $SvcPrincipals)
			{
					# Create a new AD application if not created before
					$identifierUri = [string]::Format("http://localhost:8080/{0}",[Guid]::NewGuid().ToString("N"));
					$defaultHomePage = 'http://GCBlueprint.sample';
					$now = [System.DateTime]::Now;
					$oneYearFromNow = $now.AddYears(1);
					$aadPassword=[Guid]::NewGuid().ToString()
					$aadClientSecret = ConvertTo-SecureString $aadPassword  -AsPlainText -Force

					Write-Host "Creating new AAD application ($aadAppName)";
					$ADApp = New-AzureRmADApplication -DisplayName $aadAppName -HomePage $defaultHomePage -IdentifierUris $identifierUri  -StartDate $now -EndDate $oneYearFromNow -Password $aadClientSecret;
					$servicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $ADApp.ApplicationId;
					Write-Host "Sleeping for 10 seconds..." -ForegroundColor Yellow					
					Start-Sleep 10 #sleep for 10 seconds
					$SvcPrincipals = (Get-AzureRmADServicePrincipal -SearchString $aadAppName);
					if(-not $SvcPrincipals)
					{
							# AAD app wasn't created
							Write-Error "Failed to create AAD app $aadAppName. Please log-in to Azure using Login-AzureRmAccount  and try again";
							return;
					}
					$aadClientID = $servicePrincipal.ApplicationId;
					Write-Host "Created a new AAD Application ($aadAppName) with ID: $aadClientID ";
			}
			else
			{
					if(-not $aadClientSecret)
					{
							$aadClientSecret = Read-Host -Prompt "Aad application ($aadAppName) was already created, input corresponding aadClientSecret and hit ENTER. It can be retrieved from https://portal.azure.com portal" ;
					}
					if(-not $aadClientSecret)
					{
							Write-Error "Aad application ($aadAppName) was already created. Re-run the script by supplying aadClientSecret parameter with corresponding secret from https://portal.azure.com portal";
							return;
					}
					$aadClientID = $SvcPrincipals[0].ApplicationId;
			}
		#make the AAD app owner of the resource group
		Write-Host "Assigning owner role on the resoruce group to the AAD application (service principal: $aadClientID)"
		New-AzureRmRoleAssignment -ServicePrincipalName $aadClientID -ResourceGroupName $resourceGroupName `
		 -RoleDefinitionName owner 
		


	# Create KeyVault or setup existing keyVault
	#Create a new vault if vault doesn't exist
	if (-not (Get-AzureRMKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue )) {
		Write-Host "Create a keyVault '$($keyVaultName)' to store the service principal ids and passwords"
		#New-AzureRMKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -EnabledForTemplateDeployment -Location $location | Out-String | Write-Verbose
        New-AzureRMKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -EnabledForTemplateDeployment -Location $location -sku Premium | Out-String | Write-Verbose 
		Write-Host "Created a new KeyVault named $keyVaultName to store encryption keys";

		# Specify privileges to the vault for the AAD application - https://msdn.microsoft.com/en-us/library/mt603625.aspx
		Write-Host "Set Azure Key Vault Access Policy."
		Write-Host "Set ServicePrincipalName: $aadClientID in Key Vault: $keyVaultName";
		Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ServicePrincipalName $aadClientID -PermissionsToKeys wrapKey -PermissionsToSecrets set;
		Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ServicePrincipalName $aadClientID -PermissionsToKeys backup,get,list,wrapKey -PermissionsToSecrets get,list,set;
		Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -EnabledForDiskEncryption;
    	$keyEncryptionKeyName = $keyVaultName + "kek"

		if($keyEncryptionKeyName)
		{
				try
				{
						$kek = Get-AzureKeyVaultKey -VaultName $keyVaultName -Name $keyEncryptionKeyName -ErrorAction SilentlyContinue;
				}
				catch [Microsoft.Azure.KeyVault.KeyVaultClientException]
				{
						Write-Host "Couldn't find key encryption key named : $keyEncryptionKeyName in Key Vault: $keyVaultName";
						$kek = $null;
				}

				if(-not $kek)
				{
						Write-Host "Creating new key encryption key named:$keyEncryptionKeyName in Key Vault: $keyVaultName";
						$kek = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name $keyEncryptionKeyName -Destination HSM -ErrorAction SilentlyContinue;
						Write-Host "Created  key encryption key named:$keyEncryptionKeyName in Key Vault: $keyVaultName";
				}

				$keyEncryptionKeyUrl = $kek.Key.Kid;
		}

		#Generate a self-signed cert for App Gateway
		Write-Host "Generate a self-signed cert for App Gateway" 
		$policy=New-AzureKeyVaultCertificatePolicy -IssuerName self -SubjectName "CN=$domain" -ValidityInMonths 12
		
		Add-AzureKeyVaultCertificate -VaultName $keyVaultName -Name sslcertOrigin -CertificatePolicy $policy
		Write-Host "Certificate is being generated..."
		$x=1
		while((Get-AzureKeyVaultCertificateOperation -VaultName $keyVaultName -Name "sslcertOrigin").Status -ne "completed"  )
		{
			$x++
			$y=$x*200	
			start-sleep -Milliseconds ($y)
		}
		Write-Host "Certificate Generated"
		$cert=Get-AzureKeyVaultCertificate -VaultName $keyVaultName -Name sslcertOrigin
		$certificate=[System.Convert]::ToBase64String($cert.Certificate.GetRawCertData())

		Write-Host "Set adminUsername in Key Vault: $keyVaultName";
		$adminUsernameSecureString = ConvertTo-SecureString $adminUsername -AsPlainText -Force 
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'adminUsername' -SecretValue $adminUsernameSecureString

		Write-Host "Set AdminPassword in Key Vault: $keyVaultName";
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'adminPassword' -SecretValue $adminPassword

		Write-Host "Set SqlServerServiceAccountPassword in Key Vault: $keyVaultName";
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sqlServerServiceAccountPassword' -SecretValue $sqlServerServiceAccountPassword

		Write-Host "Set sslCert in Key Vault: $keyVaultName";
		$sslCertSecureString = ConvertTo-SecureString "$certificate" -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sslCert' -SecretValue $sslCertSecureString

		#Write-Host "Set sslCertPassword in Key Vault: $keyVaultName";
		#$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sslPassword' -SecretValue $secureCertPassword

		Write-Host "Set domain in Key Vault: $keyVaultName";
		$domainSecureString = ConvertTo-SecureString $domain -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'domain' -SecretValue $domainSecureString

		Write-Host "Set guid in Key Vault: $keyVaultName";
		$guid = new-guid
		$guidSecureString = ConvertTo-SecureString $guid -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'guid' -SecretValue $guidSecureString

		Write-Host "Set Application Client ID in Key Vault: $keyVaultName";
		$aadClientIDSecureString = ConvertTo-SecureString $aadClientID -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientID' -SecretValue $aadClientIDSecureString

		Write-Host "Set Application Client Secret in Key Vault: $keyVaultName";
		$aadClientSecretSecureString =  $aadClientSecret 
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientSecret' -SecretValue $aadClientSecretSecureString

		Write-Host "Set Azure AD tenant id in Key Vault: $keyVaultName";
		$aadTenantIDSecureString = ConvertTo-SecureString $subscription.TenantId  -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadTenantId' -SecretValue $aadTenantIDSecureString

		Write-Host "Set Key Encryption URL in Key Vault: $keyVaultName";
		$keyEncryptionKeyUrlSecureString = ConvertTo-SecureString $keyEncryptionKeyUrl -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'keyEncryptionKeyURL' -SecretValue $keyEncryptionKeyUrlSecureString
	}

}



try{

	Write-Host "You will now be asked to create credentials for the administrator and sql service accounts. `n"

	Read-Host "Press ENTER key to continue ..."

	Write-Host "`n CREATE CREDENTIALS `n" -foregroundcolor green

	$adminUsername = Read-Host "Enter an admin username"

	$passwordNames = @("adminPassword","sqlServerServiceAccountPassword")
	$passwords = New-Object -TypeName PSObject


	for($i=0;$i -lt $passwordNames.Length;$i++){
	   checkPasswords -name $passwordNames[$i]
	}


	orchestration  -adminUsername $adminUsername -adminPassword $passwords.adminPassword -sqlServerServiceAccountPassword $passwords.sqlServerServiceAccountPassword

}
catch{
	Write-Host $PSItem.Exception.Message
	Write-Host "Thank You"
}