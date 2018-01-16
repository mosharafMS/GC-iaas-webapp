#Requires -Modules AzureRM,AzureRM.Profile
#Requires -RunAsAdministrator

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


Write-Host "`n LOGIN TO AZURE `n" -foregroundcolor green
$global:azureUsername = $null
$global:azurePassword = $null


########################################################################################################################
# LOGIN TO AZURE FUNCTION
########################################################################################################################
function loginToAzure
{
	Param(
			[Parameter(Mandatory=$true)]
			[int]$lginCount
		)

	Login-AzureRmAccount -EnvironmentName "AzureCloud" 

	if($?) {
		Write-Host "Login successful!"
	} else {
		if($lginCount -lt 3){
			$lginCount = $lginCount + 1

			Write-Host "Invalid Credentials! Try Logging in again"

			loginToAzure -lginCount $lginCount
		} else{

			Throw "Your credentials are incorrect or invalid exceeding maximum retries. Make sure you are using your Azure Government account information"

		}
	}
}

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

function Generate-Cert() {
		[CmdletBinding()]
		param(
        [securestring]$certPassword,
				[string]$domain
    )

		## This script generates a self-signed certificate

		$filePath = ".\"

		$cert = New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $domain
		$path = 'cert:\localMachine\my\' + $cert.thumbprint
		$certPath = $filePath + '\cert.pfx'
		$outFilePath = $filePath + '\cert.txt'
		Export-PfxCertificate -cert $path -FilePath $certPath -Password $certPassword
		$fileContentBytes = get-content $certPath -Encoding Byte
		[System.Convert]::ToBase64String($fileContentBytes) | Out-File $outFilePath

}
########################################################################################################################
# Create KeyVault or setup existing keyVault
########################################################################################################################
function orchestration
{
	Param(
		[string]$environmentName = "AzureCloud",
		[string]$location = "Canada Central",
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

	try
	{
		$subscription = Get-AzureRmSubscription  -SubscriptionId $SubscriptionId
		Write-Host "Using existing authentication"
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
					$defaultHomePage = 'http://contoso.com';
					$now = [System.DateTime]::Now;
					$oneYearFromNow = $now.AddYears(1);
					$aadPassword=[Guid]::NewGuid().ToString()
					$aadClientSecret = ConvertTo-SecureString $aadPassword  -AsPlainText -Force

					Write-Host "Creating new AAD application ($aadAppName)";
					$ADApp = New-AzureRmADApplication -DisplayName $aadAppName -HomePage $defaultHomePage -IdentifierUris $identifierUri  -StartDate $now -EndDate $oneYearFromNow -Password $aadClientSecret;
					$servicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $ADApp.ApplicationId;
					Write-Host "Sleeping for 20 seconds..." -ForegroundColor Yellow					
					Start-Sleep 20 #sleep for 20 seconds
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
							$aadClientSecret = Read-Host -Prompt "Aad application ($aadAppName) was already created, input corresponding aadClientSecret and hit ENTER. It can be retrieved from https://manage.windowsazure.com portal" ;
					}
					if(-not $aadClientSecret)
					{
							Write-Error "Aad application ($aadAppName) was already created. Re-run the script by supplying aadClientSecret parameter with corresponding secret from https://manage.windowsazure.com portal";
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

		$certPassword = New-RandomPassword
		$secureCertPassword = ConvertTo-SecureString $certPassword -AsPlainText -Force
		Generate-Cert -certPassword $secureCertPassword -domain $domain
		$certificate = Get-Content -Path ".\cert.txt" | Out-String

		Write-Host "Set Azure Key Vault Access Policy. Set AzureUserName in Key Vault: $keyVaultName";
		
		Write-Host "Set Azure Key Vault Access Policy. Set adminUsername in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'adminUsername' -Destination 'HSM'
		$adminUsernameSecureString = ConvertTo-SecureString $adminUsername -AsPlainText -Force 
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'adminUsername' -SecretValue $adminUsernameSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set AdminPassword in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'adminPassword' -Destination 'HSM'
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'adminPassword' -SecretValue $adminPassword

		Write-Host "Set Azure Key Vault Access Policy. Set SqlServerServiceAccountPassword in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'sqlServerServiceAccountPassword' -Destination 'HSM'
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sqlServerServiceAccountPassword' -SecretValue $sqlServerServiceAccountPassword

		Write-Host "Set Azure Key Vault Access Policy. Set sslCert in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'sslCert' -Destination 'HSM'
		$sslCertSecureString = ConvertTo-SecureString "$certificate" -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sslCert' -SecretValue $sslCertSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set sslCertPassword in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'sslPassword' -Destination 'HSM'
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'sslPassword' -SecretValue $secureCertPassword

		Write-Host "Set Azure Key Vault Access Policy. Set domain in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'domain' -Destination 'HSM'
		$domainSecureString = ConvertTo-SecureString $domain -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'domain' -SecretValue $domainSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set guid in Key Vault: $keyVaultName";
		$guid = new-guid
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'guid' -Destination 'HSM'
		$guidSecureString = ConvertTo-SecureString $guid -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'guid' -SecretValue $guidSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set Application Client ID in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'aadClientID' -Destination 'HSM'
		$aadClientIDSecureString = ConvertTo-SecureString $aadClientID -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientID' -SecretValue $aadClientIDSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set Application Client Secret in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'aadClientSecret' -Destination 'HSM'
		$aadClientSecretSecureString =  $aadClientSecret 
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadClientSecret' -SecretValue $aadClientSecretSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set Azure AD tenant id in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'aadTenantID' -Destination 'HSM'
		$aadTenantIDSecureString = ConvertTo-SecureString $subscription.TenantId  -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'aadTenantId' -SecretValue $aadTenantIDSecureString

		Write-Host "Set Azure Key Vault Access Policy. Set Key Encryption URL in Key Vault: $keyVaultName";
		$key = Add-AzureKeyVaultKey -VaultName $keyVaultName -Name 'keyEncryptionKeyURL' -Destination 'HSM'
		$keyEncryptionKeyUrlSecureString = ConvertTo-SecureString $keyEncryptionKeyUrl -AsPlainText -Force
		$secret = Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name 'keyEncryptionKeyURL' -SecretValue $keyEncryptionKeyUrlSecureString
	}

}



try{

	#there's no need to loginToAzure function. to be removed in v2
	#loginToAzure -lginCount 1

	Write-Host "You will now be asked to create credentials for the administrator and sql service accounts. `n"

	Write-Host "Press any key to continue ..."
	cmd /c pause | out-null

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
