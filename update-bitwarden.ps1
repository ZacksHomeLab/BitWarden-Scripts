<#
.Synopsis
    This script performs updates the BitWarden application.

.DESCRIPTION
    This script automatically performs a backup and then proceeds with updating the bitwarden application.

.PARAMETER PasswordFile
    The password file that holds the passphrase that will be used to encrypt backups.

.PARAMETER FinalBackupLocation
    The destination of the encrypted backup (e.g., '/backups')

.PARAMETER EmailAddresses
    The email address(es) in which notifications will be sent out to.

.PARAMETER ConfigFile
    The location of Bitwarden's configruation file. Default value is /opt/bitwarden/bwdata/config.yml

.PARAMETER DockerFile
    Bitwarden's docker file. Default value is /opt/bitwarden/bwdata/docker/docker-compose.yml
	
.PARAMETER BackupScriptLocation
	BitWarden's PowerShell script for performing backups. Default value is /opt/bitwarden/backup-bitwarden.ps1

.PARAMETER LogFile
    The location where the log file will reside. Default is ./update-bitwarden.log

.EXAMPLE
    ./Update-Bitwarden.ps1 -PasswordFile '/opt/bitwarden/password_file' -FinalBackupLocation '/backups'
    
    Perform an update on BitWarden while performing a BitWarden Backup where it will be saved in directory /backups
#>
[cmdletbinding()]
param (
    [parameter(Mandatory,
        Position=0)]
    [string]$PasswordFile,

    [parameter(Mandatory,
        Position=1)]
    [string]$FinalBackupLocation,

    [Parameter(Mandatory=$false)]
    [string[]]$EmailAddresses,

    [parameter(Mandatory=$false)]
    [string]$ConfigFile = '/opt/bitwarden/bwdata/config.yml',

    [parameter(Mandatory=$false)]
    [string]$DockerFile = '/opt/bitwarden/bwdata/docker/docker-compose.yml',
	
	[parameter(Mandatory=$false)]
	[string]$BackupScriptLocation = '/opt/bitwarden/backup-bitwarden.ps1',

    [Parameter(Mandatory=$false)]
    [string]$LogFile = './update-bitwarden.log'
)

#region VARIABLES
$script:LOG_FILE = $LogFile
$DATE = (Get-Date).toString('yyyy-MM-dd-HH-mm')

$BITWARDEN_DIR = '/opt/bitwarden'

# Our powershell script we use to create a BitWarden backup
$BITWARDEN_BACKUP_SCRIPT = $BackupScriptLocation

# /opt/bitwarden/bitwarden.sh
$CURRENT_BITWARDEN_SCRIPT_FILE_PATH = "$BITWARDEN_DIR/bitwarden.sh"
# /opt/bitwarden-2022-12-25-10-45
$TEMP_BITWARDEN_DIR = "$BITWARDEN_DIR-$DATE"
# /opt/bitwarden-2022-12-25-10-45/bitwarden.sh
$TEMP_BITWARDEN_SCRIPT_FILE_PATH = "$TEMP_BITWARDEN_DIR/bitwarden.sh"
# /opt/bitwarden-2022-12-25-10-45/bitwarden.sh.old
$OLD_BITWARDEN_SCRIPT_PATH = "$TEMP_BITWARDEN_DIR/bitwarden.sh.old"

# /opt/bitwarden/bwdata
$BWDATA_DIR = "$BITWARDEN_DIR/bwdata"
$CURRENT_SCRIPT_DIR = "$BWDATA_DIR/scripts"
# /opt/bitwarden/bwdata/scripts/run.sh
$CURRENT_RUN_FILE_PATH = "$CURRENT_SCRIPT_DIR/run.sh"
# /opt/bitwarden-2022-12-25-10-45/run.sh
$TEMP_BITWARDEN_RUN_FILE_PATH = "$TEMP_BITWARDEN_DIR/run.sh"
# /opt/bitwarden-2022-12-25-10-45/run.sh.old
$OLD_BITWARDEN_RUN_FILE_PATH = "$TEMP_BITWARDEN_DIR/run.sh.old"

# Retrieve the URL from the script file
$BITWARDEN_SCRIPT_URL = (Select-String -Path $CURRENT_BITWARDEN_SCRIPT_FILE_PATH -Pattern "BITWARDEN_SCRIPT_URL=").toString().split('BITWARDEN_SCRIPT_URL=')[-1].Replace('"','')
#endregion

#region Reset these used variables
$CURRENT_CORE_ID = $null
$CURRENT_WEB_ID = $null
$CURRENT_KEYCONNECTOR_ID = $null
$LATEST_CORE_ID = $null
$LATEST_WEB_ID = $null
$LATEST_KEYCONNECTOR_ID = $null
$KEY_CONNECTOR_ENABLED = $null
$DownloadBitWardenScript = $null
$DownloadBitWardenRunScript = $null
$UpdateBitWardenScriptPermissions = $null
$UpdateBitWardenRunScriptPermissions = $null
$BITWARDEN_RUN_SCRIPT_URL = $null
$ReplaceBitWardenScript = $null
$ReplaceBitWardenRunScript = $null
$Counter = 0
$State = $null
$UpdateState = $null
$BackupFileName = $null
$UpdateNeeded = $null
$DidWeUpdate = $null
$EmailData = $null
#endregion

#region Functions
function Write-Log
{
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param
    (
        [parameter(Mandatory = $false,
                    Position = 0)]
        [string]$Path = $script:LOG_FILE,
        [Parameter(Position = 1,
                    Mandatory = $true,
                    ParameterSetName = 'Default')]
        [ValidateSet('Verbose', 'Information', 'Warning', 'Error')]
        [String]$EntryType,
        [Parameter(Position = 2,
                    Mandatory = $true,
                    ParameterSetName = 'Default')]
        [String]$Message
    )
    
    begin
    {
        
        # Check if the log level an error or an error record was submitted
        if ($PSCmdlet.ParameterSetName -eq 'Default' -and $EntryType -eq 'Error')
        {
            $ErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $Message, 'Unknown', 'NotSpecified', $null
        }
    }
    
    process
    {
        # Output to file
        $Line = "[$EntryType][$((Get-Date).toString('yyyy-MM-dd:hh-mm-ss'))][$env:ComputerName], $Message"
        $Line | Out-File $Path -Append
        
        switch ($EntryType)
        {
            'Verbose'     { Write-Verbose -Message $Message }
            'Information' { Write-Output $Message }
            'Warning'     { Write-Warning -Message $Message }
            'Error'       { Write-Error -ErrorRecord $ErrorRecord }
        }
    }
}
function Download-BitWardenScript {
    [cmdletbinding()]
    param (
        [parameter(Mandatory,
            Position=0)]
        [string]$Path,

        [parameter(Mandatory,
            Position=1)]
        [string]$OutFile,

        [parameter(Mandatory,
            Position=2)]
        [string]$URL
    )

    BEGIN {
        $Success = $false
    }
    process {
        if (-not (Test-Path -Path $Path)) {
            # Create the temp directory if it does not exist
            New-Item -Path $Path -ItemType Directory | Out-Null
        }
        # Attempt to download the file and save it into the temp directory
        Write-Log -EntryType Verbose -Message "Download-BitWardenScript: Downloading BitWarden's script from $URL..."
        Invoke-WebRequest -Uri $URL -OutFile $OutFile

        # If we have the file, return success as true
        if (Test-Path -Path $OutFile) {
            Write-Log -EntryType Verbose -Message "Download-BitWardenScript: Successfully downloaded new BitWarden.sh script."
            $Success = $true
        } else {
            Write-Log -EntryType Warning -Message "Download-BitWardenScript: Did not successfully download BitWarden.sh Script."
        }
    }

    end {
        return $Success
    }
}

# Objective is to move /opt/bitwarden/bitwarden.sh to /opt/bitwarden-DATE/bitwarden.sh.old
# Then move the downloaded bitwarden.sh (/opt/bitwarden-DATE/bitwarden.sh) to /opt/bitwarden/bitwarden.sh
function Replace-BitWardenScript {
    [cmdletbinding()]
    param (
        [parameter(Mandatory, Position=0)]
        [string]$CurrentScript,
        [parameter(Mandatory, Position=1)]
        [string]$TempScript,
        [parameter(Mandatory, Position=2)]
        [string]$OldScript
    )

    BEGIN {
        $Success = $false
    }

    PROCESS {
        Write-Log -EntryType Verbose -Message "Replace-BitWardenScript: Attempting to move $CurrentScript to $OldScript."
        Copy-Item -Path $CurrentScript -Destination $OldScript -Force

        if ($?) {
            # Continue!!
            Write-Log -EntryType Verbose -Message "Replace-BitWardenScript: Attempting to replace $CurrentScript with $TempScript."
            Copy-Item -Path $CurrentScript -Destination $OldScript -Force

            if ($?) {
                $Success = $true
                Write-Log -EntryType Verbose -Message "Replace-BitWardenScript: Successfully replaced script."
            } else {
                Write-Log -EntryType Warning -Message "Replace-BitwardenScript: Failed replacing current script with temporary script."
            }
        }
    }
    END {
        return $Success
    }
}

function Update-BitWardenPermissions {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [string]$Path
    )

    BEGIN {
        $CORRECT_USER_PERMISSIONS = "bitwarden"
        $CORRECT_GROUP_PERMISSIONS = "bitwarden"
        $CORRECT_Unix_MODE = "-rwxr--r--"
        $SCRIPT_FILE = Get-Item -Path $Path
        $Success = $false
    }

    PROCESS {
        if ($SCRIPT_FILE.user -ne $CORRECT_USER_PERMISSIONS -and $SCRIPT_FILE.group -ne $CORRECT_GROUP_PERMISSIONS) {
            Write-Log -EntryType Verbose -Message "Update-BitWardenPermissions: Updating script user and group ownership to $($CORRECT_USER_PERMISSIONS):$($CORRECT_GROUP_PERMISSIONS)"
            chown "$($CORRECT_USER_PERMISSIONS):$($CORRECT_GROUP_PERMISSIONS)" $($SCRIPT_FILE).FullName
        } elseif ($SCRIPT_FILE.group -ne $CORRECT_GROUP_PERMISSIONS) {
            Write-Log -EntryType Verbose -Message "Update-BitWardenPermissions: Updating script group ownership to $($CORRECT_GROUP_PERMISSIONS)"
            chown ":$($CORRECT_GROUP_PERMISSIONS)" $($SCRIPT_FILE).FullName
        } elseif ($SCRIPT_FILE.User -ne $CORRECT_USER_PERMISSIONS) {
            Write-Log -EntryType Verbose -Message "Update-BitWardenPermissions: Updating script user ownership to $($CORRECT_USER_PERMISSIONS)"
            chown $($CORRECT_USER_PERMISSIONS) $($SCRIPT_FILE).FullName
        }

        if ($SCRIPT_FILE.unixmode -ne $CORRECT_Unix_MODE) {
            Write-Log -EntryType Verbose -Message "Update-BitWardenPermissions: Updating script UnixMode permissions to $($CORRECT_Unix_MODE)"
            chmod u+x $($SCRIPT_FILE).FullName
        }

        Write-Log -EntryType Verbose -Message "Update-BitWardenPermissions: Validate changes to current script file.."
        $NewPermissions = Get-Item -Path $Path
        if ($NewPermissions.user -eq $CORRECT_USER_PERMISSIONS -and $NewPermissions.group -eq $CORRECT_GROUP_PERMISSIONS -and $NewPermissions.UnixMode -eq $CORRECT_Unix_MODE) {
            Write-Log -EntryType Verbose -Message "Update-BitWardenPermissions: The script file has the correct permissions."
            $Success = $true
        }
    }
    END {
        return $Success
    }
}

function Get-WebID {
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DockerFile
    )
    
    end {
        return docker-compose --file $DockerFile ps -q web
    }
}

function Get-CoreID {
    param (
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DockerFile
    )
    
    end {
        return docker-compose --file $DockerFile ps -q admin
    }
}

function Get-KeyConnectorID {
    param (
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DockerFile
    )
    
    end {
        return docker-compose --file $DockerFile ps -q key-connector
    }
}
function Confirm-Update {
	[cmdletbinding()]
	param (
        [parameter(Mandatory,
            Position=0)]
        [ValidateNotNullOrEmpty()]
		[string]$ConfigFile,

        [parameter(Mandatory,
            Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$DockerFile,

        [parameter(Mandatory,
            Position=2)]
        [string]$NewScript
	)
	
	BEGIN {
		
        $WEB_ID = Get-WebID -DockerFile $DockerFile
        $WEB_ID = docker inspect --format='{{.Config.Image}}:' $WEB_ID
        $CORE_ID = Get-CoreID -DockerFile $DockerFile
        $CORE_ID = docker inspect --format='{{.Config.Image}}:' $CORE_ID

        $COREVERSION = (Select-String -Path $NewScript -Pattern "COREVERSION=").tostring().split('=')[-1].replace('"','')
        $WEBVERSION = (Select-String -Path $NewScript -Pattern "WEBVERSION=").tostring().split('=')[-1].replace('"','')
        $KEYCONNECTORVERSION = (Select-String -Path $NewScript -Pattern "KEYCONNECTORVERSION=").tostring().split('=')[-1].replace('"','')

		# Retrieve the key connector value, should return true or false
		$KEY_CONNECTOR_ENABLED = (Select-String -Path $ConfigFile -Pattern "enable_key_connector").toString().split(':')[-1].trim()

        $UpdateNeeded = $true
	}
	
	PROCESS {

		if ($KEY_CONNECTOR_ENABLED -eq 'true') {
            $KEYCONNECTOR_ID = Get-KeyConnectorID -DockerFile $DockerFile
            $KEYCONNECTOR_ID = docker inspect --format='{{.Config.Image}}:' $KEYCONNECTOR_ID 
        }

        if ($null -ne $KEYCONNECTOR_ID -and $CORE_ID -match $COREVERSION -and $WEB_ID -match $WEBVERSION -and $KEYCONNECTOR_ID -match $KEYCONNECTORVERSION) {
            Write-Log -EntryType Verbose -Message "Confirm-Update: We're fully updated."
            $UpdateNeeded = $false
        } elseif ($CORE_ID -match $COREVERSION -and $WEB_ID -match $WEBVERSION) {
            Write-Log -EntryType Verbose -Message "Confirm-Update: We're fully updated."
            $UpdateNeeded = $false
        } else {
            Write-Log -EntryType Verbose -Message "Confirm-Update: We can update!"
        }
	}

    END {
        return $UpdateNeeded
    }
}

function Cleanup-Items {
    [cmdletbinding()]
    param (
        [string]$Path = $TEMP_BITWARDEN_DIR
    )

    PROCESS {
        Write-Log -EntryType Verbose -Message "Cleanup-Items: Removing directory $Path..."
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Send-Email {
    [cmdletbinding()]
    param (
        [string]$From = "",
        [string]$SMTPServer = "",
        [string]$Subject = "",
        [String]$Body,
        [System.Object[]]$Data,
        [string[]]$EmailAddresses
    )
    
    BEGIN {
        $Body = $null  

        $CURRENT_CORE_ID = $Data.CURRENT_CORE_ID
        $LATEST_CORE_ID = $Data.LATEST_CORE_ID
        $CURRENT_WEB_ID = $Data.CURRENT_WEB_ID
        $LATEST_WEB_ID = $Data.LATEST_WEB_ID
        $CURRENT_KEYCONNECTOR_ID = $null
        $LATEST_KEYCONNECTOR_ID = $null
        if ($null -ne $Data.CURRENT_KEYCONNECTOR_ID) {
            $CURRENT_KEYCONNECTOR_ID = $Data.CURRENT_KEYCONNECTOR_ID
            $LATEST_KEYCONNECTOR_ID = $Data.LATEST_KEYCONNECTOR_ID
        }
        $BackupFile = $Data.BACKUP_FILE
    }

    PROCESS {
        if ($null -ne $CURRENT_KEYCONNECTOR_ID) {
            $body = @"
            <p>Successfully Updated BitWarden from the following verion:</p>
        <table style="width: 40%" style="border-collapse: collapse; border: 1px solid #008080;">
         <tr>
            <td colspan="2" bgcolor="#175ddc" style="padding-left: 5px; color: #FFFFFF; font-size: large; height: 35px;"> 
                Old BitWarden Software Version
            </td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Core ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$CURRENT_CORE_ID</b></td>
         </tr>
          <tr style="height: 39px; border: 1px solid #008080">
          <td style="padding-left: 20px; width: 201px; font-size: medium; height: 39px">Web ID</td>
         <td style="text-align: left; font-size: medium; height: 39px; width: 233px;">
          <b>$CURRENT_WEB_Id</b></td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Key Connector ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$CURRENT_KEYCONNECTOR_ID</b></td>
         </tr>
        </table>
        <p>To the following version:</p>
        <table style="width: 40%" style="border-collapse: collapse; border: 1px solid #008080;">
         <tr>
            <td colspan="2" bgcolor="#175ddc" style="padding-left: 5px; color: #FFFFFF; font-size: large; height: 35px;"> 
                New BitWarden Software Version
            </td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Core ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$LATEST_CORE_ID</b></td>
         </tr>
          <tr style="height: 39px; border: 1px solid #008080">
          <td style="padding-left: 20px; width: 201px; font-size: medium; height: 39px">Web ID</td>
         <td style="text-align: left; font-size: medium; height: 39px; width: 233px;">
          <b>$LATEST_WEB_ID</b></td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Key Connector ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$LATEST_KEYCONNECTOR_ID</b></td>
         </tr>
        </table>
        <p>If there's a bug with this release, perform the following steps to restore BitWarden back to the previous version:</p>
        <ul>
          <li>SSH into your BitWarden Server and run the following commands::</li>
          <ul>
          <li><p>Open PowerShell: <span style="border: 1px solid black">sudo pwsh </span></p></li>
          <li><p>Browse to BitWarden's Directory: <span style="border: 1px solid black">cd /opt/bitwarden </span></p></li>
          <li><p>Restore Backup: <span style="border: 1px solid black">./Restore-BitWardenBackup.ps1 -Passwordfile /opt/bitwarden/password_file -BackupFile $BackupFile</span></p></li>
          </ul>
        </ul>
"@
        } else {
            $body = @"
            <p>Successfully Updated BitWarden from the following verion:</p>
        <table style="width: 40%" style="border-collapse: collapse; border: 1px solid #008080;">
         <tr>
            <td colspan="2" bgcolor="#175ddc" style="padding-left: 5px; color: #FFFFFF; font-size: large; height: 35px;"> 
                Old BitWarden Software Version
            </td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Core ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$CURRENT_CORE_ID</b></td>
         </tr>
          <tr style="height: 39px; border: 1px solid #008080">
          <td style="padding-left: 20px; width: 201px; font-size: medium; height: 39px">Web ID</td>
         <td style="text-align: left; font-size: medium; height: 39px; width: 233px;">
          <b>$CURRENT_WEB_Id</b></td>
         </tr>
        </table>
        <p>To the following version:</p>
        <table style="width: 40%" style="border-collapse: collapse; border: 1px solid #008080;">
         <tr>
            <td colspan="2" bgcolor="#175ddc" style="padding-left: 5px; color: #FFFFFF; font-size: large; height: 35px;"> 
                New BitWarden Software Version
            </td>
         </tr>
         <tr style="border-bottom-style: solid; border-bottom-width: 1px; padding-bottom: 1px">
            <td style="padding-left: 20px; width: 201px; font-size: medium; height: 35px">Core ID</td>
            <td style="text-align: left; font-size: medium; height: 35px; width: 233px;">
            <b>$LATEST_CORE_ID</b></td>
         </tr>
          <tr style="height: 39px; border: 1px solid #008080">
          <td style="padding-left: 20px; width: 201px; font-size: medium; height: 39px">Web ID</td>
         <td style="text-align: left; font-size: medium; height: 39px; width: 233px;">
          <b>$LATEST_WEB_ID</b></td>
         </tr>
        </table>
        <p>If there's a bug with this release, perform the following steps to restore BitWarden back to the previous version:</p>
        <ul>
          <li>SSH into your BitWarden Server and run the following commands::</li>
          <ul>
          <li><p>Open PowerShell: <span style="border: 1px solid black">sudo pwsh </span></p></li>
          <li><p>Browse to BitWarden's Directory: <span style="border: 1px solid black">cd /opt/bitwarden </span></p></li>
          <li><p>Restore Backup: <span style="border: 1px solid black">./Restore-BitWardenBackup.ps1 -Passwordfile /opt/bitwarden/password_file -BackupFile $BackupFile</span></p></li>
          </ul>
        </ul>
"@
        }
        
    }

    END {
        Send-MailMessage -To $EmailAddresses -From $From -Subject $Subject -BodyAsHtml -Body $Body -SmtpServer $SMTPServer
    }
}
#endregion

#region ExitCodes
$exitcode_NoUpdateNeeded = 0
$exitcode_NoBitwardenURL = 9
$exitcode_MissingConfigFile = 10
$exitcode_MissingDockerCommand = 11
$exitcode_MissingDockerComposeCommand = 12
$exitcode_MissingDockerFile = 13
$exitcode_MissingScriptsDirectory = 14
$exitcode_FailDownloadingSCript = 15
$exitcode_FailReplacingScript = 16
$exitcode_FailUpdatingPermissions = 17
$exitcode_FailDownloadingRunScript = 18
$exitcode_FailReplacingRunScript = 19
$exitcode_FailUpdatingPermissionsOnRunFile = 20
$exitcode_MissingPWSHCommand = 21
$exitcode_TooLongForBackup = 22
$exitcode_BackupJobCompletedButNoBackup = 23
$exitcode_TooLongForUpdate = 24
$exitcode_MissingBitWardenBackupScript = 25
$exitcode_UpdateFailed = 26
#endregion

#region Preconditions
Write-Log -EntryType Information -Message "Main: Checking preconditions before we start..."

if ($null -eq $BITWARDEN_SCRIPT_URL) {
    Write-Log -EntryType Error -Message "Main: BitWarden Script URL is null. Cannot proceed."
    exit $exitcode_NoBitwardenURL
}

if (-not (Test-Path -Path $ConfigFile)) {
    Write-Log -EntryType Error -Message "Main: Cannot find configuration file $ConfigFile."
    exit $exitcode_MissingConfigFile
}

if (-not (Get-Command 'docker' -ErrorAction SilentlyContinue)) {
    Write-Log -EntryType Error -Message "Main: Missing command Docker, is it installed?"
    exit $exitcode_MissingDockerCommand
}

if (-not (Get-Command 'docker-compose' -ErrorAction SilentlyContinue)) {
    Write-Log -EntryType Error -Message "Main: Missing command Docker-compose, is it installed?"
    exit $exitcode_MissingDockerComposeCommand
}

if (-not (Get-Command 'pwsh' -ErrorAction SilentlyContinue)) {
    Write-Log -EntryType Error -Message "Main: Missing command PWSH, is it installed?"
    exit $exitcode_MissingPWSHCommand
}

if (-not (Test-Path -Path $DockerFile)) {
    Write-Log -EntryType Error -Message "Main: Missing docker configuration file. Does $DockerFile exist?"
    exit $exitcode_MissingDockerFile
}

if (-not (Test-Path -Path $BWDATA_DIR)) {
    Write-Log -EntryType Error -Message "Main: Cannot find Bitwarden's script directory. Does $BWDATA_DIR exist?"
    exit $exitcode_MissingScriptsDirectory
}
if (-not (Test-Path -Path $BITWARDEN_BACKUP_SCRIPT)) {
    Write-Log -EntryType Warning -Message "Main: Cannot find Bitwarden's Backup Script. Does $BITWARDEN_BACKUP_SCRIPT exist?"
    exit $exitcode_MissingBitWardenBackupScript
}
#endregion

#region Retrieve current versions of BitWarden
$CURRENT_CORE_ID = Get-CoreID -DockerFile $DockerFile
$CURRENT_CORE_ID = docker inspect --format='{{.Config.Image}}:' $CURRENT_CORE_ID
$CURRENT_WEB_ID = Get-WebID -DockerFile $DockerFile
$CURRENT_WEB_ID = docker inspect --format='{{.Config.Image}}:' $CURRENT_WEB_ID
$KEY_CONNECTOR_ENABLED = (Select-String -Path $ConfigFile -Pattern "enable_key_connector").toString().split(':')[-1].trim()
if ($KEY_CONNECTOR_ENABLED -eq 'true') {
    $CURRENT_KEYCONNECTOR_ID = Get-KeyConnectorID -DockerFile $DockerFile
    $CURRENT_KEYCONNECTOR_ID = docker inspect --format='{{.Config.Image}}:' $CURRENT_KEYCONNECTOR_ID
}
Write-Log -EntryType Information -Message "Main: Current Core ID: $CURRENT_CORE_ID"
Write-Log -EntryType Information -Message "Main: Current Web ID: $CURRENT_WEB_ID"
if ($null -ne $CURRENT_KEYCONNECTOR_ID) {
    Write-Log -EntryType Information -Message "Main: Current KeyConnector ID: $CURRENT_KEYCONNECTOR_ID"
}
#endregion


#region Download and setup bitwarden.sh
# Download the new BitWarden Run SCript
Write-Log -EntryType Information -Message "Main: Downloading latest bitwarden script..."
$DownloadBitWardenScript = Download-BitWardenScript -Path $TEMP_BITWARDEN_DIR -OutFile $TEMP_BITWARDEN_SCRIPT_FILE_PATH -URL $BITWARDEN_SCRIPT_URL

# Exit if we failed to download script
if (-not $DownloadBitWardenScript) {
    Write-Log -EntryType Warning -Message "Main: Failed downloading the BitWarden script at URL $BITWARDEN_SCRIPT_URL."
    Cleanup-Items
    exit $exitcode_FailDownloadingScript
}

# Update permissions on the downloaded bitwarden.sh
Write-Log -EntryType Information -Message "Main: Updating permissions on bitwarden script file $TEMP_BITWARDEN_SCRIPT_FILE_PATH..."
$UpdateBitWardenScriptPermissions = Update-BitWardenPermissions -Path $TEMP_BITWARDEN_SCRIPT_FILE_PATH

# exit if we failed to update permissions
if (-not $UpdateBitWardenScriptPermissions) {
    Write-Log -EntryType Warning -Message "Main: Failed updating permissions on script file $TEMP_BITWARDEN_SCRIPT_FILE_PATH."
    Cleanup-Items
    exit $exitcode_FailUpdatingPermissions
}
#endregion

#region Download and setup run.sh
# Retrieve the RUN Script URL from the script file
$BITWARDEN_RUN_SCRIPT_URL = (Select-String -Path $CURRENT_BITWARDEN_SCRIPT_FILE_PATH -Pattern "RUN_SCRIPT_URL=").toString().split('RUN_SCRIPT_URL=')[-1].Replace('"','')

Write-Log -EntryType Information -Message "Main: Downloading latest bitwarden run script..."
$DownloadBitWardenRunScript = Download-BitWardenScript -Path $TEMP_BITWARDEN_DIR -OutFile $TEMP_BITWARDEN_RUN_FILE_PATH -URL $BITWARDEN_RUN_SCRIPT_URL

if (-not $DownloadBitWardenRunScript) {
    Write-Log -EntryType Warning -Message "Main: Failed downloading the BitWarden run script at URL $BITWARDEN_RUN_SCRIPT_URL."
    Cleanup-Items
    exit $exitcode_FailDownloadingRunScript
}

# Update permissions on the downloaded run.sh
Write-Log -EntryType Information -Message "Main: Updating permissions on run script $TEMP_BITWARDEN_RUN_FILE_PATH..."
$UpdateBitWardenRunScriptPermissions = Update-BitWardenPermissions -Path $TEMP_BITWARDEN_RUN_FILE_PATH

# exit if we failed to update permissions
if (-not $UpdateBitWardenRunScriptPermissions) {
    Write-Log -EntryType Warning -Message "Main: Failed updating permissions on run file $CURRENT_RUN_FILE_PATH."
    Cleanup-Items
    exit $exitcode_FailUpdatingPermissionsOnRunFile
}
#endregion

#region Can we update?
Write-Log -EntryType Information -Message "Main: Checking if we can update..."
$UpdateNeeded = Confirm-Update -ConfigFile $ConfigFile -DockerFile $DockerFile -NewScript $TEMP_BITWARDEN_SCRIPT_FILE_PATH
if (-not $UpdateNeeded) {
    Write-Log -EntryType Information -Message "Main: We do not need to update, removing downloaded files."
    Cleanup-Items
    exit $exitcode_NoUpdateNeeded
}
Write-Log -EntryType Information -Message "Main: We can update!"
#endregion

#region Create Backup
$BackupFileName = "full-backup-$((Get-Date).toString('yyyy-MM-dd-hh-mm')).tar"
$EncryptedBackupFileName = "$FinalBackupLocation/$BackupFileName.gpg"
Write-Log -EntryType Information -Message "Main: Attempting to create backup $BackupFileName before we update..."

# Check if Job 'CreateBackup' exists. If it does, remove it
if (Get-Job -Name 'CreateBackup' -ErrorAction SilentlyContinue) {
    if ((Get-Job -Name 'CreateBackup').State -eq 'Running') {
        Get-Job -Name 'CreateBackup' | Stop-Job
    }
    Get-Job -Name 'CreateBackup' | Remove-Job
}

# Start the Backup
Start-Job -Name "CreateBackup" -ScriptBlock {pwsh -File $using:BITWARDEN_BACKUP_SCRIPT -PasswordFile $using:PasswordFile -FinalBackupLocation $using:FinalBackupLocation -All -BackupName $using:BackupFileName}
$State = (Get-Job -Name 'CreateBackup').State
$Counter = 0
do {
    Write-Log -EntryType Verbose -Message "Main: Waiting for backup to finish..."
    Start-Sleep -Seconds 5
    $State = (Get-Job -Name 'CreateBackup').State
    $Counter += 5
    
} until ($State -ne 'Running' -or $Counter -gt 240)

if ($Counter -gt 240 -and $State -ne 'Completed') {
    Write-Log -EntryType Warning -Message "Main: Script waited 4 minutes to create a backup but it did not finish..."
    Receive-job -Name 'CreateBackup' | Out-File -FilePath $LogFile -Append

    if ((Get-Job -Name 'CreateBackup').State -eq 'Running') {
        Get-Job -Name 'CreateBackup' | Stop-Job
    }
    Get-Job -Name 'CreateBackup' | Remove-Job
    Cleanup-Items
    exit $exitcode_TooLongForBackup
}

if ($State -eq 'Completed') {
    Write-Log -EntryType Information -Message "Main: The backup job has completed, let's see if it exists..."
    if (-not (Test-Path -Path $EncryptedBackupFileName)) {
        Write-Log -EntryType Warning -Message "Main: Backup File does not exist, dumping the job details into our log file.."
        Receive-job -Name 'CreateBackup' | Out-File -FilePath $LogFile -Append
        Get-Job -Name 'CreateBackup' | Remove-Job
        Cleanup-Items
        exit $exitcode_BackupJobCompletedButNoBackup
    } else {
        Write-Log -EntryType Information -Message "Main: Found the backup!"
        # Append the job results to our log file and remove the backup
        Receive-job -Name 'CreateBackup' | Out-File -FilePath $LogFile -Append
        Get-Job -Name 'CreateBackup' | Remove-Job
    }
}
#endregion

#region Replace bitwarden.sh & run.sh
Write-Log -EntryType Information -Message "Main: Saving the current run script for just in case purposes and moving the new run script in its place..."
$ReplaceBitWardenScript = Replace-BitWardenScript -CurrentScript $CURRENT_BITWARDEN_SCRIPT_FILE_PATH -TempScript $TEMP_BITWARDEN_SCRIPT_FILE_PATH -OldScript $OLD_BITWARDEN_SCRIPT_PATH

# Exit if we failed to replace script
if (-not $ReplaceBitWardenScript) {
    Write-Log -EntryType Warning -Message "Main: Failed replacing the downloaded script with the current BitWarden script."
    Cleanup-Items
    exit $exitcode_FailReplacingScript
}


# We downloaded the script, time to move our current run file to a temporarily location and replace it with the new run script.
Write-Log -EntryType Information -Message "Main: Saving the current run script for just in case purposes and moving the new run script in its place..."
$ReplaceBitWardenRunScript = Replace-BitWardenScript -CurrentScript $CURRENT_RUN_FILE_PATH -TempScript $TEMP_BITWARDEN_RUN_FILE_PATH -OldScript $OLD_BITWARDEN_RUN_FILE_PATH

# Exit if we failed to replace script
if (-not $ReplaceBitWardenRunScript) {
    Write-Log -EntryType Warning -Message "Main: Failed replacing the downloaded run script with the current run script."
    Cleanup-Items
    exit $exitcode_FailReplacingRunScript
}
#endregion

# Set the location to /opt/bitwarden/
Write-Log -EntryType Information -Message "Main: Attempting to update BitWarden..."
Set-Location -Path $BITWARDEN_DIR

#region Update Bitwarden
Write-Log -EntryType Information -Message "Main: Creating background job for ./bitwarden.sh update"
# Check if Job 'Update' exists. If it does, remove it
if (Get-Job -Name 'Update' -ErrorAction SilentlyContinue) {
    if ((Get-Job -Name 'Update').State -eq 'Running') {
        Get-Job -Name 'Update' | Stop-Job
    }
    Get-Job -Name 'Update' | Remove-Job
}
Start-Job -Name 'Update' -ScriptBlock {bash $using:CURRENT_BITWARDEN_SCRIPT_FILE_PATH update}
$UpdateState = (Get-Job -Name 'Update').State
$Counter = 0
do {
    Write-Log -EntryType Verbose -Message "Main: Waiting for Update to finish..."
    Start-Sleep -Seconds 10
    $UpdateState = (Get-Job -Name 'Update').State
    $Counter += 10

} until ($UpdateState -ne 'Running' -or $Counter -gt 600)

if ($Counter -gt 600 -and $UpdateState -ne 'Completed') {
    Write-Log -EntryType Warning -Message "Main: Script waited 10 minutes for bitwarden to update but it did not finish..."
    Receive-job -Name 'Update' | Out-File -FilePath $LogFile -Append

    if ((Get-Job -Name 'Update').State -eq 'Running') {
        Get-Job -Name 'Update' | Stop-Job
    }
    Get-Job -Name 'Update' | Remove-Job
    Cleanup-Items
    exit $exitcode_TooLongForUpdate
}

# Update job was completed, did we get an update?
if ($UpdateState -eq 'Completed') {
    Write-Log -EntryType Information -Message "Main: Checking if we actually updated..."
    # This should return false if we updated
    $DidWeUpdate = Confirm-Update -ConfigFile $ConfigFile -DockerFile $DockerFile -NewScript $CURRENT_BITWARDEN_SCRIPT_FILE_PATH
    if (-not $DidWeUpdate) {
        # Append the job results to our log file and remove the backup
        Receive-job -Name 'Update' | Out-File -FilePath $LogFile -Append
        Get-Job -Name 'Update' | Remove-Job

        Write-Log -EntryType Information -Message "Main: Successfully updated!"
    } else {
        Write-Log -EntryType Warning -Message "Main: Update failed. Storing results of job in the log file."
        # Append the job results to our log file and remove the backup
        Receive-job -Name 'Update' | Out-File -FilePath $LogFile -Append
        Get-Job -Name 'Update' | Remove-Job
        # Cleanup Items
        Cleanup-Items
        $exitcode_UpdateFailed
    }
}
#endregion

#region Send Email
Write-Log -EntryType Information -Message "Main: Retrieve new updated version values for BitWarden..."

$LATEST_CORE_ID = Get-CoreID -DockerFile $DockerFile
$LATEST_CORE_ID = docker inspect --format='{{.Config.Image}}:' $LATEST_CORE_ID

$LATEST_WEB_ID = Get-WebID -DockerFile $DockerFile
$LATEST_WEB_ID = docker inspect --format='{{.Config.Image}}:' $LATEST_WEB_ID

$KEY_CONNECTOR_ENABLED = (Select-String -Path $ConfigFile -Pattern "enable_key_connector").toString().split(':')[-1].trim()
if ($KEY_CONNECTOR_ENABLED -eq 'true') {
    $LATEST_KEYCONNECTOR_ID = Get-KeyConnectorID -DockerFile $DockerFile
    $LATEST_KEYCONNECTOR_ID = docker inspect --format='{{.Config.Image}}:' $LATEST_KEYCONNECTOR_ID 
}

Write-Log -EntryType Information -Message "Main: Latest Core ID: $LATEST_CORE_ID"
Write-Log -EntryType Information -Message "Main: Latest Web ID: $LATEST_WEB_ID"
if ($null -ne $LATEST_KEYCONNECTOR_ID) {
    Write-Log -EntryType Information -Message "Main: Latest KeyConnector ID: $LATEST_KEYCONNECTOR_ID"
}

# Send email of the update.
$EmailData = "" | Select-Object CURRENT_CORE_ID, LATEST_CORE_ID, CURRENT_WEB_ID, LATEST_WEB_ID, CURRENT_KEYCONNECTOR_ID, LATEST_KEYCONNECTOR_ID, BACKUP_FILE
$EmailData.CURRENT_CORE_ID = $CURRENT_CORE_ID
$EmailData.LATEST_CORE_ID = $LATEST_CORE_ID
$EmailData.CURRENT_WEB_ID = $CURRENT_WEB_ID
$EmailData.LATEST_WEB_ID = $LATEST_WEB_ID
if ($null -ne $CURRENT_KEYCONNECTOR_ID) {
    $EmailData.CURRENT_KEYCONNECTOR_ID = $CURRENT_KEYCONNECTOR_ID
    $EmailData.LATEST_KEYCONNECTOR_ID = $LATEST_KEYCONNECTOR_ID
}
$EmailData.BACKUP_FILE = $EncryptedBackupFileName

#Send-Email -Data $EmailData -EmailAddresses $EmailAddresses
#endregion

#region Cleanup
Write-Log -EntryType Information -Message "Main: Before exiting, let's cleanup our created directory and downloaded files..."
Cleanup-Items
#endregion
