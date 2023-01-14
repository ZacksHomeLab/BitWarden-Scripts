<#
.Synopsis
    This script performs updates the BitWarden application.
.DESCRIPTION
    This script automatically performs a backup and then proceeds with updating the bitwarden application.
.PARAMETER PasswordFile
    The password file that holds the passphrase that will be used to encrypt backups.
.PARAMETER PasswordPhrase
    The Password Phrase that will be used to ecnrypt backups. NOTE: This must be as a SecuredString (e.g., ("Password" | ConverTo-SecureString -AsPlainText) )
.PARAMETER FinalBackupLocation
    The destination of the encrypted backup (e.g., '/backups')
.PARAMETER ConfigFile
    The location of Bitwarden's configruation file. Default value is /opt/bitwarden/bwdata/config.yml
.PARAMETER DockerFile
    Bitwarden's docker file. Default value is /opt/bitwarden/bwdata/docker/docker-compose.yml
.PARAMETER BitWardenDir
    The installation directory of BitWarden (e.g., '/opt/bitwarden')
.PARAMETER BackupScriptLocation
	BitWarden's PowerShell script for performing backups. Default value is /opt/bitwarden/backup-bitwarden.ps1
.PARAMETER LogFile
    The location where the log file will reside. Default is ./update-bitwarden.log
.PARAMETER EmailAddresses
    The email address(es) in which notifications will be sent out to.
.PARAMETER SMTPServer
    The SMTP Server the script will use to send emails from.
.PARAMETER From
    The Email Address that will be sending said emails.
.PARAMETER SkipBackup
    Use this switch if you want to skip the backup before updating.
.EXAMPLE
    ./Update-Bitwarden.ps1 -PasswordFile '/opt/bitwarden/password_file' -FinalBackupLocation '/backups'
    
    Perform an update on BitWarden while performing a BitWarden Backup where it will be saved in directory /backups
.EXAMPLE
    ./update-bitwarden.ps1 -PasswordPhrase ("MY_PASSWORD" | ConvertTo-SecureString -AsPlainText) -FinalBackupLocation '/backups' -EmailAddresses @("test.email@company.com", "test2.email@company.com") -SMTPServer 'contoso-com.mail.protection.outlook.com' -from 'bitwarden@company.com'

    Perform an update on Bitwarden and email the recipients in EmailAddresses with the provided SMTP settings.
.NOTES
    Author - Zack
.LINK
    GitHub (Scripts) - https://github.com/ZacksHomeLab/BitWarden-Scripts
    GitHub (Documentation) - https://github.com/ZacksHomeLab/BitWarden
#>
[cmdletbinding()]
param (
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='PasswordFile')]
        [ValidateScript({Test-Path -Path $_})]
    [string]$PasswordFile,

    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='PasswordPhrase')]
        [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]$PasswordPhrase,

    [parameter(Mandatory,
        Position=1)]
        [ValidateScript({Test-Path -Path $_})]
    [string]$FinalBackupLocation,

    [parameter(Mandatory=$false,
        Position=2,
        ValueFromPipelineByPropertyName)]
        [ValidateScript({Test-Path -Path $_})]
    [string]$ConfigFile = '/opt/bitwarden/bwdata/config.yml',

    [parameter(Mandatory=$false,
        Position=3,
        ValueFromPipelineByPropertyName)]
    [ValidateScript({Test-Path -Path $_})]
    [string]$DockerFile = '/opt/bitwarden/bwdata/docker/docker-compose.yml',

    [parameter(Mandatory=$false,
        Position=4)]
        [ValidateScript({Test-Path -Path $_})]
    [string]$BitWardenDir = '/opt/bitwarden',
	
	[parameter(Mandatory=$false,
        Position=5)]
        [ValidateScript({Test-Path -Path $_})]
	[string]$BackupScriptLocation = '/opt/bitwarden/backup-bitwarden.ps1',

    [Parameter(Mandatory=$false,
        Position=6)]
    [string]$LogFile = './update-bitwarden.log',

    [Parameter(Mandatory=$false,
        Position=7,
        helpMessage="What Email Addresses should receive the update report?")]
    [string[]]$EmailAddresses,

    [Parameter(Mandatory=$false,
        Position=8,
        helpMessage="What's your SMTP Server's address? (e.g., contoso-com.mail.protection.outlook.com)")]
    [string]$SMTPServer,

    [Parameter(Mandatory=$false,
        Position=9,
        HelpMessage="What's the email address that'll send the email?")]
    [string]$From,

    [Parameter(Mandatory=$false,
        Position=10)]
    [switch]$SkipBackup
)

BEGIN {
    #region VARIABLES
    $script:LOG_FILE = $LogFile
    $DATE = (Get-Date).toString('yyyy-MM-dd-HH-mm')

    # Example BitWarden Directory: '/opt/bitwarden'
    $BITWARDEN_DIR = $BitWardenDir

    # Our powershell script we use to create a BitWarden backup
    $BITWARDEN_BACKUP_SCRIPT = $BackupScriptLocation

    # Example Current BitWarden Directory: /opt/bitwarden/bitwarden.sh
    $CURRENT_BITWARDEN_SCRIPT_FILE_PATH = "$BITWARDEN_DIR/bitwarden.sh"
    # Example Temp BitWArden Directory: /opt/bitwarden-2022-12-25-10-45
    $TEMP_BITWARDEN_DIR = "$BITWARDEN_DIR-$DATE"
    # Example Script File Path: /opt/bitwarden-2022-12-25-10-45/bitwarden.sh
    $TEMP_BITWARDEN_SCRIPT_FILE_PATH = "$TEMP_BITWARDEN_DIR/bitwarden.sh"
    # Example File Name: /opt/bitwarden-2022-12-25-10-45/bitwarden.sh.old
    $OLD_BITWARDEN_SCRIPT_PATH = "$TEMP_BITWARDEN_DIR/bitwarden.sh.old"

    # Example bwdata directory: /opt/bitwarden/bwdata
    $BWDATA_DIR = "$BITWARDEN_DIR/bwdata"
    # Example BitWarden Scripts directory: /opt/bitwarden/bwdata/scripts
    $CURRENT_SCRIPT_DIR = "$BWDATA_DIR/scripts"
    # Example BitWarden Run File path: /opt/bitwarden/bwdata/scripts/run.sh
    $CURRENT_RUN_FILE_PATH = "$CURRENT_SCRIPT_DIR/run.sh"
    # Example Temp Run File Path: /opt/bitwarden-2022-12-25-10-45/run.sh
    $TEMP_BITWARDEN_RUN_FILE_PATH = "$TEMP_BITWARDEN_DIR/run.sh"
    # Example Temp Old Run File Path: /opt/bitwarden-2022-12-25-10-45/run.sh.old
    $OLD_BITWARDEN_RUN_FILE_PATH = "$TEMP_BITWARDEN_DIR/run.sh.old"
    #endregion

    #region Reset these used variables
    $CURRENT_CORE_ID = $null
    $CURRENT_WEB_ID = $null
    $CURRENT_KEYCONNECTOR_ID = $null
    $LATEST_CORE_ID = $null
    $LATEST_WEB_ID = $null
    $LATEST_KEYCONNECTOR_ID = $null
    $KEY_CONNECTOR_ENABLED = $null
    $BITWARDEN_RUN_SCRIPT_URL = $null
    $Counter = 0
    $JOB_STATE = $null
    $UPDATE_STATE = $null
    $BACKUP_FILE_NAME = $null
    $UPDATE_NEEDED = $null
    $DID_WE_UPDATE = $null
    $EMAIL_DATA = $null
    $BW_ITEMS = @($TEMP_BITWARDEN_DIR)
    #endregion

    #region ExitCodes
    $exitcode_NoUPDATE_NEEDED = 0
    $exitcode_MissingZHLBitWardenModule = 8
    $exitcode_NoScriptURL = 9
    $exitcode_FailCreatingTempDirectory = 10
    $exitcode_MissingDockerCommand = 11
    $exitcode_MissingDockerComposeCommand = 12
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
    $exitcode_FailSendingUpdateEmail = 27
    #endregion

    #region functions
    function Write-Log {
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
    #endregion

}

PROCESS {
    #region Preconditions
    Write-Log -EntryType Information -Message "Main: Checking preconditions before we start..."

    # Verify if we can import the ZHLBitWarden Module:
    if (-not (Get-Module -Name ZHLBitWarden -ErrorAction SilentlyContinue)) {
        try {
            Import-Module -Name ZHLBitWarden -ErrorAction Stop
        } catch {
            Write-Log -EntryType Warning -Message "Main: Error importing PowerShell Module ZHLBitWarden."
            Write-Log -EntryType Warning -Message "Main: Verify the module exists in '/usr/local/share/powershell/Modules'"
            exit $exitcode_MissingZHLBitWardenModule
        }
    }
    # Verify Docker is installed
    if (-not (Get-Command 'docker' -ErrorAction SilentlyContinue)) {
        Write-Log -EntryType Error -Message "Main: Missing command Docker, is it installed?"
        exit $exitcode_MissingDockerCommand
    }

    # Verify Docker Compose is installed
    if (-not (Get-Command 'docker-compose' -ErrorAction SilentlyContinue)) {
        Write-Log -EntryType Error -Message "Main: Missing command Docker-compose, is it installed?"
        exit $exitcode_MissingDockerComposeCommand
    }

    # Verify if PWSH is installed
    if (-not (Get-Command 'pwsh' -ErrorAction SilentlyContinue)) {
        Write-Log -EntryType Error -Message "Main: Missing command PWSH, is it installed?"
        exit $exitcode_MissingPWSHCommand
    }

    # Verify if the provided BitWarden Data directory exists
    if (-not (Test-Path -Path $BWDATA_DIR)) {
        Write-Log -EntryType Error -Message "Main: Cannot find Bitwarden's script directory. Does $BWDATA_DIR exist?"
        exit $exitcode_MissingScriptsDirectory
    }

    # Verify if the BitWarden Backup Script exists
    if (-not (Test-Path -Path $BITWARDEN_BACKUP_SCRIPT) -and (-not ($SkipBackup))) {
        Write-Log -EntryType Warning -Message "Main: Cannot find Bitwarden's Backup Script. Does $BITWARDEN_BACKUP_SCRIPT exist?"
        exit $exitcode_MissingBitWardenBackupScript
    }

    # Create Temp BitWarden Directory if it doesn't exist
    if (-not (Test-Path -Path $TEMP_BITWARDEN_DIR)) {
        Write-Log -EntryType Verbose -Message "Main: Attempting to create temp bitwarden directory..."
        try {
            New-Item -ItemType Directory $TEMP_BITWARDEN_DIR -ErrorAction Stop
        } catch {
            Write-Log -EntryType Warning -Message "Main: Failed creating Temporary BitWarden Directory $TEMP_BITWARDEN_DIR due to $_"
            exit $exitcode_FailCreatingTempDirectory
        }
    }
    #endregion



    #region Retrieve URLs for BitWarden's Script File & Run File
    # Retrieve BitWarden Script URL
    Write-Log -EntryType Verbose -Message "Main: Attempting to retrieve BitWarden Script URL..."
    $BITWARDEN_SCRIPT_URL = Get-ZHLBWScriptURL -ConfigFile $CURRENT_BITWARDEN_SCRIPT_FILE_PATH

    # Validate the URL's existence
    if ($null -eq $BITWARDEN_SCRIPT_URL) {
        Write-Log -EntryType Warning -Message "Main: Failed retrieving BitWarden Script URL from config file $CURRENT_BITWARDEN_SCRIPT_FILE_PATH."
        exit $exitcode_NoScriptURL
    }

    # Retrieve the RUN Script URL from the script file
    Write-Log -EntryType Verbose -Message "Main: Attempting to retrieve BitWarden Run Script URL..."
    $BITWARDEN_RUN_SCRIPT_URL = Get-ZHLBWRunScriptURL -CurrentScript $CURRENT_BITWARDEN_SCRIPT_FILE_PATH

    if ($null -eq $BITWARDEN_RUN_SCRIPT_URL) {
        Write-Log -EntryType Warning -Message "Main: Failed retrieving BitWarden Run Script URL from config file $CURRENT_BITWARDEN_SCRIPT_FILE_PATH."
        exit $exitcode_NoScriptURL
    }
    #endregion


    #region Generate File Names

    # Generate a new Backup File Name
    $BACKUP_FILE_NAME = New-ZHLBWBackupName
    # Generate an Encrypted Backup File Name
    $ENCRYPTED_BACKUP_FILE_NAME = "$FinalBackupLocation/$BACKUP_FILE_NAME.gpg"
    #endregion


    #region Retrieve current versions of BitWarden
    $CURRENT_CORE_ID = Get-ZHLBWCoreID -DockerFile $DockerFile
    $CURRENT_WEB_ID = Get-ZHLBWWebID -DockerFile $DockerFile
    $KEY_CONNECTOR_ENABLED = Get-ZHLBWKeyConnectorStatus -ConfigFile $ConfigFile

    if ($KEY_CONNECTOR_ENABLED) {
        $CURRENT_KEYCONNECTOR_ID = Get-KeyConnectorID -DockerFile $DockerFile
    }

    Write-Log -EntryType Information -Message "Main: Current Core ID: $CURRENT_CORE_ID"
    Write-Log -EntryType Information -Message "Main: Current Web ID: $CURRENT_WEB_ID"

    if ($null -ne $CURRENT_KEYCONNECTOR_ID) {
        Write-Log -EntryType Information -Message "Main: Current KeyConnector ID: $CURRENT_KEYCONNECTOR_ID"
    }
    #endregion


    #region Download and setup bitwarden.sh

    # This will download $BITWARDEN_SCRIPT_URL at path $TEMP_BITWARDEN_SCRIPT_FILE_PATH. The -Path parameter is only used to verify the existence of said out-file path.
    try {
        Write-Log -EntryType Information -Message "Main: Downloading latest bitwarden script..."
        Install-ZHLBWBitWardenScripts -URL $BITWARDEN_SCRIPT_URL -OutFile $TEMP_BITWARDEN_SCRIPT_FILE_PATH -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed downloading the BitWarden script at URL $BITWARDEN_SCRIPT_URL due to $_"
        exit $exitcode_FailDownloadingScript
    }

    # Update permissions on the downloaded bitwarden.sh
    try {
        Write-Log -EntryType Information -Message "Main: Updating permissions on bitwarden script file $TEMP_BITWARDEN_SCRIPT_FILE_PATH..."
        Update-ZHLBWScriptPermissions -Path $TEMP_BITWARDEN_SCRIPT_FILE_PATH -ErrorAction stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed updating permissions on script file $TEMP_BITWARDEN_SCRIPT_FILE_PATH."
        Remove-ZHLBWItems -Items $BW_ITEMS
        exit $exitcode_FailUpdatingPermissions
    }
    #endregion



    #region Download and setup run.sh

    # This will download $BITWARDEN_SCRIPT_URL at path $TEMP_BITWARDEN_SCRIPT_FILE_PATH. The -Path parameter is only used to verify the existence of said out-file path.
    try {
        Write-Log -EntryType Information -Message "Main: Downloading latest bitwarden run script..."
        Install-ZHLBWBitWardenScripts -URL $BITWARDEN_RUN_SCRIPT_URL -OutFile $TEMP_BITWARDEN_RUN_FILE_PATH -ErrorAction stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed downloading the BitWarden run script at URL $BITWARDEN_RUN_SCRIPT_URL due to $_"
        Remove-ZHLBWItems -Items $BW_ITEMS
        exit $exitcode_FailDownloadingRunScript
    }

    # Update permissions on the downloaded run.sh
    try {
        Write-Log -EntryType Information -Message "Main: Updating permissions on run script $TEMP_BITWARDEN_RUN_FILE_PATH..."
        Update-ZHLBWScriptPermissions -Path $TEMP_BITWARDEN_RUN_FILE_PATH -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed updating permissions on run file $TEMP_BITWARDEN_RUN_FILE_PATH."
        Remove-ZHLBWItems -Items $BW_ITEMS
        exit $exitcode_FailUpdatingPermissionsOnRunFile
    }
    #endregion

    #region Can we update BitWarden?
    Write-Log -EntryType Information -Message "Main: Checking if we can update..."
    # This will return true if we can update
    $UPDATE_NEEDED = Confirm-ZHLBWUpdate -ConfigFile $ConfigFile -DockerFile $DockerFile -NewScript $TEMP_BITWARDEN_SCRIPT_FILE_PATH

    if (-not $UPDATE_NEEDED) {
        Write-Log -EntryType Information -Message "Main: We do not need to update, removing downloaded files."
        Remove-ZHLBWItems -Items $BW_ITEMS
        exit $exitcode_NoUPDATE_NEEDED
    }
    Write-Log -EntryType Information -Message "Main: We can update!"
    #endregion

    #region Create Full BitWarden Backup

    # Perform a backup before updating
    if (-not $SkipBackup) {
        Write-Log -EntryType Information -Message "Main: Attempting to create backup $BACKUP_FILE_NAME before we update..."

        # Check if Job 'CreateBackup' exists. If it does, remove it
        if (Get-Job -Name 'CreateBackup' -ErrorAction SilentlyContinue) {
            if ((Get-Job -Name 'CreateBackup').State -eq 'Running') {
                Get-Job -Name 'CreateBackup' | Stop-Job
            }
            Get-Job -Name 'CreateBackup' | Remove-Job
        }

        # Start the Backup
        if ($PSBoundParameters.ParameterSetName -eq 'PasswordFile') {
            Start-Job -Name "CreateBackup" -ScriptBlock {pwsh -File $using:BITWARDEN_BACKUP_SCRIPT -PasswordFile $using:PasswordFile -FinalBackupLocation $using:FinalBackupLocation -All -BackupName $using:BACKUP_FILE_NAME}
        } elseif ($PSBoundParameters.ParameterSetName -eq 'PasswordPhrase') {
            Start-Job -Name "CreateBackup" -ScriptBlock {pwsh -File $using:BITWARDEN_BACKUP_SCRIPT -PasswordPhrase $using:PasswordPhrase -FinalBackupLocation $using:FinalBackupLocation -All -BackupName $using:BACKUP_FILE_NAME}

        }
        # Get the current state of the job
        $JOB_STATE = (Get-Job -Name 'CreateBackup').State
        $Counter = 0

        # Perform an iteration loop while the job is running or until the counter exceeds 240
        do {
            Write-Log -EntryType Verbose -Message "Main: Waiting for backup to finish..."
            Start-Sleep -Seconds 5
            $JOB_STATE = (Get-Job -Name 'CreateBackup').State
            $Counter += 5
            
        } until ($JOB_STATE -ne 'Running' -or $Counter -gt 240)

        # The job ran too long, exit.
        if ($Counter -gt 240 -and $JOB_STATE -ne 'Completed') {
            Write-Log -EntryType Warning -Message "Main: Script waited 4 minutes to create a backup but it did not finish..."
            Receive-job -Name 'CreateBackup' | Out-File -FilePath $script:LOG_FILE -Append

            if ((Get-Job -Name 'CreateBackup').State -eq 'Running') {
                Get-Job -Name 'CreateBackup' | Stop-Job
            }
            Get-Job -Name 'CreateBackup' | Remove-Job
            Remove-ZHLBWItems -Items $BW_ITEMS
            exit $exitcode_TooLongForBackup
        }

        # The job was complete!
        if ($JOB_STATE -eq 'Completed') {
            Write-Log -EntryType Information -Message "Main: The backup job has completed, let's see if it exists..."

            # Verify the encrypted backup exists
            if (-not (Test-Path -Path $ENCRYPTED_BACKUP_FILE_NAME)) {
                Write-Log -EntryType Warning -Message "Main: Backup File does not exist, dumping the job details into our log file.."
                Receive-job -Name 'CreateBackup' | Out-File -FilePath $script:LOG_FILE -Append
                Get-Job -Name 'CreateBackup' | Remove-Job
                Remove-ZHLBWItems -Items $BW_ITEMS
                exit $exitcode_BackupJobCompletedButNoBackup
            }

            Write-Log -EntryType Information -Message "Main: Found the backup!"
            # Append the job results to our log file and remove the backup
            Receive-job -Name 'CreateBackup' | Out-File -FilePath $LogFile -Append
            Get-Job -Name 'CreateBackup' | Remove-Job
        }
    }
    #endregion



    #region Replace bitwarden.sh & run.sh with their downloaded variants
    try {
        Write-Log -EntryType Information -Message "Main: Saving the current run script for just in case purposes and moving the new run script in its place..."
        Update-ZHLBWBitWardenScripts -CurrentScript $CURRENT_BITWARDEN_SCRIPT_FILE_PATH -NewScript $TEMP_BITWARDEN_SCRIPT_FILE_PATH -OldScript $OLD_BITWARDEN_SCRIPT_PATH -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed replacing the downloaded script with the current BitWarden script due to $_"
        Remove-ZHLBWItems -Items $BW_ITEMS
        exit $exitcode_FailReplacingScript
    }

    # We downloaded the script, time to move our current run file to a temporarily location and replace it with the new run script.
    try {
        Write-Log -EntryType Information -Message "Main: Saving the current run script for just in case purposes and moving the new run script in its place..."
        Update-ZHLBWBitWardenScripts -CurrentScript $CURRENT_RUN_FILE_PATH -NewScript $TEMP_BITWARDEN_RUN_FILE_PATH -OldScript $OLD_BITWARDEN_RUN_FILE_PATH
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed replacing the downloaded run script with the current run script due to $_"
        Remove-ZHLBWItems -Items $BW_ITEMS
        exit $exitcode_FailReplacingRunScript
    }
    #endregion


    #region Update Bitwarden

    # Set the location to BITWARDEN_DIR (Example: /opt/bitwarden/)
    Write-Log -EntryType Information -Message "Main: Attempting to update BitWarden..."
    Set-Location -Path $BITWARDEN_DIR

    Write-Log -EntryType Information -Message "Main: Creating background job for ./bitwarden.sh update"
    # Check if Job 'Update' exists. If it does, remove it
    if (Get-Job -Name 'Update' -ErrorAction SilentlyContinue) {
        if ((Get-Job -Name 'Update').State -eq 'Running') {
            Get-Job -Name 'Update' | Stop-Job
        }
        Get-Job -Name 'Update' | Remove-Job
    }

    # Start job 'Update' which calls the update function on BitWarden's script file
    Start-Job -Name 'Update' -ScriptBlock {bash $using:CURRENT_BITWARDEN_SCRIPT_FILE_PATH update}

    # Retrieve the job's status
    $UPDATE_STATE = (Get-Job -Name 'Update').State
    $Counter = 0

    # Iterate until the job has stopped running or until counter exceeds 600
    do {
        Write-Log -EntryType Verbose -Message "Main: Waiting for Update to finish..."
        Start-Sleep -Seconds 10
        $UPDATE_STATE = (Get-Job -Name 'Update').State
        $Counter += 10

    } until ($UPDATE_STATE -ne 'Running' -or $Counter -gt 600)

    # The job ran longer than 600 seconds, exiting.
    if ($Counter -gt 600 -and $UPDATE_STATE -ne 'Completed') {
        Write-Log -EntryType Warning -Message "Main: Script waited 10 minutes for bitwarden to update but it did not finish..."
        Receive-job -Name 'Update' | Out-File -FilePath $LogFile -Append

        if ((Get-Job -Name 'Update').State -eq 'Running') {
            Get-Job -Name 'Update' | Stop-Job
        }
        Get-Job -Name 'Update' | Remove-Job
        Remove-ZHLBWItems -Items $BW_ITEMS
        exit $exitcode_TooLongForUpdate
    }

    # Update job was completed, did we get an update?
    if ($UPDATE_STATE -eq 'Completed') {
        Write-Log -EntryType Information -Message "Main: Checking if we actually updated..."

        # This should return false as if we did update, our BitWarden version should match the new versions
        $DID_WE_UPDATE = Confirm-ZHLBWUpdate -ConfigFile $ConfigFile -DockerFile $DockerFile -NewScript $CURRENT_BITWARDEN_SCRIPT_FILE_PATH

        if (-not $DID_WE_UPDATE) {
            # Append the job results to our log file and remove the backup
            Receive-job -Name 'Update' | Out-File -FilePath $LogFile -Append
            Get-Job -Name 'Update' | Remove-Job

            Write-Log -EntryType Information -Message "Main: Successfully updated!"
        }

        Write-Log -EntryType Warning -Message "Main: Update failed. Storing results of job in the log file."
        # Append the job results to our log file and remove the backup
        Receive-job -Name 'Update' | Out-File -FilePath $LogFile -Append
        Get-Job -Name 'Update' | Remove-Job
        # Cleanup Items
        Remove-ZHLBWItems -Items $BW_ITEMS
        $exitcode_UpdateFailed
    }
    #endregion

    #region Send Email of Version Changes
    Write-Log -EntryType Information -Message "Main: Retrieve updated version values for BitWarden..."

    # Retrieve current version info
    $LATEST_CORE_ID = Get-ZHLBWCoreID -DockerFile $DockerFile
    $LATEST_WEB_ID = Get-ZHLBWWebID -DockerFile $DockerFile
    $KEY_CONNECTOR_STATUS = Get-ZHLBWKeyConnectorStatus -ConfigFile $ConfigFile

    if ($KEY_CONNECTOR_STATUS) {
        $LATEST_KEYCONNECTOR_ID = Get-ZHLBWKeyConnectorID -DockerFile $DockerFile
    }

    Write-Log -EntryType Information -Message "Main: Latest Core ID: $LATEST_CORE_ID"
    Write-Log -EntryType Information -Message "Main: Latest Web ID: $LATEST_WEB_ID"
    if ($null -ne $LATEST_KEYCONNECTOR_ID) {
        Write-Log -EntryType Information -Message "Main: Latest KeyConnector ID: $LATEST_KEYCONNECTOR_ID"
    }

    # Send email of the update
    $EMAIL_DATA = "" | Select-Object CURRENT_CORE_ID, LATEST_CORE_ID, CURRENT_WEB_ID, LATEST_WEB_ID, CURRENT_KEYCONNECTOR_ID, LATEST_KEYCONNECTOR_ID, BACKUP_FILE
    $EMAIL_DATA.CURRENT_CORE_ID = $CURRENT_CORE_ID
    $EMAIL_DATA.LATEST_CORE_ID = $LATEST_CORE_ID
    $EMAIL_DATA.CURRENT_WEB_ID = $CURRENT_WEB_ID
    $EMAIL_DATA.LATEST_WEB_ID = $LATEST_WEB_ID
    if ($null -ne $CURRENT_KEYCONNECTOR_ID) {
        $EMAIL_DATA.CURRENT_KEYCONNECTOR_ID = $CURRENT_KEYCONNECTOR_ID
        $EMAIL_DATA.LATEST_KEYCONNECTOR_ID = $LATEST_KEYCONNECTOR_ID
    }
    $EMAIL_DATA.BACKUP_FILE = $ENCRYPTED_BACKUP_FILE_NAME

    if ($PSBoundParameters.ContainsKey('EmailAddresses') -and $PSBoundParameters.ContainsKey('From') -and $PSBoundParameters.ContainsKey('SMTPServer')) {
        try {
            Write-Log -EntryType Information -Message "Main: Attempting to send update report email..."
            Send-ZHLBWUpdateEmail -EmailAddresses $EmailAddresses -From $From -SmtpServer $SMTPServer -Subject "BitWarden Update Results" -Data $EMAIL_DATA -ErrorAction Stop
        } catch {
            Write-Log -EntryType Warning -Message "Main: Failed sending email report due to $_"
        } finally {
            Remove-ZHLBWItems -Items $BW_ITEMS
            exit $exitcode_FailSendingUpdateEmail
        }
    }
    #endregion

    #region Cleanup
    Write-Log -EntryType Information -Message "Main: Before exiting, let's cleanup our created directory and downloaded files..."
    Remove-ZHLBWItems -Items $BW_ITEMS
    #endregion
}