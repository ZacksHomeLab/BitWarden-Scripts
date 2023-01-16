<#
.Synopsis
    This script performs a backup operation on our on-premise bitwarden server.

.DESCRIPTION
    This script requires autofs to be setup on said local server and moves backups to said autofs location (preferably a fileserver). The script will keep backups after x provided days.

.PARAMETER PasswordFile
    The password file that holds the passphrase that will be used to encrypt backups.

.PARAMETER FinalBackupLocation
    The destination of the encrypted backup (e.g., '/backups')

.PARAMETER Incremental
    This switch will backup if there's been any changes to the Bitwarden database within the past hour. 

.PARAMETER All
    This switch will perform a full backup of BitWarden.

.PARAMETER Days
    Pass amount of days to keep backups. For example, if you set this to '10', the script will delete all backups greater than 10 days from current date. You must also
    give the correct backup location that houses said existing backups.

.PARAMETER BackupName
    If you wish to overwrite the default backup name, use this parameter to do so. You must end the filename with a .tar file extension (e.g., backup.tar)

.PARAMETER SendEmail
    Toggle this switch if you would like the script to send an email based off of your settings in the Global Environments file.

.PARAMETER EmailAddresses
    Input the email addresses that should receive the email from this script.

.PARAMETER LogFile
    The location where the log file will reside.

.EXAMPLE
    ./Backup-Bitwarden.ps1 -PasswordFile '/opt/bitwarden/password_file' -FinalBackupLocation '/backups' -All
    
    Perform a full BitWarden Backup with the default retention days of 31 and store the backups at location /backups

.EXAMPLE
    ./Backup-Bitwarden.ps1 -PasswordFile './password_file' -FinalBackupLocation '/backups' -All -SendEmail -EmailAddresses 'zack@zackshomelab.com'
    
    Perform a full BitWarden Backup with a retention of 5 days (this will remove backups older than 5 days) and store the backup at /backups' and gather the Email Settings from the 
    global environment file to send an email to zack@zackshomelab.com

.EXAMPLE
    ./Backup-Bitwarden.ps1 -PasswordFile '/opt/bitwarden/password_file' -FinalBackupLocation '/backups' -Incremental -days 10 -LogFile '/root/bitwarden_backup.log'
    
    Perform an incremental Bitwarden Backup with the provided password file and cleanup backups to only allow 10 days worth of backups to be stored at the final destination. Also, 
    set the script's log file to be stored at /root/bitwarden_backup.log'
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
        ParameterSetName='IncrementPasswordFile')]
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='AllPasswordFile')]
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='IncrementPasswordFileSendEmail')]
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='AllPasswordFileSendEmail')]
        [ValidateScript({Test-Path -Path $_})]
    [string]$PasswordFile,

    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='IncrementPasswordPhrase')]
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='AllPasswordPhrase')]
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='IncrementPasswordPhraseSendEmail')]
    [parameter(Mandatory,
        Position=0,
        ValueFromPipeline,
        ParameterSetName='AllPasswordPhraseSendEmail')]
        [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]$PasswordPhrase,

    [parameter(Mandatory,
        Position=1)]
        [ValidateScript({Test-Path -Path $_})]
    [string]$FinalBackupLocation,

    [parameter(Mandatory,
        Position=2,
        ParameterSetName='IncrementPasswordFile')]
    [parameter(Mandatory,
        Position=2,
        ParameterSetName='IncrementPasswordPhrase')]
    [parameter(Mandatory,
        Position=2,
        ParameterSetName='IncrementPasswordPhraseSendEmail')]
    [parameter(Mandatory,
        Position=2,
        ParameterSetName='IncrementPasswordFileSendEmail')]
    [switch]$Incremental,

    [parameter(Mandatory,
        Position=2,
        ParameterSetName='AllPasswordFile')]
    [parameter(Mandatory,
        Position=2,
        ParameterSetName='AllPasswordPhrase')]
    [parameter(Mandatory,
        Position=2,
        ParameterSetName='AllPasswordFileSendEmail')]
    [parameter(Mandatory,
        Position=2,
        ParameterSetName='AllPasswordPhraseSendEmail')]
    [switch]$All,

    [parameter(Mandatory=$false,
        helpMessage="How many days should we retain backups?",
        Position=3)]
        [ValidateRange(1, 365)]
    [int]$Days = 31,

    [parameter(Mandatory=$false,
        Position=4,
        helpMessage="Enter the name of your back, it must end with extension .tar")]
        [ValidateScript({$_ -match "^(.*)\.tar$"})]
    [string]$BackupName,

    [Parameter(Mandatory=$false,
        Position=5)]
    [string]$LogFile = './backup-bitwarden.log',

    [parameter(Mandatory,
        Position=6,
        ParameterSetName='IncrementPasswordFileSendEmail')]
    [parameter(Mandatory,
        Position=6,
        ParameterSetName='AllPasswordFileSendEmail')]
    [parameter(Mandatory,
        Position=6,
        ParameterSetName='IncrementPasswordPhraseSendEmail')]
    [parameter(Mandatory,
        Position=6,
        ParameterSetName='AllPasswordPhraseSendEmail')]
    [switch]$SendEmail,

    [parameter(Mandatory,
        Position=7,
        ParameterSetName='IncrementPasswordFileSendEmail',
        helpMessage="What Email Addresses should receive the update report? (Must also add '-SendEmail' switch to enable this)")]
    [parameter(Mandatory,
        Position=7,
        ParameterSetName='AllPasswordFileSendEmail',
        helpMessage="What Email Addresses should receive the update report? (Must also add '-SendEmail' switch to enable this)")]
    [parameter(Mandatory,
        Position=7,
        ParameterSetName='IncrementPasswordPhraseSendEmail',
        helpMessage="What Email Addresses should receive the update report? (Must also add '-SendEmail' switch to enable this)")]
    [parameter(Mandatory,
        Position=7,
        ParameterSetName='AllPasswordPhraseSendEmail',
        helpMessage="What Email Addresses should receive the update report? (Must also add '-SendEmail' switch to enable this)")]
    [string[]]$EmailAddresses
)

BEGIN {
    #region VARIABLES
    $script:LOG_FILE = $LogFile


    $FINAL_BACKUP_LOCATION = $FinalBackupLocation
    if ($FINAL_BACKUP_LOCATION[-1] -eq '/') {
        $FINAL_BACKUP_LOCATION = $FINAL_BACKUP_LOCATION.Substring(0,$FINAL_BACKUP_LOCATION.Length-1)
    }

    # The incremental directories to be backed up
    $INCREMENTAL_DIRECTORIES = "/opt/bitwarden/bwdata/env", "/opt/bitwarden/bwdata/core/attachments", "/opt/bitwarden/bwdata/mssql/data"

    # The entire backup of Bitwarden
    $ALL_DIRECTORIES = "/opt/bitwarden/bwdata"

    # Path of the Vault log (this is used to determine if we need to make an incremental backup)
    $VAULT_LOG = "/opt/bitwarden/bwdata/mssql/data/vault_log.ldf"

    # We will use this splatter to send an email if '-sendEmail' was given
    $EMAIL_PARAMS = @{}

    # Email settings will be stored in this hash table
    $EMAIL_SETTINGS = @{}

    $SEND_EMAIL = $false
    #endregion



    #region FUNCTIONS
    function Write-Log {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory, Position=0)]
            [ValidateNotNullOrEmpty()]
            [String]$Message,

            [Parameter(Mandatory=$false, Position=1)]
            [ValidateSet('Verbose', 'Info', 'Warning', 'Error')]
            [String]$EntryType = "Info",

            [parameter(Mandatory=$false, Position=2)]
            [ValidateNotNullOrEmpty()]
            [string]$Path = $script:LOG_FILE
        )
        
        begin {
            
            # Check if the log level an error or an error record was submitted
            if ($EntryType -eq 'Error') {
                $ErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $Message, 'Unknown', 'NotSpecified', $null
            }
        }
        
        process {
            # Output to file
            $Line = "[$EntryType][$((Get-Date).toString('yyyy-MM-dd:hh-mm-ss'))], $Message"
            $Line | Out-File $Path -Append
            
            switch ($EntryType) {
                'Verbose'     { Write-Verbose -Message $Message }
                'Info'        { Write-Output $Message }
                'Warning'     { Write-Warning -Message $Message }
                'Error'       { Write-Error -ErrorRecord $ErrorRecord }
            }
        }
    }

    #region Exit Codes
    $exitcode_NoChangesInPastHour = 0
    $exitcodde_NotRoot = 9
    $exitcode_MissingZHLBitWardenModule = 10
    $exitcode_FailCreatingBackup = 11
    $exitcode_FailEncryptingBackup = 12
    $exitcode_FailMovingEncryptBackup = 13
    $exitcode_FailFindingBackupAfterMove = 14
    $exitcode_FailRemoveOldBackups = 15
    $exitcode_MissingGlobalEnv = 16
    $exitcode_FailGatheringEmailSettings = 17
    #endregion
}

PROCESS {

    #region Prereqs
    # Check if the user is root
    if ($PSVersionTable.Platform -eq "Unix") {
        if ($(whoami) -ne "root") {
            Write-Log -EntryType Warning -Message "Main: You must run this script as root, stopping."
            exit $exitcode_NotRoot
        }
    }

    # Verify if we can import the ZHLBitWarden Module:
    if (-not (Get-Module -Name ZHLBitWarden -ErrorAction SilentlyContinue)) {
        try {
            if (Test-Path -Path "$($Home)/.local/share/powershell/Modules/ZHLBitWarden.psm1") {
                Import-Module -Name "$($Home)/.local/share/powershell/Modules/ZHLBitWarden.psm1"
            } elseif (Test-Path -Path "/usr/local/share/powershell/Modules/ZHLBitWarden.psm1") {
                Import-Module -Name "/usr/local/share/powershell/Modules/ZHLBitWarden.psm1" -ErrorAction Stop
            }
            
        } catch {
            Write-Log -EntryType Warning -Message "Main: Error importing PowerShell Module ZHLBitWarden."
            Write-Log -EntryType Warning -Message "Main: Verify the module exists in '$($Home)/.local/share/powershell/Modules/ OR /usr/local/share/powershell/Modules/'"
            exit $exitcode_MissingZHLBitWardenModule
        }
    }

    # Generate a backup name if one wasn't provided
    if (-not $PSBoundParameters.ContainsKey('BackupName')) {
        $BACKUP_NAME = New-ZHLBWBackupName -Directory $FINAL_BACKUP_LOCATION
    } else {
        #TODO: Figure out a way to check if the finaly backup location is within the backup name
        $BACKUP_NAME = $BackupName
    }

    # The file path of the Encrypted Backup
    $ENCRYPTED_BACKUP_NAME = "$BACKUP_NAME.gpg"

    # Add the items or directories to be removed by the script if we encounter an error or end said script
    $CLEANUP_ITEMS = @($ENCRYPTED_BACKUP_NAME, $BACKUP_NAME)

    #region Gather Email Settings
    if ($PSCmdlet.ParameterSetName -like '*SendEmail*') {
        $SEND_EMAIL = $true

        # The location of the global environment variables. Verify it exists.
        $GLOBAL_ENV = '/opt/bitwarden/bwdata/env/global.override.env'
        if (-not (Test-Path -Path $GLOBAL_ENV)) {
            Write-Log -EntryType Warning -Message "Main: Global Environment file $GLOBAL_ENV does not exist. Could not retrieve SMTP settings."
            exit $exitcode_MissingGlobalEnv
        }

        try {
            Write-Log "Main: Gathering Email Settings from global environment file $GLOBAL_ENV"
            $EMAIL_SETTINGS = Get-ZHLBWEmailSettings -GlobalEnv $GLOBAL_ENV -ErrorAction Stop
        } catch {
            Write-Log -EntryType Warning -Message "Main: Failed gathering Email Settings from $GLOBAL_ENV due to error $_"
            exit $exitcode_FailGatheringEmailSettings
        }
        
        # Create the parameter splat
        $EMAIL_PARAMS.add('EmailAddresses', $EmailAddresses)
        $EMAIL_PARAMS.add('FROM', $EMAIL_SETTINGS['From'])
        $EMAIL_PARAMS.add('SMTPServer', $EMAIL_SETTINGS['SMTPServer'])
        $EMAIL_PARAMS.add('SMTPPort', $EMAIL_SETTINGS['SMTPPort'])
        $EMAIL_PARAMS.add('UseSSL', $EMAIL_SETTINGS['UseSSL'])

        # If a password was given, create the credentials variable
        if ($null -ne $PASS) {
            $EMAIL_PARAMS.add('Creds', $EMAIL_SETTINGS['Creds'])
        }
    }
    #endregion

    #endregion


    #region Create Backup
    try {
        if ($PSCmdlet.ParameterSetName -like 'Increment*') {
            # Check if Bitwarden's Vault Log has had any changes within the past hour
            # If this is true, create incremental backup.
            if (-not (Get-Item -Path $VAULT_LOG | Where-Object {$_.LastWriteTime -ge ((Get-Date).AddHours(-1))})) {
                Write-Log "Main: Vault hasn't changed within the past hour, no need for an incremental backup. Stopping script."
                exit $exitcode_NoChangesInPastHour
            }

            Write-Log "Main: Vault has changed within the hour, creating incremental Backup..."
            Backup-ZHLBWBitWarden -Items $INCREMENTAL_DIRECTORIES -BackupName $BACKUP_NAME -ErrorAction Stop
        } elseif ($PSCmdlet.ParameterSetName -like 'All*') {
            # Create a full backup
            Write-Log "`nMain: Creating full Backup..."
            Backup-ZHLBWBitWarden -Items $ALL_DIRECTORIES -BackupName $BACKUP_NAME -ErrorAction Stop
        }
        
    } catch {
        Write-Log -EntryType Warning "Main: Failed creating a BiTwarden Backup due to $_"
        exit $exitcode_FailCreatingBackup
    }
    
    Write-Log "Main: Successfully created backup $BACKUP_NAME!"
    #endregion



    #region Encrypt Backup
    try {
        Write-Log "`nMain: Attempting to encrypt Backup $BACKUP_NAME."
        if ($PSCmdlet.ParameterSetName -like '*PasswordFile*') {
            Lock-ZHLBWBackup -BackupFile $BACKUP_NAME -PasswordFile $PasswordFile -ErrorAction Stop
        } elseif ($PSCmdlet.ParameterSetName -like '*PasswordPhrase*') {
            Lock-ZHLBWBackup -BackupFile $BACKUP_NAME -PasswordPhrase $PasswordPhrase -ErrorAction Stop
        }
        
    } catch {
        $Message = $_
        Write-Log -EntryType Warning -Message "Main: Failed to encrypt backup $BACKUP_NAME because of error $Message"
        if ($SEND_EMAIL) {
            Send-ZHLBWEmail @EMAIL_PARAMS -Subject "FAILURE: BitWarden Backup" -Body "Encryption was successful but failed to delete unencrypted backup because of error: $Message"
        }
        Remove-ZHLBWItems -Items $CLEANUP_ITEMS
        exit $exitcode_FailEncryptingBackup
    }

    # Encryption was successful, delete unencrypted backup
    Write-Log "`nMain: Encryption was successful, removing unencrypted backup."
    Remove-Item -Path $BACKUP_NAME -Force
    #endregion


    #region Move Encrypted Backup to Final Destination
    try {
        Write-Log "`nMain: Moving Encrypted Backup to final backup destination: $FINAL_BACKUP_LOCATION."
        Move-Item -Path $ENCRYPTED_BACKUP_NAME -Destination $FINAL_BACKUP_LOCATION -ErrorAction Stop
    } catch {
        $Message = $_
        Write-Log -EntryType Warning -Message "Main: Failed to move encrypted backup $ENCRYPTED_BACKUP_NAME due to error $Message"
        if ($SEND_EMAIL) {
            Send-ZHLBWEmail @EMAIL_PARAMS -Subject "FAILURE: BitWarden Backup" -Body "Failed to move encrypted backup $ENCRYPTED_BACKUP_NAME because of error $Message"
        }
        exit $exitcode_FailMovingEncryptBackup
    }

    # Verify the backup is at its final location
    if (-not (Test-Path -Path $ENCRYPTED_BACKUP_NAME)) {
        Write-Log -EntryType Warning -Message "Main: Could not find created backup $ENCRYPTED_BACKUP_NAME."
        if ($SEND_EMAIL) {
            Send-ZHLBWEmail @EMAIL_PARAMS -Subject "FAILURE: BitWarden Backup" -Body "Successfully created backup but could not find it after moving to $ENCRYPTED_BACKUP_NAME"
        }
        exit $exitcode_FailFindingBackupAfterMove
    }

    Write-Log "`nMain: Successfully created backup $ENCRYPTED_BACKUP_NAME. Sending success email (if Send-ZHLBWEmail was configured)."
    if ($SEND_EMAIL) {
        Send-ZHLBWEmail @EMAIL_PARAMS -Subject "SUCCESS: BitWarden Backup" -Body "Successfully created backup $ENCRYPTED_BACKUP_NAME."
    }
    #endregion



    #region Delete old backups
    try {
        # Delete Backups older than $Days at backup location $FINAL_BACKUP_LOCATION
        Write-Log "`nMain: Check if there's any backups that are more than $Days days old."
        Remove-ZHLBWBackups -Days $Days -BackupLocation $FINAL_BACKUP_LOCATION -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed to remove old backups due to error $_"
        exit $exitcode_FailRemoveOldBackups
    }
    #endregion
}