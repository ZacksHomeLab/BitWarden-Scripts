<#
.Synopsis
    restore-bitwarden.ps1 restores from a Bitwarden backup from an encrypted backup.
.DESCRIPTION
    restore-bitwarden.ps1 restores from an encrypted bitwarden backup, which is decrypted by a given passphrase or password file.
.PARAMETER PasswordFile
    The file that contains the pass phrase used to encrypt the backup.
.PARAMETER Passphrase
    The passphrase used to encrypt the backup file.
.PARAMETER BackupFile
    The full path of the backup file. (e.g., /backups/BitwardenBackup-xx.tar.gpg)
.PARAMETER BitWardenScript
    The location of the bitwarden bash script (default location is /opt/bitwarden/bitwarden.sh)
.PARAMETER BitWardenDir
    The installation directory of BitWarden (e.g., '/opt/bitwarden')
.PARAMETER LogFile
    The location where the log file will reside (default location is ./restore-bitwarden.log)
.EXAMPLE
    ./restore-bitwarden.ps1 -Passwordfile ./password_file -BackupFile /backups/BitWardenBackup-2022-05-13_00-00-03.tar.gpg
    Restore a backup file with a given password file
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
        ValueFromPipelineByPropertyName,
        ParameterSetName='PasswordPhrase')]
        [ValidateNotNullOrEmpty()]
    [System.Security.SecureString]$PasswordPhrase,

    [Parameter(Mandatory,
        Position=1,
        ValueFromPipelineByPropertyName,
        helpMessage="What's the path of the backup file? (Must end with .gpg or .tar)")]
        [ValidateScript({Test-path -Path $_ -and ($_ -match '(.*)\.(gpg|tar)$')})]
    [string]$BackupFile,

    [Parameter(Mandatory=$false,
        Position=2,
        ValueFromPipelineByPropertyName
        helpMessage="What's the name and path of the Bitwarden service script? (Must end in .sh)")]
        [ValidateScript({Test-Path -Path $_ -and $_ -match '(.*)\.sh$'})]
    [string]$BitWardenScript = '/opt/bitwarden/bitwarden.sh',

    [parameter(Mandatory=$false,
        Position=3,
        ValueFromPipelineByPropertyName)]
        [ValidateScript({Test-Path -Path $_})]
    [string]$BitWardenDir = '/opt/bitwarden'

    [Parameter(Mandatory=$false, 
        Position=4)]
    [string]$LogFile = "./Restore-BitWardenBackup.log"
)

begin {
    #region VARIABLES
    $script:LOG_FILE = $LogFile

    # Example BitWarden Directory: '/opt/bitwarden'
    $BITWARDEN_DIR = $BitWardenDir
    if ($BITWARDEN_DIR[-1] -eq '/') {
        $BITWARDEN_DIR = $BITWARDEN_DIR.Substring(0,$BITWARDEN_DIR.Length-1)
    }

    # Example Current BitWarden Directory: /opt/bitwarden/bitwarden.sh
    if ($PSBoundParameters.ContainsKey('BitWardenScript')) {
        $BITWARDEN_SCRIPT_FILE_PATH = $BitWardenScript
    } else {
        $BITWARDEN_SCRIPT_FILE_PATH = "$BITWARDEN_DIR/bitwarden.sh"
    }

    # Example bwdata directory: /opt/bitwarden/bwdata
    $BWDATA_DIR = "$BITWARDEN_DIR/bwdata"
    # Example BitWarden Scripts directory: /opt/bitwarden/bwdata/scripts
    $BITWARDEN_SCRIPTS_PATH = "$BWDATA_DIR/scripts"
    # Example BitWarden Run File path: /opt/bitwarden/bwdata/scripts/run.sh
    $BITWARDEN_RUN_FILE_PATH = "$BITWARDEN_SCRIPTS_PATH/run.sh"

    # Only used to save the backup run script in case stuff breaks
    $TEMP_BITWARDEN_RUN_FILE_PATH = "/tmp/run.sh"
    # Decrypt Backup File Name + Path
    $DECRYPT_LOCATION = New-ZHLBWBackupDecryptionName -Directory '/tmp'

    # Extract Backup File Name + Path
    $EXTRACT_LOCATION = New-ZHLBWBackupExtractionName -Directory '/tmp'

    # The items in this array will be removed upon error or upon success of the script.
    $CLEANUP_ITEMS = @($DECRYPT_LOCATION, $EXTRACT_LOCATION, $TEMP_BITWARDEN_RUN_FILE_PATH)
    #endregion

    #region FUNCTIONS
    function Write-Log {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory, Position=0)]
            [ValidateNotNullOrEmpty()]
            [String]$Message,

            [Parameter(Mandatory=$false, Position=1)]
            [ValidateSet('Verbose', 'Information', 'Warning', 'Error')]
            [String]$EntryType = "Information",

            [parameter(Mandatory=$false, Position=2)]
            [ValidateNotNullOrEmpty()]
            [string]$Path = $script:LOG_FILE,
        )
        
        begin {
            
            # Check if the log level an error or an error record was submitted
            if ($EntryType -eq 'Error') {
                $ErrorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList $Message, 'Unknown', 'NotSpecified', $null
            }
        }
        
        process {
            # Output to file
            $Line = "[$EntryType][$((Get-Date).toString('yyyy-MM-dd:hh-mm-ss'))][$env:ComputerName], $Message"
            $Line | Out-File $Path -Append
            
            switch ($EntryType) {
                'Verbose'     { Write-Verbose -Message $Message }
                'Information' { Write-Output $Message }
                'Warning'     { Write-Warning -Message $Message }
                'Error'       { Write-Error -ErrorRecord $ErrorRecord }
            }
        }
    }
    #endregion

    #region Exit Codes
    $exitcode_NotRoot = 10
    $exitcode_MissingZHLBitWardenModule = 11
    $exitcode_MissingBitWardenScript = 12
    $exitcode_FailDecryptingBackup = 13
    $exitcode_FailExtractingBackup = 14
    $exitcode_FailFindingRunScriptAfterExtraction = 15
    $exitcode_FailReplacingNewRunWithOldRun = 16
    $exitcode_FailStoppingBitWarden = 17
    $exitcode_ExtractDirectoryEmpty = 18
    $exitcode_FailStartingBitWarden = 19
    $exitcode_MissingBitWardenRunScript = 20
    #endregion

    #region Reset these variables
    $Backup = $null
    $EXTRACTED_ITEMS = $null
    #endregion


    #region Pre-reqs
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
            Import-Module -Name ZHLBitWarden -ErrorAction Stop
        } catch {
            Write-Log -EntryType Warning -Message "Main: Error importing PowerShell Module ZHLBitWarden."
            Write-Log -EntryType Warning -Message "Main: Verify the module exists in '/usr/local/share/powershell/Modules'"
            exit $exitcode_MissingZHLBitWardenModule
        }
    }
    # Verify the BitWarden script exists
    if (-not (Test-Path -Path $BITWARDEN_SCRIPT_FILE_PATH)) {
        Write-Log -EntryType Warning -Message "Main: Missing $BITWARDEN_SCRIPT_FILE_PATH"
        exit $exitcode_MissingBitWardenScript
    }

    # Verify the BitWarden run script exists
    if (-not (Test-Path -Path $BITWARDEN_RUN_FILE_PATH)) {
        Write-Log -EntryType Warning -Message "Main: Missing $BITWARDEN_RUN_FILE_PATH"
        exit $exitcode_MissingBitWardenRunScript
    }

    #endregion
}

process {
    #region Decrypt Backup if extension is .gpg
    $Backup = Get-Item -Path $BackupFile
    if ($Backup.Extension -eq '.gpg') {
        try {
            if ($PSCmdlet.ParameterSetName -eq "PasswordFile") {
                Write-Log "`nMain: Attempting to decrypt backup $($Backup.FullName) with password file $PasswordFile."
                Unlock-ZHLBWBackup -BackupFile $($Backup.FullName) -PasswordFile $PasswordFile -DecryptLocation $DECRYPT_LOCATION
            } elseif ($PSCmdlet.ParameterSetName -eq "Passphrase") {
                Write-Log "`nMain: Attempting to decrypt backup $($Backup.FullName) with a given passphrase."
                Unlock-ZHLBWBackup -BackupFile $($Backup.FullName) -Passwordphrase $Passwordphrase -DecryptLocation $DECRYPT_LOCATION
            }
        } catch {
            Write-Log -EntryType Warning "Main: Failure decrypting backup $($Backup.FullName) due to $_"
            exit $exitcode_FailDecryptingBackup
        }
    } else {
        Write-Log "Main: Backup isn't encrypted, skipping decryption."
        # Store the backup into DECRYPT_LOCATION for the extraction step
        $DECRYPT_LOCATION = $($Backup.FullName)
    }
    #endregion

    #region Extract Archive
    try {
        Write-Log "`nMain: Attempting to extract $DECRYPT_LOCATION"
        Expand-ZHLBWBackup -ArchiveFile $DECRYPT_LOCATION -ExtractLocation $EXTRACT_LOCATION -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failed to extract the decrypted backup ($DECRYPT_LOCATION) because of error $_"
        exit $exitcode_FailExtractingBackup
    }
    #endregion



    #region Restore BitWarden Backup

    # Stop BitWarden Service
    try {
        # Attempting to stop Bitwarden before restoring backup
        Write-Log "Main: Attempting to stop BitWarden before we proceed with the restoration process..."
        Stop-Bitwarden -ScriptLocation $BITWARDEN_SCRIPT_FILE_PATH -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failure stopping BitWarden, stopping script."
        Remove-ZHLBWItems -Items $CLEANUP_ITEMS
        exit $exitcode_FailStoppingBitWarden
    }

    # Retrieve Extracted Items
    Write-Log "Main: Gathering extracted BitWarden Backup contents..."
    $EXTRACTED_ITEMS = Get-ZHLBWExtractedItems -ExtractLocation $EXTRACT_LOCATION
    if ($null -eq $EXTRACTED_ITEMS) {
        Write-Log -EntryType Warning -Message "Main: There isn't any contents within extract directory $EXTRACT_LOCATION."
        Remove-ZHLBWItems -Items $CLEANUP_ITEMS
        exit $exitcode_ExtractDirectoryEmpty
    }

    # Restore BitWarden Backup
    try {
        Write-Log "Main: Attempting to restore BitWarden..."
        Restore-Backup -ExtractedItems $EXTRACTED_ITEMS -ExtractLocation $EXTRACT_LOCATION
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failure stopping BitWarden, stopping script."
        Remove-ZHLBWItems -Items $CLEANUP_ITEMS
        exit $exitcode_FailRestoringBitWardenBackup
    }

    # Start BitWarden after the restore
    try {
        # Attempting to stop Bitwarden before restoring backup
        Write-Log "Main: Attempting to start BitWarden before..."
        Start-Bitwarden -ScriptLocation $BITWARDEN_SCRIPT_FILE_PATH -ErrorAction Stop
    } catch {
        Write-Log -EntryType Warning -Message "Main: Failure starting BitWarden, stopping script."
        Remove-ZHLBWItems -Items $CLEANUP_ITEMS
        exit $exitcode_FailStartingBitWarden
    }
    #endregion

    #region Cleanup time
    Remove-ZHLBWItems -Items $CLEANUP_ITEMS
    #endregion
}