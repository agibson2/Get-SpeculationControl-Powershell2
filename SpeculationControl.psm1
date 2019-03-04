function Get-SpeculationControlSettings {
  <#

  .SYNOPSIS
  This function queries the speculation control settings for the system.

  .DESCRIPTION
  This function queries the speculation control settings for the system.

  .PARAMETER Quiet
  This parameter suppresses host output that is displayed by default.
  
  #>

  [CmdletBinding()]
  param (
    [switch]$Quiet
  )
  
  process {

    $NtQSIDefinition = @'
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(uint systemInformationClass, IntPtr systemInformation, uint systemInformationLength, IntPtr returnLength);
'@
    
    $ntdll = Add-Type -MemberDefinition $NtQSIDefinition -Name 'ntdll' -Namespace 'Win32' -PassThru


    [System.IntPtr]$systemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
    [System.IntPtr]$returnLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

    $object = New-Object -TypeName PSObject

    try {

        $cpu = Get-MyCimInstance Win32_Processor

        if ($cpu -is [array]) {
            $cpu = $cpu[0]
        }

        $manufacturer = $cpu.Manufacturer
 
        #
        # Query branch target injection information.
        #

        if ($Quiet -ne $true) {

            Write-Host "For more information about the output below, please refer to https://support.microsoft.com/en-in/help/4074629" -ForegroundColor Cyan
            Write-Host
            Write-Host "Speculation control settings for CVE-2017-5715 [branch target injection]" -ForegroundColor Cyan

            if ($manufacturer -eq "AuthenticAMD") {
                Write-Host "AMD CPU detected: mitigations for branch target injection on AMD CPUs have additional registry settings for this mitigation, please refer to FAQ #15 at https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV180002" -ForegroundColor Cyan
            }

            Write-Host
        }

        $btiHardwarePresent = $false
        $btiWindowsSupportPresent = $false
        $btiWindowsSupportEnabled = $false
        $btiDisabledBySystemPolicy = $false
        $btiDisabledByNoHardwareSupport = $false

        $ssbdAvailable = $false
        $ssbdHardwarePresent = $false
        $ssbdSystemWide = $false
        $ssbdRequired = $null
    
        [System.UInt32]$systemInformationClass = 201
        [System.UInt32]$systemInformationLength = 4

        $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

        if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
            # fallthrough
        }
        elseif ($retval -ne 0) {
            throw (("Querying branch target injection information failed with error {0:X8}" -f $retval))
        }
        else {
    
            [System.UInt32]$scfBpbEnabled = 0x01
            [System.UInt32]$scfBpbDisabledSystemPolicy = 0x02
            [System.UInt32]$scfBpbDisabledNoHardwareSupport = 0x04
            [System.UInt32]$scfHwReg1Enumerated = 0x08
            [System.UInt32]$scfHwReg2Enumerated = 0x10
            [System.UInt32]$scfHwMode1Present = 0x20
            [System.UInt32]$scfHwMode2Present = 0x40
            [System.UInt32]$scfSmepPresent = 0x80
            [System.UInt32]$scfSsbdAvailable = 0x100
            [System.UInt32]$scfSsbdSupported = 0x200
            [System.UInt32]$scfSsbdSystemWide = 0x400
            [System.UInt32]$scfSsbdRequired = 0x1000

            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

            $btiHardwarePresent = ((($flags -band $scfHwReg1Enumerated) -ne 0) -or (($flags -band $scfHwReg2Enumerated)))
            $btiWindowsSupportPresent = $true
            $btiWindowsSupportEnabled = (($flags -band $scfBpbEnabled) -ne 0)

            if ($btiWindowsSupportEnabled -eq $false) {
                $btiDisabledBySystemPolicy = (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                $btiDisabledByNoHardwareSupport = (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
            }
            
            $ssbdAvailable = (($flags -band $scfSsbdAvailable) -ne 0)

            if ($ssbdAvailable -eq $true) {
                $ssbdHardwarePresent = (($flags -band $scfSsbdSupported) -ne 0)
                $ssbdSystemWide = (($flags -band $scfSsbdSystemWide) -ne 0)
                $ssbdRequired = (($flags -band $scfSsbdRequired) -ne 0)
            }

            if ($Quiet -ne $true -and $PSBoundParameters['Verbose']) {
                Write-Verbose "BpbEnabled                   :" (($flags -band $scfBpbEnabled) -ne 0)
                Write-Verbose "BpbDisabledSystemPolicy      :" (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                Write-Verbose "BpbDisabledNoHardwareSupport :" (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
                Write-Verbose "HwReg1Enumerated             :" (($flags -band $scfHwReg1Enumerated) -ne 0)
                Write-Verbose "HwReg2Enumerated             :" (($flags -band $scfHwReg2Enumerated) -ne 0)
                Write-Verbose "HwMode1Present               :" (($flags -band $scfHwMode1Present) -ne 0)
                Write-Verbose "HwMode2Present               :" (($flags -band $scfHwMode2Present) -ne 0)
                Write-Verbose "SmepPresent                  :" (($flags -band $scfSmepPresent) -ne 0)
                Write-Verbose "SsbdAvailable                :" (($flags -band $scfSsbdAvailable) -ne 0)
                Write-Verbose "SsbdSupported                :" (($flags -band $scfSsbdSupported) -ne 0)
                Write-Verbose "SsbdSystemWide               :" (($flags -band $scfSsbdSystemWide) -ne 0)
                Write-Verbose "SsbdRequired                 :" (($flags -band $scfSsbdRequired) -ne 0)
            }
        }

        if ($Quiet -ne $true) {
            Write-Host "Hardware support for branch target injection mitigation is present:"($btiHardwarePresent)
            Write-Host "Windows OS support for branch target injection mitigation is present:"($btiWindowsSupportPresent)
            Write-Host "Windows OS support for branch target injection mitigation is enabled:"($btiWindowsSupportEnabled)
  
            if ($btiWindowsSupportPresent -eq $true -and $btiWindowsSupportEnabled -eq $false) {
                Write-Host "Windows OS support for branch target injection mitigation is disabled by system policy:"($btiDisabledBySystemPolicy)
                Write-Host "Windows OS support for branch target injection mitigation is disabled by absence of hardware support:"($btiDisabledByNoHardwareSupport)
            }
        }
        
        $object | Add-Member -MemberType NoteProperty -Name BTIHardwarePresent -Value $btiHardwarePresent
        $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportPresent -Value $btiWindowsSupportPresent
        $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportEnabled -Value $btiWindowsSupportEnabled
        $object | Add-Member -MemberType NoteProperty -Name BTIDisabledBySystemPolicy -Value $btiDisabledBySystemPolicy
        $object | Add-Member -MemberType NoteProperty -Name BTIDisabledByNoHardwareSupport -Value $btiDisabledByNoHardwareSupport

        #
        # Query kernel VA shadow information.
        #
        
        if ($Quiet -ne $true) {
            Write-Host
            Write-Host "Speculation control settings for CVE-2017-5754 [rogue data cache load]" -ForegroundColor Cyan
            Write-Host    
        }

        $kvaShadowRequired = $true
        $kvaShadowPresent = $false
        $kvaShadowEnabled = $false
        $kvaShadowPcidEnabled = $false
        
        $l1tfRequired = $true
        $l1tfMitigationPresent = $false
        $l1tfMitigationEnabled = $false
        $l1tfFlushSupported = $false
        $l1tfInvalidPteBit = $null

        [System.UInt32]$systemInformationClass = 196
        [System.UInt32]$systemInformationLength = 4

        $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

        if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
        }
        elseif ($retval -ne 0) {
            throw (("Querying kernel VA shadow information failed with error {0:X8}" -f $retval))
        }
        else {
    
            [System.UInt32]$kvaShadowEnabledFlag = 0x01
            [System.UInt32]$kvaShadowUserGlobalFlag = 0x02
            [System.UInt32]$kvaShadowPcidFlag = 0x04
            [System.UInt32]$kvaShadowInvpcidFlag = 0x08
            [System.UInt32]$kvaShadowRequiredFlag = 0x10
            [System.UInt32]$kvaShadowRequiredAvailableFlag = 0x20
            
            [System.UInt32]$l1tfInvalidPteBitMask = 0xfc0
            [System.UInt32]$l1tfInvalidPteBitShift = 6
            [System.UInt32]$l1tfFlushSupportedFlag = 0x1000
            [System.UInt32]$l1tfMitigationPresentFlag = 0x2000

            [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

            $kvaShadowPresent = $true
            $kvaShadowEnabled = (($flags -band $kvaShadowEnabledFlag) -ne 0)
            $kvaShadowPcidEnabled = ((($flags -band $kvaShadowPcidFlag) -ne 0) -and (($flags -band $kvaShadowInvpcidFlag) -ne 0))
            
            if (($flags -band $kvaShadowRequiredAvailableFlag) -ne 0) {
                $kvaShadowRequired = (($flags -band $kvaShadowRequiredFlag) -ne 0)
            }
            else {

                if ($manufacturer -eq "AuthenticAMD") {
                    $kvaShadowRequired = $false
                }
                elseif ($manufacturer -eq "GenuineIntel") {
                    $regex = [regex]'Family (\d+) Model (\d+) Stepping (\d+)'
                    $result = $regex.Match($cpu.Description)
            
                    if ($result.Success) {
                        $family = [System.UInt32]$result.Groups[1].Value
                        $model = [System.UInt32]$result.Groups[2].Value
                        $stepping = [System.UInt32]$result.Groups[3].Value
                
                        if (($family -eq 0x6) -and 
                            (($model -eq 0x1c) -or
                             ($model -eq 0x26) -or
                             ($model -eq 0x27) -or
                             ($model -eq 0x36) -or
                             ($model -eq 0x35))) {

                            $kvaShadowRequired = $false
                        }
                    }
                }
                else {
                    throw ("Unsupported processor manufacturer: {0}" -f $manufacturer)
                }
            }

            $l1tfRequired = $kvaShadowRequired

            $l1tfInvalidPteBit = Convert-BitShift ($flags -band $l1tfInvalidPteBitMask) -right $l1tfInvalidPteBitShift

            $l1tfMitigationEnabled = (($l1tfInvalidPteBit -ne 0) -and ($kvaShadowEnabled -eq $true))
            $l1tfFlushSupported = (($flags -band $l1tfFlushSupportedFlag) -ne 0)

            if (($flags -band $l1tfMitigationPresentFlag) -or
                ($l1tfMitigationEnabled -eq $true) -or 
                ($l1tfFlushSupported -eq $true)) {
                $l1tfMitigationPresent = $true
            }

            if ($Quiet -ne $true -and $PSBoundParameters['Verbose']) {
                Write-Verbose "KvaShadowEnabled             :" (($flags -band $kvaShadowEnabledFlag) -ne 0)
                Write-Verbose "KvaShadowUserGlobal          :" (($flags -band $kvaShadowUserGlobalFlag) -ne 0)
                Write-Verbose "KvaShadowPcid                :" (($flags -band $kvaShadowPcidFlag) -ne 0)
                Write-Verbose "KvaShadowInvpcid             :" (($flags -band $kvaShadowInvpcidFlag) -ne 0)
                Write-Verbose "KvaShadowRequired            :" $kvaShadowRequired
                Write-Verbose "KvaShadowRequiredAvailable   :" (($flags -band $kvaShadowRequiredAvailableFlag) -ne 0)
                Write-Verbose "L1tfRequired                 :" $l1tfRequired
                Write-Verbose "L1tfInvalidPteBit            :" $l1tfInvalidPteBit
                Write-Verbose "L1tfFlushSupported           :" $l1tfFlushSupported
            }
        }
        
        if ($Quiet -ne $true) {
            Write-Host "Hardware requires kernel VA shadowing:"$kvaShadowRequired

            if ($kvaShadowRequired) {

                Write-Host "Windows OS support for kernel VA shadow is present:"$kvaShadowPresent
                Write-Host "Windows OS support for kernel VA shadow is enabled:"$kvaShadowEnabled

                if ($kvaShadowEnabled) {
                    Write-Host "Windows OS support for PCID performance optimization is enabled: $kvaShadowPcidEnabled [not required for security]"
                }
            }
        }
        
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowRequired -Value $kvaShadowRequired
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportPresent -Value $kvaShadowPresent
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportEnabled -Value $kvaShadowEnabled
        $object | Add-Member -MemberType NoteProperty -Name KVAShadowPcidEnabled -Value $kvaShadowPcidEnabled

        #
        # Speculation Control Settings for CVE-2018-3639 (Speculative Store Bypass)
        #
        
        if ($Quiet -ne $true) {
            Write-Host
            Write-Host "Speculation control settings for CVE-2018-3639 [speculative store bypass]" -ForegroundColor Cyan
            Write-Host    
        }
        
        if ($Quiet -ne $true) {
            if (($ssbdAvailable -eq $true)) {
                Write-Host "Hardware is vulnerable to speculative store bypass:"$ssbdRequired
                if ($ssbdRequired -eq $true) {
                    Write-Host "Hardware support for speculative store bypass disable is present:"$ssbdHardwarePresent
                    Write-Host "Windows OS support for speculative store bypass disable is present:"$ssbdAvailable
                    Write-Host "Windows OS support for speculative store bypass disable is enabled system-wide:"$ssbdSystemWide
                }
            }
            else {
                Write-Host "Windows OS support for speculative store bypass disable is present:"$ssbdAvailable
            }
        }

        $object | Add-Member -MemberType NoteProperty -Name SSBDWindowsSupportPresent -Value $ssbdAvailable
        $object | Add-Member -MemberType NoteProperty -Name SSBDHardwareVulnerable -Value $ssbdRequired
        $object | Add-Member -MemberType NoteProperty -Name SSBDHardwarePresent -Value $ssbdHardwarePresent
        $object | Add-Member -MemberType NoteProperty -Name SSBDWindowsSupportEnabledSystemWide -Value $ssbdSystemWide

        
        #
        # Speculation Control Settings for CVE-2018-3620 (L1 Terminal Fault)
        #
        
        if ($Quiet -ne $true) {
            Write-Host
            Write-Host "Speculation control settings for CVE-2018-3620 [L1 terminal fault]" -ForegroundColor Cyan
            Write-Host    
        }
        
        if ($Quiet -ne $true) {
            Write-Host "Hardware is vulnerable to L1 terminal fault:"$l1tfRequired

            if ($l1tfRequired -eq $true) {
                Write-Host "Windows OS support for L1 terminal fault mitigation is present:"$l1tfMitigationPresent
                Write-Host "Windows OS support for L1 terminal fault mitigation is enabled:"$l1tfMitigationEnabled
            }
        }

        $object | Add-Member -MemberType NoteProperty -Name L1TFHardwareVulnerable -Value $l1tfRequired
        $object | Add-Member -MemberType NoteProperty -Name L1TFWindowsSupportPresent -Value $l1tfMitigationPresent
        $object | Add-Member -MemberType NoteProperty -Name L1TFWindowsSupportEnabled -Value $l1tfMitigationEnabled
        $object | Add-Member -MemberType NoteProperty -Name L1TFInvalidPteBit -Value $l1tfInvalidPteBit
        $object | Add-Member -MemberType NoteProperty -Name L1DFlushSupported -Value $l1tfFlushSupported

        #
        # Provide guidance as appropriate.
        #

        $actions = @()
        
        if ($btiHardwarePresent -eq $false) {
            $actions += "Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation."
        }

        if (($btiWindowsSupportPresent -eq $false) -or 
            ($kvaShadowPresent -eq $false) -or
            ($ssbdAvailable -eq $false) -or
            ($l1tfMitigationPresent -eq $false)) {
            $actions += "Install the latest available updates for Windows with support for speculation control mitigations."
        }

        if (($btiHardwarePresent -eq $true -and $btiWindowsSupportEnabled -eq $false) -or 
            ($kvaShadowRequired -eq $true -and $kvaShadowEnabled -eq $false) -or
            ($l1tfRequired -eq $true -and $l1tfMitigationEnabled -eq $false)) {
            $guidanceUri = ""
            $guidanceType = ""

            
            $os = Get-MyCimInstance Win32_OperatingSystem

            if ($os.ProductType -eq 1) {
                # Workstation
                $guidanceUri = "https://support.microsoft.com/help/4073119"
                $guidanceType = "Client"
            }
            else {
                # Server/DC
                $guidanceUri = "https://support.microsoft.com/help/4072698"
                $guidanceType = "Server"
            }

            $actions += "Follow the guidance for enabling Windows $guidanceType support for speculation control mitigations described in $guidanceUri"
        }

        if ($Quiet -ne $true -and $actions.Length -gt 0) {

            Write-Host
            Write-Host "Suggested actions" -ForegroundColor Cyan
            Write-Host 

            foreach ($action in $actions) {
                Write-Host " *" $action
            }
        }

        return $object

    }
    finally
    {
        if ($systemInformationPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemInformationPtr)
        }
 
        if ($returnLengthPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($returnLengthPtr)
        }
    }    
  }
}

# Source: https://stackoverflow.com/questions/35116636/bit-shifting-in-powershell-2-0
# Powershell 2.0 doesn't have -lsh and -rsh bit shifting features so this is an alternative
function Convert-BitShift {
    param (
        [Parameter(Position = 0, Mandatory = $True)]
        [int] $Number,

        [Parameter(ParameterSetName = 'Left', Mandatory = $False)]
        [int] $Left,

        [Parameter(ParameterSetName = 'Right', Mandatory = $False)]
        [int] $Right
    ) 

    $shift = 0
    if ($PSCmdlet.ParameterSetName -eq 'Left')
    { 
        $shift = $Left
    }
    else
    {
        $shift = -$Right
    }

    return [math]::Floor($Number * [math]::Pow(2,$shift))
}

Function Test-IsWsman3 {
[cmdletbinding()]
Param(
[Parameter(Position=0,ValueFromPipeline=$true)]
[string]$Computername=$env:computername
)

Begin {
    #a regular expression pattern to match the ending
    [regex]$rx="\d\.\d$"
}
Process {
    Try {
        $result = Test-WSMan -ComputerName $Computername -ErrorAction Stop
    }
    Catch {
        Write-Error $_.exception.message
    }
    if ($result) {
        $m = $rx.match($result.productversion).value
        if ($m -eq '3.0') {
            $True
        }
        else {
            $False
        }
    }
} #process
End {
 #not used
}
} #end Test-IsWSMan


#From: https://powershell.org/2013/04/get-ciminstance-from-powershell-2-0/
# This is to simulate the Get-MyCimInstance in Powershell 3.0 for 2.0

Function Get-MyCimInstance {

<#
.Synopsis
Create on-the-fly CIMSessions to retrieve WMI data
.Description
The Get-CimInstance cmdlet in PowerShell 3 can be used to retrieve WMI information
from a remote computer using the WSMAN protocol instead of the legacy WMI service
that uses DCOM and RPC. However, the remote computers must be running PowerShell
3 and the latest version of the WSMAN protocol. When querying a remote computer,
Get-CIMInstance setups a temporary CIMSession. However, if the remote computer is
running PowerShell 2.0 this will fail. You have to manually create a CIMSession
with a CIMSessionOption to use the DCOM protocol.

This command does that for you automatically. It is designed to use computernames.
The computer is tested and if it is running PowerShell 2.0 then a temporary session
is created using DCOM. Otherwise a standard CIMSession is created. The remaining 
CIM parameters are then passed to Get-CIMInstance.

Get-MyCimInstance is essentially a wrapper around Get-CimInstance to make it easier
to query data from a mix of computers.
.Example
PS C:\> get-content computers.txt | get-myciminstance -class win32_logicaldisk -filter "drivetype=3"
.Notes
Last Updated: April 11, 2013
Version     : 1.0
Author      : Jeffery Hicks (@JeffHicks)

Read PowerShell:
Learn Windows PowerShell 3 in a Month of Lunches
Learn PowerShell Toolmaking in a Month of Lunches
PowerShell in Depth: An Administrator's Guide

.Link
http://jdhitsolutions.com/blog/2013/04/get-ciminstance-from-powershell-2-0

.Link
Get-CimInstance
New-CimSession
New-CimsessionOption

.Inputs
string

.Outputs
CIMInstance

#>

[cmdletbinding()]

Param(
[Parameter(Position=0,Mandatory=$true,HelpMessage="Enter a class name",
ValueFromPipelineByPropertyName=$true)]
[ValidateNotNullorEmpty()]
[string]$Class,
[Parameter(Position=1,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
[ValidateNotNullorEmpty()]
[string[]]$Computername=$env:computername,
[Parameter(ValueFromPipelineByPropertyName=$true)]
[string]$Filter,
[Parameter(ValueFromPipelineByPropertyName=$true)]
[string[]]$Property,
[Parameter(ValueFromPipelineByPropertyName=$true)]
[ValidateNotNullorEmpty()]
[string]$Namespace="root\cimv2",
[switch]$KeyOnly,
[uint32]$OperationTimeoutSec,
[switch]$Shallow,
[System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty
)

Begin {
    Write-Verbose -Message "Starting $($MyInvocation.Mycommand)"  
    Write-verbose -Message ($PSBoundParameters | out-string)

    Function Test-IsWsman3 {
        [cmdletbinding()]
        Param(
        [Parameter(Position=0,ValueFromPipeline=$true)]
        [string]$Computername=$env:computername
        )

        Begin {
            #a regular expression pattern to match the ending
            [regex]$rx="\d\.\d$"
        }
        Process {
            Try {
                $result = Test-WSMan -ComputerName $Computername -ErrorAction Stop
            }
            Catch {
                #Write the error to the pipeline if the computer is offline
                #or there is some other issue
                write-Error $_.exception.message
            }
            if ($result) {
                $m = $rx.match($result.productversion).value
                if ($m -eq '3.0') {
                    $True
                }
                else {
                    $False
                }
            }
        } #process
        End {
         #not used
        }
        } #end Test-IsWSMan

} #begin

Process {
    foreach ($computer in $computername) {
        Write-Verbose "Processing $computer"

        #hashtable of parameters for New-CimSession
        $sessParam=@{Computername=$computer;ErrorAction='Stop'}
        if ($credential) {
            Write-Verbose "Adding alternate credential for CIMSession"
            $sessParam.Add("Credential",$Credential)
        }
        Try {
        #test if computer is running WSMAN 2
        $isWSMAN3 = Test-IsWsman3 -Computername $computer -ErrorAction Stop

        if (-NOT $isWSMAN3) {
            #create a CIM session using the DCOM protocol
            Write-Verbose "Creating a DCOM option"
            $opt = New-CimSessionOption -Protocol Dcom
            $sessparam.Add("SessionOption",$opt)
        }
        Else {
                Write-Verbose "Confirmed WSMAN 3.0"
        }

        Try {               
            $session = New-CimSession @sessParam
        }
        Catch {
            Write-Warning "Failed to create a CIM session to $computer"
            Write-Warning $_.Exception.Message
        }

        #create the parameters to pass to Get-CIMInstance
        $paramHash=@{
         CimSession= $session
         Class = $class
        }

        $cimParams = "Filter","KeyOnly","Shallow","OperationTimeOutSec","Namespace"
        foreach ($param in $cimParams) {
          if ($PSBoundParameters.ContainsKey($param)) {
            Write-Verbose "Adding $param"
            $paramhash.Add($param,$PSBoundParameters.Item($param))
          } #if
        } #foreach param

        #execute the query
        Write-Verbose "Querying $class"
        Get-CimInstance @paramhash

        #remove the temporary cimsession
        Remove-CimSession $session
     } #Try
     Catch {
        Write-Warning "Unable to verify WSMAN on $Computer"
     }
    } #foreach computer

} #process

End {
    Write-Verbose -Message "Ending $($MyInvocation.Mycommand)"
} #end

} #end Get-MyCimInstance
