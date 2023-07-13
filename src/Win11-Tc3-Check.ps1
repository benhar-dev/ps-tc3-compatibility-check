# -------------------------------------------------------------------------------------------------------------------------------
# Copyright 2022 benhar-dev
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
# files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, 
# modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software 
# is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR 
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# -------------------------------------------------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# Forces the powershell script to run as Administrator
# ----------------------------------------------------------------------------

param([switch]$Elevated)

if ([UserInformation]::IsNotAdministrator())  {
    if (-not $Elevated) {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

# ----------------------------------------------------------------------------
# Helper guides functions
# ----------------------------------------------------------------------------

function ShowGuide ($gistUrl) {

    try {
        $response = Invoke-RestMethod -Uri $gistUrl -Method Get
        Write-Host ""
        Write-Host "Extra Information on the failed test" -ForegroundColor Cyan
        Write-Host "------------------------------------" -ForegroundColor Cyan
        Write-Host $response -ForegroundColor Cyan
        Write-Host ""
        Write-Host ""
    }
    catch {
        Write-Host "Failed to get the content from the URL '$gistUrl'."
    }
}

# ----------------------------------------------------------------------------
# Helper Window Functions
# ----------------------------------------------------------------------------

function DisplayTitle ($title) {
	Write-Host $title
    Write-Host ("-" * $title.Length)
}

function DisplaySubTitle ($subtitle) {
    Write-Host ""
	Write-Host $subtitle
}

Function PauseWithMessage ($message)
{
    # Check if running Powershell ISE
    if ($psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else
    {
        Write-Host "$message"
        Write-Host "Press Any Key..."
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# ----------------------------------------------------------------------------
# Helper Classes, used by the tests at the bottom of the script.
# ----------------------------------------------------------------------------

class TwincatInformation {

    static [System.Version]Version() {
        if (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Beckhoff\TwinCAT3\System') {
            return [System.Version](Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Beckhoff\TwinCAT3\System").TcVersion
        }
         return [System.Version]'0'
    }
    
}

class DeviceGuard {

    static [BOOL]VirtualizationBasedSecurityStatus() {     
         return (Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard).VirtualizationBasedSecurityStatus
    }
    
}

class UserInformation {

    static [bool]IsAdministrator() {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

     static [bool]IsNotAdministrator() {
        return -Not [UserInformation]::IsAdministrator()
    }
    
}

class WindowsFeatureInformation {

    static [bool]IsWindowsFeatureEnabled($featureName) {
        $feature = Get-WindowsOptionalFeature -FeatureName $featureName -Online
        return ($feature.State -eq "Enabled")
    }

    static [bool]IsWindowsFeatureDisabled($featureName) {
        $feature = Get-WindowsOptionalFeature -FeatureName $featureName -Online
        return ($feature.State -eq "Disabled")
    }
    
}

class SystemServiceInformation {

    static [bool]IsServiceStopped($serviceName) {

        $service = Get-Service -name $serviceName
        return ($service.Status -contains 'Stopped')
    }

    static [bool]IsServiceRunning($serviceName) {

        $service = Get-Service -name $serviceName
        return ($service.Status -contains 'Running')
    }
    
}

class SystemInformation {

    hidden static [PSCustomObject]$output = $null

    static SystemInformation(){
        [SystemInformation]::Update()        
    }

    static Update() {
            [SystemInformation]::output = systeminfo       
    }

    static [bool]IsVirtualisationEnabledInTheFirmware() {
        return [SystemInformation]::output -Like '*Virtualization Enabled In Firmware: Yes'
    }
    
}

class ProcessorInformation {

    hidden static [PSCustomObject]$output = $null

    static ProcessorInformation(){
        [IntelProcessorInformation]::Update()        
    }

    static Update() {
        [IntelProcessorInformation]::output = Get-CimInstance -Class CIM_Processor | Select-Object *
    }

    static [string]Name() {
        return [IntelProcessorInformation]::output.Name
    }
    
}

class IntelProcessorInformation : ProcessorInformation {

    static [bool]ProcessorIsIntel() {
        return [IntelProcessorInformation]::Name() -like '*Intel*'
    }
    
}

class AmdProcessorInformation : ProcessorInformation {

    static [bool]ProcessorIsAmdRyzen() {
        return [IntelProcessorInformation]::Name() -like '*AMD Ryzen*'
    }
    
}

class BootConfigurationData {

    hidden static [PSCustomObject]$output = $null

    static BootConfigurationData(){
        [BootConfigurationData]::Update()        
    }

    static Update() {

        (bcdedit /enum | Out-String) -split '(?<=\r\n)\r\n' | ForEach-Object {
            $name, $data = $_ -split '\r\n---+\r\n'

            $props = [ordered]@{
                'name' = $name.Trim()
            }

            $data | Select-String '(?m)^(\S+)\s\s+(.*)' -AllMatches |
                Select-Object -Expand Matches |
                ForEach-Object { $props[$_.Groups[1].Value] = $_.Groups[2].Value.Trim() }

            [BootConfigurationData]::output = [PSCustomObject]$props
        }

    }

    static [bool]IsDynamicTickDisabled() {
        return ([BootConfigurationData]::output.disabledynamictick -eq 'Yes')
    }
    
    static [bool]IsUsePlatformTickEnabled() {
        return ([BootConfigurationData]::output.useplatformtick -eq 'Yes')
    }


}

# ----------------------------------------------------------------------------
# .Net Classes, used by the tests at the bottom of the script.
# ----------------------------------------------------------------------------

$KernalInformationSourceCode = @"
    namespace SystemInfo
    {
        using System;
        using System.Runtime.InteropServices;

        public static class KernalInformation
        {
            internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
            {
                /// </summary>
                SystemDmaGuardPolicyInformation = 202
            }

            [DllImport("ntdll.dll")]
            internal static extern Int32 NtQuerySystemInformation(
                SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
                IntPtr SystemInformation,
                Int32 SystemInformationLength,
                out Int32 ReturnLength);

            public static bool BootDmaEnabled() {
                Int32 result;
                Int32 SystemInformationLength = 1;
                IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
                Int32 ReturnLength;

                result = KernalInformation.NtQuerySystemInformation(
                        KernalInformation.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
                        SystemInformation,
                        SystemInformationLength,
                        out ReturnLength);

                if (result == 0) {
                    byte info = Marshal.ReadByte(SystemInformation, 0);
                    return (info != 0);
                }

                return false;
            }
        }
    }
"@
Add-Type -TypeDefinition $KernalInformationSourceCode

# ----------------------------------------------------------------------------
# Test Helper Functions
# ----------------------------------------------------------------------------

function Test
{
  param
  (
    $name,
  	$if = $true,
  	$assertTrue = $true,
    $assertFalse = $false,
    $message = '',
    $gistUrl = ''
  )
  if (-not $if) {
    ReportSkip $name 
    return
  }

  if (($assertTrue -eq $true) -and ($assertFalse -eq $false)){

    ReportPass $name

  } else {

    ReportFail $name $message

    DisplaySubTitle "Checks Failed. Test Aborted"
    ShowGuide($gistUrl)
    PauseWithMessage('Fail')
    Exit

  }
}

function ReportPass ($info) {
    Write-Host -NoNewline '   ['
	Write-Host -ForegroundColor Green -NoNewLine ([Char]8730)
    Write-Host -NoNewline ']PASS: '
	Write-Host $info
}

function ReportSkip ($info) {
    Write-Host -NoNewline '   ['
	Write-Host -ForegroundColor Gray -NoNewLine '-'
    Write-Host -NoNewline ']SKIP: '
	Write-Host $info
}

function ReportFail ($info,$message){
    Write-Host -NoNewline '   ['
	Write-Host -ForegroundColor Red -NoNewLine 'X'
    Write-Host -NoNewline ']FAIL: '
    if ($message) {
        Write-Host -NoNewline $info
        Write-Host -NoNewline ' REASON: '
        Write-Host $message
    } else {
        Write-Host $info
    }
}

# ----------------------------------------------------------------------------
# Start of TwinCAT 3 runtime compatibility checks
# Feel free to add your tests and checks here.#
# ----------------------------------------------------------------------------

DisplayTitle "TwinCAT3 Runtime Compatibility Check (Beta)"
DisplaySubTitle "Powershell checks"

    Test 'Script is running as Administrator'`
        -assertTrue ([UserInformation]::IsAdministrator())

DisplaySubTitle "Windows services checks"

    Test 'Hyper-V Heartbeat service is stopped'`
        -assertTrue ([SystemServiceInformation]::IsServiceStopped('vmicheartbeat'))`
        -message "Hyper-V Heartbeat service is running. This indicates that Hyper-V is enabled."

    Test 'Virtualization-based Security: VirtualizationBasedSecurityStatus is disabled.'`
        -assertFalse ([DeviceGuard]::VirtualizationBasedSecurityStatus())`
        -gistUrl "https://gist.githubusercontent.com/benhar-dev/1403b4e070655787c3f8ff1e15b1ab73/raw/0f3cb068ad337f55ac3ab4b1048969bd8e20d31b/Windows11-VirtualizationBasedSecurityStatus.md"

DisplaySubTitle "BIOS checks"

    Test 'Dynamic Tick Disabled'`
        -assertTrue ([BootConfigurationData]::IsDynamicTickDisabled())`
        -message "Disable dynamic tick has not been set. Please run C:\TwinCAT\3.1\System\win8settick.bat as Administrator"
    
    Test 'Use Platform Tick Enabled'`
        -assertTrue ([BootConfigurationData]::IsUsePlatformTickEnabled())`
        -message "Use platform tick has not been set. Please run C:\TwinCAT\3.1\System\win8settick.bat as Administrator"

    Test 'Virtualization (VT-X) is enabled In BIOS'`
        -assertTrue ([SystemInformation]::IsVirtualisationEnabledInTheFirmware())`
        -message "Virtualization (VT-X) is currently disabled In the BIOS. Please enable."

DisplaySubTitle "Windows feature checks"

    Test 'Hyper-V Windows Feature is disabled'`
        -assertTrue ([WindowsFeatureInformation]::IsWindowsFeatureDisabled('Microsoft-Hyper-V-All'))`
        -message "Hyper-V Windows Feature is enabled. You will need to disable this using 'Turn Windows Features On or Off', and unticking Hyper-V"

    Test 'Windows Sandbox Feature is disabled'`
        -assertTrue ([WindowsFeatureInformation]::IsWindowsFeatureDisabled('Containers-DisposableClientVM'))`
        -message "Windows Sandbox Feature is enabled. You will need to disable this using 'Turn Windows Features On or Off', and unticking Windows Sandbox"

    Test 'Virtual Machine Platform Feature is disabled'`
        -assertTrue ([WindowsFeatureInformation]::IsWindowsFeatureDisabled('VirtualMachinePlatform'))`
        -message "Virtual Machine Platform Feature is enabled. You will need to disable this using 'Turn Windows Features On or Off', and unticking Virtual Machine Platform"

DisplaySubTitle "Kernal checks"

    Test 'Kernel DMA Protection is off'`
        -if ([TwincatInformation]::Version() -lt [System.Version]'3.1.4024.17')`
        -assertFalse ([SystemInfo.KernalInformation]::BootDmaEnabled())`
        -message "Kernel DMA Protection is on. This is only allowed with TwinCAT3 version 3.1.4024.17 and above"

DisplaySubTitle "Processor checks"

    Test 'AMD Ryzen processor vs TwinCAT version compatible'`
        -if([AmdProcessorInformation]::ProcessorIsAmdRyzen())`
        -assertTrue([TwincatInformation]::Version() -ge [System.Version]'3.1.4024.25')`
        -message "AMD Ryzen detected. This is only allowed with TwinCAT3 version 3.1.4024.25 and above"

    # in progress, requires processor generation check to complete this test
    Test '11th Gen Intel processor vs TwinCAT version compatible'`
        -if($false -and [IntelProcessorInformation]::ProcessorIsIntel())`
        -assertTrue([TwincatInformation]::Version() -ge [System.Version]'3.1.4024.22')`
        -message "11th Gen Intel processor detected. This is only allowed with TwinCAT3 version 3.1.4024.22 and above"

    # in progress, requires processor generation check to complete this test
    Test '12th Gen Intel processor vs TwinCAT version compatible'`
        -if($false -and [IntelProcessorInformation]::ProcessorIsIntel())`
        -assertTrue([TwincatInformation]::Version() -ge [System.Version]'3.1.4024.25')`
        -message "12th Gen Intel processor detected. This is only allowed with TwinCAT3 version 3.1.4024.32 and above"


DisplaySubTitle "Checks Complete"
PauseWithMessage('Done')
Exit
