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

param([switch]$Elevated)
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

function DisplayTitle {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string] $title
	)
	Write-Host $title
    Write-Host ("-" * $title.Length)
}

function DisplaySubTitle {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string] $subtitle
	)
    Write-Host ""
	Write-Host $subtitle
}

function ReportPass {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string] $info
	)
    Write-Host -NoNewline '   ['
	Write-Host -ForegroundColor Green -NoNewLine ([Char]8730)
    Write-Host -NoNewline '] '
	Write-Host $info
}

function ReportFail {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string] $info
	)
    Write-Host -NoNewline '   ['
	Write-Host -ForegroundColor Red -NoNewLine 'X'
    Write-Host -NoNewline '] '
	Write-Host $info

}

Function PauseWithMessage
{
    [CmdletBinding()]
	param(
		[Parameter()]
		[string] $message
	)
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


Function GetTcVersion {
    if (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Beckhoff\TwinCAT3\System') {
        return [System.Version](Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Beckhoff\TwinCAT3\System").TcVersion
    }
}

Function IsHypervisorHeartbeatServiceStopped {
    if ($global:vmicheartbeatService -eq $null){
        $global:vmicheartbeatService = Get-Service -name vmicheartbeat
    }
    return ($global:vmicheartbeatService.Status -contains 'Stopped')
}

Function IsVirtualizationVTXEnabledInBios {
    if ($global:systemInfo -eq $null){
        $global:systemInfo = systeminfo
    }
    return ($global:systemInfo -Like '*Virtualization Enabled In Firmware: Yes') 
}

Function IsWindowsFeatureDisabled($featureName) {
    $feature = Get-WindowsOptionalFeature -FeatureName $featureName -Online
    return ($feature.State -eq "Disabled")
}

Function AssertTrue($testName,$condition,$failMessage){


}

# ----------------------------------------------------------------------------
class UserLevel {

    static [bool]IsAdministrator() {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

DisplayTitle "TwinCAT Runtime Compatibility Check (Beta)"
DisplaySubTitle "Powershell checks"

    if ([UserLevel]::IsAdministrator()) { 
        ReportPass "Script is running as Administrator."
    }else {
        ReportFail "Script not running as Administrator. Please run this script by right clicking and select 'Run as Administrator'"
        PauseWithMessage('Unable to continue')
        Exit
    }

DisplaySubTitle "Windows services checks"

if (IsHypervisorHeartbeatServiceStopped) { 
    ReportPass "Hyper-V Heartbeat service is stopped."
}else {
    ReportFail "Hyper-V Heartbeat service is running. This indicates that Hyper-V is enabled."
}


DisplaySubTitle "Bios checks"

    if ([BootConfigurationData]::IsDynamicTickDisabled()) { 
      ReportPass "Disable dynamic tick has been correctly set."
    }else {
      ReportFail "Disable dynamic tick has not been set. Please run C:\TwinCAT\3.1\System\win8settick.bat as Administrator"
    }

    if ([BootConfigurationData]::IsUsePlatformTickEnabled()) { 
      ReportPass "Use platform tick has been correctly set."
    }else {
      ReportFail "Use platform tick has not been set. Please run C:\TwinCAT\3.1\System\win8settick.bat as Administrator"
    }

    # virtualization enabled in firmware check (VT-X)
    if (IsVirtualizationVTXEnabledInBios) { 
      ReportPass "Virtualization (VT-X) is enabled In Firmware."
    }else {
      ReportFail "Virtualization (VT-X) is disabled In Firmware."
    }


DisplaySubTitle "Windows feature checks"

    # Windows feature Hyper-V
    if(IsWindowsFeatureDisabled('Microsoft-Hyper-V-All')) {
        ReportPass "Hyper-V Windows Feature is disabled."
    } else {
        ReportFail "Hyper-V Windows Feature is enabled. You will need to disable this using 'Turn Windows Features On or Off', and unticking Hyper-V"
    }

    # Windows feature Windows Sandbox
    if(IsWindowsFeatureDisabled('Containers-DisposableClientVM')) {
        ReportPass "Windows Sandbox Feature is disabled."
    } else {
        ReportFail "Windows Sandbox Feature is enabled. You will need to disable this using 'Turn Windows Features On or Off', and unticking Windows Sandbox"
    }

    # Windows feature Virtual Machine Platform
    if(IsWindowsFeatureDisabled('VirtualMachinePlatform')) {
        ReportPass "Virtual Machine Platform Feature is disabled."
    } else {
        ReportFail "Virtual Machine Platform Feature is enabled. You will need to disable this using 'Turn Windows Features On or Off', and unticking Virtual Machine Platform"
    }

DisplaySubTitle "Kernal checks"

    # Kernal - bootDMAProtection
    $bootDMAProtectionCheck =
    @"
      namespace SystemInfo
        {
          using System;
          using System.Runtime.InteropServices;

          public static class NativeMethods
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

            public static byte BootDmaCheck() {
              Int32 result;
              Int32 SystemInformationLength = 1;
              IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
              Int32 ReturnLength;

              result = NativeMethods.NtQuerySystemInformation(
                        NativeMethods.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
                        SystemInformation,
                        SystemInformationLength,
                        out ReturnLength);

              if (result == 0) {
                byte info = Marshal.ReadByte(SystemInformation, 0);
                return info;
              }

              return 0;
            }
          }
        }
"@

    Add-Type -TypeDefinition $bootDMAProtectionCheck
    $bootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0

    if($bootDMAProtection) {
        ReportPass "Kernel DMA Protection is on."
    } else {
        ReportFail "Kernel DMA Protection is off."
    }

DisplaySubTitle "Checks Complete"




PauseWithMessage('Done')
Exit