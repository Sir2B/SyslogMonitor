; Inno Setup script – compiled by build.ps1, which passes AppVersion, SourceDir, IconFile and OutputDir.
; Installs per user without admin rights; the firewall rule is an optional, elevated extra step.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "Syslog Monitor"
#define AppExe "SyslogMonitor.exe"
#define FirewallRule "Syslog Monitor (UDP inbound)"

[Setup]
AppId={{6E4C1E0A-2F7B-4C35-9D0E-5B1C9A7F3D21}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Tobias Obermayer
AppPublisherURL=https://github.com/Sir2B/SyslogMonitor
AppSupportURL=https://github.com/Sir2B/SyslogMonitor/issues
DefaultDirName={localappdata}\Programs\SyslogMonitor
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=SyslogMonitor-{#AppVersion}-setup
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "autostart"; Description: "Start automatically with Windows (runs in the system tray)"; Flags: unchecked
Name: "firewall"; Description: "Allow inbound Syslog (UDP) through the firewall — requires administrator rights"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Recreate optional shortcuts according to the selected tasks.
Type: files; Name: "{autodesktop}\{#AppName}.lnk"
Type: files; Name: "{userstartup}\{#AppName}.lnk"

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: autostart

[Run]
; program-bound rule: stays valid when the port is changed in the settings. Block rules that
; Windows created automatically for this exe on an earlier, unprivileged start would win, so drop them.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$exe = '{app}\{#AppExe}'; Remove-NetFirewallRule -DisplayName '{#FirewallRule}' -ErrorAction SilentlyContinue; Get-NetFirewallApplicationFilter -Program $exe | Get-NetFirewallRule | Where-Object Action -eq Block | Remove-NetFirewallRule; New-NetFirewallRule -DisplayName '{#FirewallRule}' -Direction Inbound -Protocol UDP -Program $exe -Action Allow"""; \
  Verb: runas; Flags: shellexec runhidden waituntilterminated; Tasks: firewall; \
  StatusMsg: "Configuring firewall rule…"
Filename: "{app}\{#AppExe}"; Description: "Start {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -Command ""Remove-NetFirewallRule -DisplayName '{#FirewallRule}' -ErrorAction SilentlyContinue"""; \
  Verb: runas; Flags: shellexec runhidden waituntilterminated; RunOnceId: "RemoveFirewallRule"; Check: FirewallRuleExists

[Code]
function FirewallRuleExists(): Boolean;
var
  ResultCode: Integer;
begin
  // reading needs no admin rights; only ask for elevation if there is something to remove
  Result := Exec('powershell.exe',
    '-NoProfile -Command "if (Get-NetFirewallRule -DisplayName ''{#FirewallRule}'' -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;
