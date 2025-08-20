# ===================================================
# OTIMIZADOR PC ULTRA+ (50+ Funções) - Sem Emojis
# PowerShell + Windows Forms
# ===================================================

# --------- Requisitos/Elevação ---------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# --------- UI / Imports ---------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --------- Infra: Log e Helpers ---------
$Global:BasePath = "C:\OtimizadorUltra"
$Global:LogPath  = Join-Path $BasePath "log.txt"
$null = New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log($msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] $msg"
    Add-Content -Path $Global:LogPath -Value $line
}

function Confirm-Action($text="Deseja continuar?") {
    $res = [System.Windows.Forms.MessageBox]::Show($text,"Confirmar", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
    return ($res -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Show-Message {
    param([string]$Text, [string]$Title = "Otimizador PC", [string]$Icon = "Information")
    [System.Windows.Forms.MessageBox]::Show($Text, $Title, "OK", $Icon) | Out-Null
    Write-Log "$Title -> $Text"
}

# --------- Ponto de Restauração / Backup Registro ---------
function Create-RestorePoint {
    try {
        Checkpoint-Computer -Description "OtimizadorUltra" -RestorePointType "MODIFY_SETTINGS"
        Show-Message "Ponto de restauração criado." "Restauração"
    } catch { Show-Message "Falha ao criar ponto de restauração: $($_.Exception.Message)" "Erro" }
}
function Backup-Registry {
    $bk = Join-Path $Global:BasePath ("reg-backup-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
    New-Item -ItemType Directory -Path $bk -Force | Out-Null
    & reg export HKLM "$bk\HKLM.reg" /y | Out-Null
    & reg export HKCU "$bk\HKCU.reg" /y | Out-Null
    Show-Message "Backup do Registro salvo em: $bk" "Backup Registro"
}

# ===================================================
# FORM
# ===================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Otimizador PC ULTRA+"
$form.Size = New-Object System.Drawing.Size(980, 720)
$form.StartPosition = "CenterScreen"
$form.BackColor = "#1e1e1e"
$form.ForeColor = "White"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.MaximizeBox = $true

$tab = New-Object System.Windows.Forms.TabControl
$tab.Dock = "Fill"

function New-Flow() {
    $f = New-Object System.Windows.Forms.FlowLayoutPanel
    $f.Dock = "Fill"; $f.AutoScroll = $true; $f.BackColor = "#2d2d2d"
    return $f
}
function Add-Button($panel, $text, $scriptBlock, $color="#3B82F6") {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text
    $b.Size = New-Object System.Drawing.Size(310, 42)
    $b.BackColor = $color; $b.ForeColor = "White"
    $b.FlatStyle = "Flat"; $b.Cursor = "Hand"
    $b.Add_Click($scriptBlock)
    $panel.Controls.Add($b)
}

# ===================================================
# ABA: INÍCIO (Ponto de restauração, backup, log)
# ===================================================
$tabStart = New-Object System.Windows.Forms.TabPage
$tabStart.Text = "Início"
$flowStart = New-Flow

Add-Button $flowStart "Criar Ponto de Restauração" { Create-RestorePoint }
Add-Button $flowStart "Backup do Registro" { Backup-Registry }
Add-Button $flowStart "Abrir Pasta de Logs" { Start-Process $Global:BasePath }
Add-Button $flowStart "Abrir Visualizador de Logs" { notepad $Global:LogPath }

$tabStart.Controls.Add($flowStart)
$tab.Controls.Add($tabStart)

# ===================================================
# ABA: LIMPEZA (10+)
# ===================================================
$tabClean = New-Object System.Windows.Forms.TabPage
$tabClean.Text = "Limpeza"
$flowClean = New-Flow

Add-Button $flowClean "Limpar Arquivos Temporários" {
    $paths = "$env:TEMP\*", "C:\Windows\Temp\*", "$env:LOCALAPPDATA\Temp\*"
    foreach ($p in $paths) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
    Show-Message "Temporários removidos." "Limpeza"
} "#EF4444"

Add-Button $flowClean "Limpar Prefetch" {
    if (Confirm-Action "Limpar Prefetch pode afetar o primeiro boot após limpeza. Continuar?") {
        Remove-Item "$env:WINDIR\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
        Show-Message "Prefetch limpo." "Limpeza"
    }
} "#EF4444"

Add-Button $flowClean "Limpar Cache de Miniaturas" {
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*" -Force -ErrorAction SilentlyContinue
    Show-Message "Cache de miniaturas limpo." "Limpeza"
} "#EF4444"

Add-Button $flowClean "Limpar Logs de Eventos" {
    wevtutil el | ForEach-Object { try { wevtutil cl $_ } catch {} }
    Show-Message "Logs de eventos limpos." "Limpeza"
} "#EF4444"

Add-Button $flowClean "Limpar Cache Windows Update" {
    net stop wuauserv | Out-Null
    net stop bits | Out-Null
    Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    net start bits | Out-Null
    net start wuauserv | Out-Null
    Show-Message "Cache do Windows Update limpo." "Limpeza"
} "#EF4444"

Add-Button $flowClean "Limpar Cache da Microsoft Store" {
    Start-Process "wsreset.exe"
    Show-Message "wsreset iniciado." "Limpeza"
} "#EF4444"

Add-Button $flowClean "Remover Apps Pré-instalados (lista segura)" {
    $apps = "*Xbox*", "*Solitaire*", "*Skype*", "*Teams*", "*Clipchamp*", "*Zune*", "*3DBuilder*", "*GetHelp*", "*Help*", "*MixedReality*"
    foreach ($a in $apps) { Get-AppxPackage $a | Remove-AppxPackage -ErrorAction SilentlyContinue }
    Show-Message "Apps desnecessários removidos (se presentes)." "Limpeza"
} "#EF4444"

Add-Button $flowClean "Remover Arquivos de Crash Dumps" {
    Remove-Item "C:\Windows\Minidump\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\MEMORY.DMP" -Force -ErrorAction SilentlyContinue
    Show-Message "Crash dumps removidos." "Limpeza"
} "#EF4444"

Add-Button $flowClean "Limpar Cache de Fontes" {
    Remove-Item "$env:WINDIR\ServiceProfiles\LocalService\AppData\Local\FontCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Show-Message "Cache de fontes limpo." "Limpeza"
} "#EF4444"

Add-Button $flowClean "StartComponentCleanup (DISM)" {
    Start-Process dism.exe "/Online /Cleanup-Image /StartComponentCleanup" -Verb RunAs -Wait
    Show-Message "StartComponentCleanup concluído." "DISM"
} "#EF4444"

$tabClean.Controls.Add($flowClean)
$tab.Controls.Add($tabClean)

# ===================================================
# ABA: OTIMIZAÇÃO (15+)
# ===================================================
$tabOpt = New-Object System.Windows.Forms.TabPage
$tabOpt.Text = "Otimização"
$flowOpt = New-Flow

Add-Button $flowOpt "Otimizar Disco (C:)" {
    Optimize-Volume -DriveLetter C -Defrag -ErrorAction SilentlyContinue
    Show-Message "Otimização do volume C: concluída." "Disco"
}

Add-Button $flowOpt "Ativar Alto Desempenho" {
    powercfg /setactive SCHEME_MIN
    Show-Message "Plano de energia: Alto desempenho." "Energia"
}

Add-Button $flowOpt "Ativar Desempenho Máximo (Ultimate se disponível)" {
    try {
        powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
    } catch {}
    $guid = (powercfg -list) -match "Ultimate Performance" | ForEach-Object {
        ($_ -split '\s+\(')[0].Trim()
    } | Select-Object -First 1
    if ($guid) { powercfg /setactive $guid; Show-Message "Ultimate Performance ativado." "Energia" }
    else { Show-Message "Plano Ultimate não disponível nesta edição." "Energia" }
}

Add-Button $flowOpt "Desativar Hibernação" {
    powercfg /h off
    Show-Message "Hibernação desativada." "Energia"
}

Add-Button $flowOpt "Ativar TRIM (SSD)" {
    fsutil behavior set DisableDeleteNotify 0 | Out-Null
    Show-Message "TRIM ativado para SSD." "SSD"
}

Add-Button $flowOpt "Desativar Indexação (Windows Search)" {
    Stop-Service WSearch -Force -ErrorAction SilentlyContinue
    Set-Service WSearch -StartupType Disabled -ErrorAction SilentlyContinue
    Show-Message "Windows Search desativado." "Serviço"
}

Add-Button $flowOpt "Reativar Indexação (Desfazer)" {
    Set-Service WSearch -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service WSearch -ErrorAction SilentlyContinue
    Show-Message "Windows Search reativado." "Serviço"
}

Add-Button $flowOpt "Reduzir Efeitos Visuais" {
    Set-ItemProperty "HKCU:\Control Panel\Desktop" "DragFullWindows" "0"
    Set-ItemProperty "HKCU:\Control Panel\Desktop" "MenuShowDelay" "80"
    Set-ItemProperty "HKCU:\Control Panel\Desktop" "WaitToKillAppTimeout" "2000"
    Show-Message "Efeitos visuais reduzidos." "Interface"
}

Add-Button $flowOpt "Desativar SysMain (Superfetch)" {
    Stop-Service SysMain -Force -ErrorAction SilentlyContinue
    Set-Service SysMain -StartupType Disabled -ErrorAction SilentlyContinue
    Show-Message "SysMain desativado." "Serviço"
}

Add-Button $flowOpt "Reativar SysMain (Desfazer)" {
    Set-Service SysMain -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service SysMain -ErrorAction SilentlyContinue
    Show-Message "SysMain reativado." "Serviço"
}

Add-Button $flowOpt "Gerenciar Pagefile (Automático)" {
    wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True | Out-Null
    Show-Message "Memória virtual ajustada para automático." "Pagefile"
}

Add-Button $flowOpt "Desativar Programas de Inicialização (User)" {
    Get-CimInstance Win32_StartupCommand | ForEach-Object { try { $_.Delete() | Out-Null } catch {} }
    Show-Message "Entradas de inicialização do usuário removidas." "Startup"
}

Add-Button $flowOpt "Exportar Programas de Inicialização" {
    $out = Join-Path $Global:BasePath "startup.csv"
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Export-Csv $out -NoTypeInformation -Encoding UTF8
    Show-Message "Relatório salvo em: $out" "Startup"
}

Add-Button $flowOpt "Desativar Serviços (lista segura)" {
    $services = "Fax","RemoteRegistry","XblGameSave","MapsBroker","RetailDemo","WbioSrvc","SharedAccess"
    foreach ($s in $services) {
        try { Stop-Service $s -Force -ErrorAction SilentlyContinue; Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
    }
    Show-Message "Serviços desnecessários desativados." "Serviços"
}

Add-Button $flowOpt "Reverter Serviços (Automático)" {
    $services = "Fax","RemoteRegistry","XblGameSave","MapsBroker","RetailDemo","WbioSrvc","SharedAccess"
    foreach ($s in $services) {
        try { Set-Service $s -StartupType Manual -ErrorAction SilentlyContinue } catch {}
    }
    Show-Message "Serviços revertidos para Manual." "Serviços"
}

$tabOpt.Controls.Add($flowOpt)
$tab.Controls.Add($tabOpt)

# ===================================================
# ABA: REDE (10+)
# ===================================================
$tabNet = New-Object System.Windows.Forms.TabPage
$tabNet.Text = "Rede"
$flowNet = New-Flow

Add-Button $flowNet "Flush DNS e Reset Winsock" {
    ipconfig /flushdns | Out-Null
    netsh winsock reset | Out-Null
    netsh int ip reset | Out-Null
    Show-Message "DNS limpo e Winsock/IP resetados. Reinicie o PC." "Rede"
} "#10B981"

Add-Button $flowNet "Desativar IPv6 (todas as interfaces)" {
    netsh interface ipv6 set teredo disabled | Out-Null
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    Show-Message "IPv6 desativado (bindings)." "Rede"
} "#10B981"

Add-Button $flowNet "Reativar IPv6" {
    Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    Show-Message "IPv6 reativado." "Rede"
} "#10B981"

Add-Button $flowNet "Liberar Largura Reservada (QoS)" {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" 0
    Show-Message "QoS ajustado para 0% reservado." "Rede"
} "#10B981"

Add-Button $flowNet "Otimizar TCP (Gaming/Latência)" {
    netsh int tcp set global autotuninglevel=normal | Out-Null
    netsh int tcp set global rss=enabled | Out-Null
    netsh int tcp set global chimney=default | Out-Null
    Show-Message "Parâmetros TCP ajustados." "Rede"
} "#10B981"

Add-Button $flowNet "Desativar Detecção de Proxy" {
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "AutoDetect" 0
    Show-Message "Detecção automática de proxy desativada." "Rede"
} "#10B981"

Add-Button $flowNet "Limpar Configurações de Proxy" {
    netsh winhttp reset proxy | Out-Null
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable" 0
    Show-Message "Proxy desativado e limpo." "Rede"
} "#10B981"

Add-Button $flowNet "Renovar IP" {
    ipconfig /release | Out-Null
    ipconfig /renew | Out-Null
    Show-Message "IP renovado." "Rede"
} "#10B981"

Add-Button $flowNet "Desativar NetBIOS sobre TCP/IP" {
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object {
        $_.SetTcpipNetbios(2) | Out-Null
    }
    Show-Message "NetBIOS desativado (IPEnabled)." "Rede"
} "#10B981"

Add-Button $flowNet "Reativar NetBIOS" {
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object {
        $_.SetTcpipNetbios(1) | Out-Null
    }
    Show-Message "NetBIOS reativado." "Rede"
} "#10B981"

$tabNet.Controls.Add($flowNet)
$tab.Controls.Add($tabNet)

# ===================================================
# ABA: PRIVACIDADE (10)
# ===================================================
$tabPriv = New-Object System.Windows.Forms.TabPage
$tabPriv.Text = "Privacidade"
$flowPriv = New-Flow

Add-Button $flowPriv "Desativar Telemetria" {
    Set-Service "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
    Show-Message "Telemetria desativada." "Privacidade"
} "#8B5CF6"

Add-Button $flowPriv "Desativar Cortana" {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
    Show-Message "Cortana desativada." "Privacidade"
} "#8B5CF6"

Add-Button $flowPriv "Desativar Sugestões/Anúncios" {
    $cdm = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    New-Item -Path $cdm -Force | Out-Null
    "SystemPaneSuggestionsEnabled","SubscribedContent-338389Enabled","SubscribedContent-310093Enabled","SubscribedContent-338388Enabled" |
        ForEach-Object { Set-ItemProperty $cdm $_ 0 }
    Show-Message "Sugestões e anúncios desativados." "Privacidade"
} "#8B5CF6"

Add-Button $flowPriv "Desativar Histórico de Atividades" {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
    Show-Message "Timeline/Atividades desativada." "Privacidade"
} "#8B5CF6"

Add-Button $flowPriv "Desativar Localização (Serviço)" {
    Stop-Service "lfsvc" -ErrorAction SilentlyContinue
    Set-Service "lfsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Show-Message "Serviço de localização desativado." "Privacidade"
} "#8B5CF6"

Add-Button $flowPriv "Reativar Localização" {
    Set-Service "lfsvc" -StartupType Manual -ErrorAction SilentlyContinue
    Start-Service "lfsvc" -ErrorAction SilentlyContinue
    Show-Message "Serviço de localização reativado." "Privacidade"
} "#8B5CF6"

Add-Button $flowPriv "Bloquear Coleta no Edge (básico)" {
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Edge" -Force | Out-Null
    Set-ItemProperty "HKCU:\Software\Policies\Microsoft\Edge" "PersonalizationReportingEnabled" 0
    Set-ItemProperty "HKCU:\Software\Policies\Microsoft\Edge" "SearchSuggestEnabled" 0
    Show-Message "Algumas coletas do Edge foram desativadas." "Privacidade"
} "#8B5CF6"

Add-Button $flowPriv "Limpar Histórico Explorer" {
    Clear-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -ErrorAction SilentlyContinue
    Show-Message "Histórico do Explorer limpo." "Privacidade"
} "#8B5CF6"

Add-Button $flowPriv "Exportar Senhas Wi-Fi" {
    $nets = (netsh wlan show profiles) -match "All User Profile"
    $out = "Senhas Wi-Fi:`r`n`r`n"
    foreach ($n in $nets) {
        $name = ($n -split ": ")[1]
        $key  = (netsh wlan show profile "$name" key=clear) -match "Key Content"
        $pass = if ($key) { ($key -split ": ")[1] } else { "(sem senha/oculta)" }
        $out += "$name -> $pass`r`n"
    }
    $file = Join-Path $Global:BasePath "wifi-senhas.txt"
    Set-Content $file $out -Encoding UTF8
    Show-Message "Exportado: $file" "Wi-Fi"
} "#8B5CF6"

Add-Button $flowPriv "Desativar Notificações do Security Center" {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" "ToastEnabled" 0
    Show-Message "Notificações do Security/Action Center reduzidas." "Privacidade"
} "#8B5CF6"

$tabPriv.Controls.Add($flowPriv)
$tab.Controls.Add($tabPriv)

# ===================================================
# ABA: UTILITÁRIOS (10+)
# ===================================================
$tabUtils = New-Object System.Windows.Forms.TabPage
$tabUtils.Text = "Utilitários"
$flowUtils = New-Flow

Add-Button $flowUtils "Localizar Arquivos >100MB (Top 100)" {
    $out = Join-Path $Global:BasePath "arquivos_grandes.txt"
    Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue |
      Where-Object { -not $_.PSIsContainer -and $_.Length -gt 100MB } |
      Sort-Object Length -Descending | Select-Object -First 100 |
      ForEach-Object { "{0:N2} MB  {1}" -f ($_.Length/1MB), $_.FullName } | Set-Content $out
    Show-Message "Relatório salvo em: $out" "Disco"
} "#F59E0B"

Add-Button $flowUtils "SFC + DISM (Reparar Sistema)" {
    Start-Process powershell -Verb RunAs -Wait -ArgumentList "dism /online /cleanup-image /restorehealth; sfc /scannow"
    Show-Message "DISM + SFC executados." "Sistema"
} "#F59E0B"

Add-Button $flowUtils "Forçar Verificação de Atualizações" {
    Start-Process "usoclient" "StartInteractiveScan"
    Show-Message "USOClient iniciado." "Windows Update"
} "#F59E0B"

Add-Button $flowUtils "Desinstalar OneDrive" {
    $p = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (-not (Test-Path $p)) { $p = "$env:SystemRoot\System32\OneDriveSetup.exe" }
    if (Test-Path $p) { Start-Process $p "/uninstall" -Verb RunAs -Wait; Show-Message "OneDrive desinstalado." "Sistema" }
    else { Show-Message "Instalador do OneDrive não encontrado." "Sistema" }
} "#F59E0B"

Add-Button $flowUtils "Testar Leitura/Escrita do Disco (100MB)" {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $tmp = "$env:TEMP\iotest.tmp"
    $data = New-Object byte[] (100MB)
    [IO.File]::WriteAllBytes($tmp,$data)
    $sw.Stop(); $w = "{0:N2}" -f (100/$sw.Elapsed.TotalSeconds)

    $sw.Restart(); [IO.File]::ReadAllBytes($tmp) | Out-Null
    $sw.Stop(); $r = "{0:N2}" -f (100/$sw.Elapsed.TotalSeconds)
    Remove-Item $tmp -Force
    Show-Message "Escrita: $w MB/s`nLeitura: $r MB/s" "Benchmark Disco"
} "#F59E0B"

Add-Button $flowUtils "Relatório do Sistema (msinfo32)" {
    Start-Process msinfo32.exe
} "#F59E0B"

Add-Button $flowUtils "Abrir Ferramentas: msconfig, cleanmgr, perfmon" {
    Start-Process msconfig
    Start-Process cleanmgr
    Start-Process perfmon
} "#F59E0B"

Add-Button $flowUtils "Backup Documentos -> Desktop" {
    $src = "$env:USERPROFILE\Documents"
    $dst = "$env:USERPROFILE\Desktop\Backup_Documentos_$(Get-Date -Format 'yyyyMMdd-HHmm')"
    Copy-Item $src -Destination $dst -Recurse -ErrorAction SilentlyContinue
    Show-Message "Backup concluído em: $dst" "Backup"
} "#F59E0B"

Add-Button $flowUtils "Monitor RAM/CPU (instantâneo)" {
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $mem = Get-CimInstance Win32_OperatingSystem
    $used = [math]::Round(($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory)/1MB,2)
    $tot  = [math]::Round($mem.TotalVisibleMemorySize/1MB,2)
    Show-Message "CPU em uso: $cpu%`nRAM: $used GB / $tot GB" "Monitor"
} "#F59E0B"

Add-Button $flowUtils "Criar Ponto de Restauração Agora" { Create-RestorePoint } "#F59E0B"

$tabUtils.Controls.Add($flowUtils)
$tab.Controls.Add($tabUtils)

# ===================================================
# ABA: INFORMAÇÕES
# ===================================================
$tabInfo = New-Object System.Windows.Forms.TabPage
$tabInfo.Text = "Informações"
$panelInfo = New-Object System.Windows.Forms.Panel
$panelInfo.Dock = "Fill"
$panelInfo.BackColor = "#2d2d2d"

$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Text = "Carregando informações..."
$lblInfo.Font = New-Object System.Drawing.Font("Consolas", 10)
$lblInfo.Location = New-Object System.Drawing.Point(20, 20)
$lblInfo.Size = New-Object System.Drawing.Size(900, 520)
$lblInfo.ForeColor = "#00ff00"

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Atualizar"
$btnRefresh.Location = New-Object System.Drawing.Point(20, 560)
$btnRefresh.Size = New-Object System.Drawing.Size(100, 32)
$btnRefresh.BackColor = "#059669"
$btnRefresh.ForeColor = "White"
$btnRefresh.FlatStyle = "Flat"
$btnRefresh.Add_Click({
    try {
        $cpu = (Get-CimInstance Win32_Processor)[0].Name
        $ram = "{0:N2} GB" -f ((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
        $os  = (Get-CimInstance Win32_OperatingSystem).Caption
        $disk = Get-PSDrive C | Select-Object Used, Free
        $free = "{0:N2} GB" -f ($disk.Free / 1GB)
        $used = "{0:N2} GB" -f ($disk.Used / 1GB)
        $gpu  = (Get-CimInstance Win32_VideoController | Select-Object -First 1).Name

        $lblInfo.Text = @"
Sistema: $os
CPU: $cpu
Memória RAM: $ram
GPU: $gpu
Disco C:
   Usado: $used
   Livre: $free
"@
    } catch { $lblInfo.Text = "Falha ao coletar informações: $($_.Exception.Message)" }
})

$panelInfo.Controls.Add($lblInfo)
$panelInfo.Controls.Add($btnRefresh)
$tabInfo.Controls.Add($panelInfo)
$tab.Controls.Add($tabInfo)

# ===================================================
# ABA: RESTAURAR / DESFAZER (ações úteis)
# ===================================================
$tabUndo = New-Object System.Windows.Forms.TabPage
$tabUndo.Text = "Restaurar/Desfazer"
$flowUndo = New-Flow

Add-Button $flowUndo "Reativar Hibernação" { powercfg /h on; Show-Message "Hibernação reativada." "Energia" } "#374151"
Add-Button $flowUndo "Reativar Serviços Padrão (básico)" {
    "WSearch","SysMain","DiagTrack","dmwappushservice" | ForEach-Object {
        try { Set-Service $_ -StartupType Manual -ErrorAction SilentlyContinue } catch {}
    }
    Show-Message "Alguns serviços voltaram para Manual." "Serviços"
} "#374151"

Add-Button $flowUndo "Restaurar Sugestões/Anúncios" {
    $cdm = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    "SystemPaneSuggestionsEnabled","SubscribedContent-338389Enabled","SubscribedContent-310093Enabled","SubscribedContent-338388Enabled" |
        ForEach-Object { Set-ItemProperty $cdm $_ 1 }
    Show-Message "Sugestões/Anúncios reativados." "Interface"
} "#374151"

Add-Button $flowUndo "Reativar Cortana" {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue
    Show-Message "Cortana reativada (pode exigir reinício)." "Privacidade"
} "#374151"

Add-Button $flowUndo "Reativar Telemetria (básico)" {
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 3 -ErrorAction SilentlyContinue
    Set-Service DiagTrack -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service dmwappushservice -StartupType Manual -ErrorAction SilentlyContinue
    Show-Message "Telemetria reativada (nível padrão)." "Privacidade"
} "#374151"

$tabUndo.Controls.Add($flowUndo)
$tab.Controls.Add($tabUndo)

# ===================================================
# Render
# ===================================================
$form.Controls.Add($tab)

$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = "Sair"
$btnExit.Size = New-Object System.Drawing.Size(90, 32)
$btnExit.Location = New-Object System.Drawing.Point($form.ClientSize.Width - 110, $form.ClientSize.Height - 50)
$btnExit.Anchor = "Bottom, Right"
$btnExit.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($btnExit)
$form.CancelButton = $btnExit

# Atualiza info ao abrir
$form.Add_Shown({ $btnRefresh.PerformClick() })

# Show
$form.ShowDialog() | Out-Null
