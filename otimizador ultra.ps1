# ===================================================
# OTIMIZADOR PC ULTRA - VERSÃO FINAL
# GUI Avançada com +15 Funções
# PowerShell + Windows Forms
# ===================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "Otimizador PC Ultra"
$form.Size = New-Object System.Drawing.Size(700, 600)
$form.StartPosition = "CenterScreen"
$form.BackColor = "#1e1e1e"
$form.ForeColor = "White"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.FormBorderStyle = "Sizable"
$form.MaximizeBox = $true

$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = "Fill"

# Função de mensagem
function Show-Message {
    param([string]$Text, [string]$Title = "Otimizador PC", [string]$Icon = "Information")
    [System.Windows.Forms.MessageBox]::Show($Text, $Title, "OK", $Icon)
}

# =================== ABA: LIMPEZA ===================
$tabClean = New-Object System.Windows.Forms.TabPage
$tabClean.Text = "Limpeza"
$flowClean = New-Object System.Windows.Forms.FlowLayoutPanel
$flowClean.Dock = "Fill"
$flowClean.AutoScroll = $true
$flowClean.BackColor = "#2d2d2d"

$cleanButtons = @(
    @{ Text = "Limpar Arquivos Temporários"; Action = {
        $paths = "$env:TEMP\*", "C:\Windows\Temp\*", "$env:LOCALAPPDATA\Temp\*", "$env:WINDIR\Prefetch\*"
        $total = 0
        foreach ($p in $paths) {
            $files = Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue
            if ($files) { $total += $files.Count }
            Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        }
        Show-Message "$total arquivos removidos com sucesso." "Limpeza"
    }}

    @{ Text = "Limpar Cache de Navegadores"; Action = {
        Remove-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
        Show-Message "Cache do Chrome e Edge limpo com sucesso." "Navegadores"
    }}

    @{ Text = "Limpar Logs do Windows"; Action = {
        wevtutil el | ForEach-Object { wevtutil cl $_ }
        Show-Message "Todos os logs do sistema foram limpos." "Logs"
    }}

    @{ Text = "Remover Aplicativos do Windows"; Action = {
        $apps = "*Xbox*", "*TikTok*", "*Solitaire*", "*Skype*", "*Teams*", "*Clipchamp*"
        $removed = 0
        foreach ($app in $apps) {
            Get-AppxPackage $app | Remove-AppxPackage -ErrorAction SilentlyContinue
            $removed++
        }
        Show-Message "$removed aplicativos removidos." "Aplicativos"
    }}
)

foreach ($btn in $cleanButtons) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $btn.Text
    $b.Size = New-Object System.Drawing.Size(300, 40)
    $b.BackColor = "#e74c3c"
    $b.ForeColor = "White"
    $b.FlatStyle = "Flat"
    $b.Cursor = "Hand"
    $b.Add_Click($btn.Action)
    $flowClean.Controls.Add($b)
}
$tabClean.Controls.Add($flowClean)
$tabControl.Controls.Add($tabClean)

# =================== ABA: OTIMIZAÇÃO ===================
$tabOptimize = New-Object System.Windows.Forms.TabPage
$tabOptimize.Text = "Otimização"
$flowOpt = New-Object System.Windows.Forms.FlowLayoutPanel
$flowOpt.Dock = "Fill"
$flowOpt.AutoScroll = $true
$flowOpt.BackColor = "#2d2d2d"

$optButtons = @(
    @{ Text = "Otimizar Disco (SSD/HDD)"; Action = {
        Optimize-Volume -DriveLetter C -Defrag -ErrorAction SilentlyContinue
        Show-Message "Disco otimizado com sucesso." "Otimização"
    }}

    @{ Text = "Desativar Efeitos Visuais"; Action = {
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value "0"
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "80"
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Value "2000"
        Show-Message "Efeitos visuais reduzidos para melhor desempenho." "Desempenho"
    }}

    @{ Text = "Desativar Hibernação"; Action = {
        powercfg /h off
        Show-Message "Hibernação desativada. Espaço liberado." "Energia"
    }}

    @{ Text = "Ativar Modo de Alto Desempenho"; Action = {
        powercfg /setactive SCHEME_MIN
        Show-Message "Modo de alto desempenho ativado." "Energia"
    }}
)

foreach ($btn in $optButtons) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $btn.Text
    $b.Size = New-Object System.Drawing.Size(300, 40)
    $b.BackColor = "#3498db"
    $b.ForeColor = "White"
    $b.FlatStyle = "Flat"
    $b.Cursor = "Hand"
    $b.Add_Click($btn.Action)
    $flowOpt.Controls.Add($b)
}
$tabOptimize.Controls.Add($flowOpt)
$tabControl.Controls.Add($tabOptimize)

# =================== ABA: PRIVACIDADE ===================
$tabPrivacy = New-Object System.Windows.Forms.TabPage
$tabPrivacy.Text = "Privacidade"
$flowPriv = New-Object System.Windows.Forms.FlowLayoutPanel
$flowPriv.Dock = "Fill"
$flowPriv.AutoScroll = $true
$flowPriv.BackColor = "#2d2d2d"

$privButtons = @(
    @{ Text = "Desativar Telemetria"; Action = {
        Set-Service "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
        Set-Service "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -ErrorAction SilentlyContinue
        Show-Message "Telemetria do Windows desativada." "Privacidade"
    }}

    @{ Text = "Limpar Histórico do Windows"; Action = {
        Clear-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -ErrorAction SilentlyContinue
        $shell = New-Object -ComObject Shell.Application
        $shell.NameSpace(0x10).Self.InvokeVerb("scanforbrokenshortcuts")
        Show-Message "Histórico e atalhos quebrados limpos." "Privacidade"
    }}

    @{ Text = "Exportar Senhas Wi-Fi"; Action = {
        $networks = (netsh wlan show profiles) -Match "All User Profile"
        $output = "Senhas Wi-Fi Salvas:`r`n`r`n"
        foreach ($net in $networks) {
            $name = ($net -split ": ")[1]
            $key = (netsh wlan show profile "$name" key=clear) -Match "Key Content"
            $pass = ($key -split ": ")[1]
            $output += "$name -> $pass`r`n"
        }
        $output += "`r`nOtimizador PC ULTRA - 2025"
        Set-Content -Path "$env:USERPROFILE\Desktop\Wi-Fi_Senhas.txt" -Value $output
        Show-Message "Senhas exportadas para Área de Trabalho\Wi-Fi_Senhas.txt" "Wi-Fi"
    }}
)

foreach ($btn in $privButtons) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $btn.Text
    $b.Size = New-Object System.Drawing.Size(300, 40)
    $b.BackColor = "#9b59b6"
    $b.ForeColor = "White"
    $b.FlatStyle = "Flat"
    $b.Cursor = "Hand"
    $b.Add_Click($btn.Action)
    $flowPriv.Controls.Add($b)
}
$tabPrivacy.Controls.Add($flowPriv)
$tabControl.Controls.Add($tabPrivacy)

# =================== ABA: INFORMAÇÕES ===================
$tabInfo = New-Object System.Windows.Forms.TabPage
$tabInfo.Text = "Informações do Sistema"
$panelInfo = New-Object System.Windows.Forms.Panel
$panelInfo.Dock = "Fill"
$panelInfo.BackColor = "#2d2d2d"

$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Text = "Carregando informações..."
$lblInfo.Font = New-Object System.Drawing.Font("Consolas", 10)
$lblInfo.Location = New-Object System.Drawing.Point(20, 20)
$lblInfo.Size = New-Object System.Drawing.Size(650, 500)
$lblInfo.ForeColor = "#00ff00"

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Atualizar"
$btnRefresh.Location = New-Object System.Drawing.Point(20, 520)
$btnRefresh.Size = New-Object System.Drawing.Size(100, 30)
$btnRefresh.BackColor = "#1abc9c"
$btnRefresh.ForeColor = "White"
$btnRefresh.FlatStyle = "Flat"
$btnRefresh.Add_Click({
    $cpu = (Get-WmiObject Win32_Processor).Name.Substring(0, 40) + "..."
    $ram = "{0:N2} GB" -f ((Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
    $os = (Get-WmiObject Win32_OperatingSystem).Caption
    $disk = Get-PSDrive C | Select-Object Used, Free
    $free = "{0:N2} GB" -f ($disk.Free / 1GB)
    $used = "{0:N2} GB" -f ($disk.Used / 1GB)
    
    $lblInfo.Text = "
Sistema: $os
CPU: $cpu
Memória RAM: $ram
Disco C:
   Usado: $used
   Livre: $free

Otimizador PC ULTRA - 2025
"
})

$panelInfo.Controls.Add($lblInfo)
$panelInfo.Controls.Add($btnRefresh)
$tabInfo.Controls.Add($panelInfo)
$tabControl.Controls.Add($tabInfo)

# =================== ABA: UTILITÁRIOS ===================
$tabUtils = New-Object System.Windows.Forms.TabPage
$tabUtils.Text = "Utilitários"
$flowUtils = New-Object System.Windows.Forms.FlowLayoutPanel
$flowUtils.Dock = "Fill"
$flowUtils.AutoScroll = $true
$flowUtils.BackColor = "#2d2d2d"

$utilsButtons = @(
    @{ Text = "Localizar Arquivos Grandes (>100MB)"; Action = {
        $files = Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 100MB -and !$_.PSIsContainer } | Select-Object FullName, @{Name="SizeMB";Expression={"{0:N2} MB" -f ($_.Length / 1MB)}} -First 50
        $files | Out-File "$env:USERPROFILE\Desktop\Arquivos_Grandes.txt"
        Show-Message "Arquivos grandes exportados para Área de Trabalho\Arquivos_Grandes.txt" "Análise de Disco"
    }}

    @{ Text = "Verificar Integridade (SFC/DISM)"; Action = {
        Start-Process powershell -ArgumentList "dism /online /cleanup-image /restorehealth; sfc /scannow" -Verb RunAs -Wait
        Show-Message "Verificação do sistema concluída." "Sistema"
    }}

    @{ Text = "Forçar Atualização do Windows"; Action = {
        Start-Process "usoclient StartInteractiveScan" -Verb RunAs
        Show-Message "Verificação de atualizações iniciada." "Windows Update"
    }}

    @{ Text = "Abrir Ferramentas do Sistema"; Action = {
        Start-Process "msconfig"
        Start-Process "cleanmgr"
        Start-Process "perfmon"
    }}
)

foreach ($btn in $utilsButtons) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $btn.Text
    $b.Size = New-Object System.Drawing.Size(300, 40)
    $b.BackColor = "#f39c12"
    $b.ForeColor = "White"
    $b.FlatStyle = "Flat"
    $b.Cursor = "Hand"
    $b.Add_Click($btn.Action)
    $flowUtils.Controls.Add($b)
}
$tabUtils.Controls.Add($flowUtils)
$tabControl.Controls.Add($tabUtils)

# Adicionar tudo ao formulário
$form.Controls.Add($tabControl)

# Botão de sair
$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = "Sair"
$btnExit.Size = New-Object System.Drawing.Size(80, 30)
$btnExit.Location = New-Object System.Drawing.Point($form.ClientSize.Width - 90, $form.ClientSize.Height - 50)
$btnExit.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$btnExit.Anchor = "Bottom, Right"
$form.Controls.Add($btnExit)

$form.CancelButton = $btnExit
$form.Add_Shown({ $btnRefresh.PerformClick() })
$form.ShowDialog() | Out-Null
