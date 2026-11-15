#Requires -Version 5.1
<#
.SYNOPSIS
    Chequeo de salud de un equipo Windows en un solo comando (solo lectura).

.DESCRIPTION
    Ejecuta las herramientas del kit sobre el equipo y genera un informe HTML
    único tipo semáforo. Ni este script ni las herramientas cambian nada del
    equipo: todo es de solo lectura.

.PARAMETER ToolsPath
    Carpeta donde están (o se instalan) las herramientas. Por defecto ./tools.

.PARAMETER OutputPath
    Carpeta donde se escriben los informes. Por defecto ./salida.

.PARAMETER Tool
    Subconjunto de herramientas a ejecutar, por nombre de repositorio.

.PARAMETER Install
    Descarga o actualiza cada herramienta desde GitHub.

.PARAMETER Quick
    Modo rápido: usa los argumentos rápidos de cada herramienta (p. ej. no
    consulta Windows Update en el estado de parches).

.PARAMETER TimeoutMinutes
    Tiempo máximo por herramienta, en minutos. Por defecto 10.

.EXAMPLE
    .\Invoke-HealthCheck.ps1 -Install
#>
[CmdletBinding()]
param(
    [string]$ToolsPath = './tools',

    [string]$OutputPath = './salida',

    [string[]]$Tool = @(),

    [switch]$Install,

    [switch]$Quick,

    [double]$TimeoutMinutes = 10
)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'lib\HealthCheck.psm1'
Import-Module -Name $modulePath -Force -ErrorAction Stop

$inicio = Get-Date

$toolsFull = [System.IO.Path]::GetFullPath($ToolsPath)
$outputFull = [System.IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Force -Path $outputFull | Out-Null

# Selección de herramientas
$registry = @(Get-ToolRegistry)
if ($Tool.Count -gt 0) {
    $nombres = @()
    foreach ($item in $Tool) {
        foreach ($parte in ([string]$item -split ',')) {
            $nombre = $parte.Trim()
            if ($nombre) { $nombres += $nombre }
        }
    }
    $registry = @($registry | Where-Object { $nombres -contains $_.Repo })
    if ($registry.Count -eq 0) {
        Write-Warning 'Ninguna de las herramientas indicadas con -Tool existe en el kit.'
    }
}

# Instalación opcional
if ($Install) {
    foreach ($t in $registry) {
        Write-Verbose "Instalando $($t.Repo)..."
        try {
            $null = Install-HealthCheckTool -Repo $t.Repo -ToolsPath $toolsFull
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
}

# Ejecución de cada herramienta en un proceso hijo del mismo motor
$resultados = @()
foreach ($t in $registry) {
    Write-Verbose "Ejecutando $($t.Repo)..."
    $r = Invoke-HealthCheckTool -Tool $t -ToolsPath $toolsFull -OutputPath $outputFull -Quick:$Quick.IsPresent -TimeoutMinutes $TimeoutMinutes
    $resultados += $r
}

# Recopilación de filas normalizadas
$filas = @()
foreach ($r in $resultados) {
    foreach ($fila in @($r.Rows)) {
        $filas += $fila
    }
}

# Cabecera del informe: primero de pc-inventory, si no de CIM
$equipo = $env:COMPUTERNAME
$fabricante = ''
$modelo = ''
$so = ''
$ramGB = ''
foreach ($r in $resultados) {
    if ($null -ne $r.EquipoSummary -and $null -ne $r.EquipoSummary.PSObject) {
        $equipo = [string]$r.EquipoSummary.Equipo
        $fabricante = [string]$r.EquipoSummary.Fabricante
        $modelo = [string]$r.EquipoSummary.Modelo
        $so = [string]$r.EquipoSummary.SO
        $ramGB = [string]$r.EquipoSummary.RAMGB
        break
    }
}
if ([string]::IsNullOrWhiteSpace($modelo) -or [string]::IsNullOrWhiteSpace($so)) {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($fabricante)) { $fabricante = [string]$cs.Manufacturer }
        if ([string]::IsNullOrWhiteSpace($modelo)) { $modelo = [string]$cs.Model }
        if ([string]::IsNullOrWhiteSpace($ramGB) -and $null -ne $cs.TotalPhysicalMemory) {
            $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB)
        }
    }
    catch { Write-Verbose "No se pudo leer Win32_ComputerSystem: $($_.Exception.Message)" }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($so)) { $so = [string]$os.Caption }
    }
    catch { Write-Verbose "No se pudo leer Win32_OperatingSystem: $($_.Exception.Message)" }
}

# Resumen por herramienta
$resumenTools = @($resultados | ForEach-Object {
        $a = @($_.Rows | Where-Object { $_.Estado -eq 'Alta' }).Count
        $v = @($_.Rows | Where-Object { $_.Estado -eq 'Aviso' }).Count
        $k = @($_.Rows | Where-Object { $_.Estado -eq 'OK' }).Count
        [pscustomobject]@{
            Herramienta = $_.Repo
            Alta        = $a
            Aviso       = $v
            OK          = $k
            Estado      = $_.Estado
            ExitCode    = $_.ExitCode
            Seconds     = $_.Seconds
            Stderr      = $_.Stderr
            Informe     = $_.Informe
        }
    })

# Conteos globales
$alta = @($filas | Where-Object { $_.Estado -eq 'Alta' }).Count
$aviso = @($filas | Where-Object { $_.Estado -eq 'Aviso' }).Count
$ok = @($filas | Where-Object { $_.Estado -eq 'OK' }).Count

# health-check.json
$jsonObj = [pscustomobject]@{
    Equipo      = $equipo
    Fecha       = $inicio.ToString('o')
    Version     = '1.0.0'
    Resumen     = [pscustomobject]@{ Alta = $alta; Aviso = $aviso; OK = $ok }
    Herramientas = $resumenTools
    Filas       = @($filas | Select-Object -Property Herramienta, Comprobacion, Estado, Detalle, Solucion, Informe)
}
$jsonPath = Join-Path $outputFull 'health-check.json'
[System.IO.File]::WriteAllText($jsonPath, ($jsonObj | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))

# health-check.html
$summary = [pscustomobject]@{
    Equipo = $equipo
    Modelo = $modelo
    SO     = $so
    Fecha  = $inicio.ToString('yyyy-MM-dd HH:mm')
    Tools  = $resumenTools
}
$htmlPath = Join-Path $outputFull 'health-check.html'
New-HealthCheckHtml -Rows @($filas) -Summary $summary -Path $htmlPath

# Resumen en consola (único punto con Write-Host)
$tabla = $resumenTools | Select-Object Herramienta, Alta, Aviso, OK,
    @{ Name = 'Estado de ejecución'; Expression = { $_.Estado } },
    @{ Name = 'Segundos'; Expression = { $_.Seconds } }

Write-Host ''
Write-Host 'Chequeo de salud del equipo' -ForegroundColor Cyan
Write-Host ('Equipo: {0}   Fecha: {1}' -f $equipo, $inicio.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ''
$tabla | Format-Table -AutoSize | Out-String -Width 240 | Write-Host

$color = 'Green'
$texto = 'Todo correcto'
if ($alta -gt 0) { $color = 'Red'; $texto = 'Hay problemas graves (Alta)' }
elseif ($aviso -gt 0) { $color = 'Yellow'; $texto = 'Hay avisos que revisar' }
Write-Host ('Resultado: {0} Alta, {1} Aviso, {2} OK - {3}' -f $alta, $aviso, $ok, $texto) -ForegroundColor $color
Write-Host ('Informe: {0}' -f $htmlPath)
Write-Host ''

if ($alta -gt 0) { exit 2 }
if ($aviso -gt 0) { exit 1 }
exit 0
