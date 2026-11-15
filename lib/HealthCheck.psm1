# Módulo del chequeo de salud del equipo (sysadmin-health-check).
# Todo es de SOLO LECTURA: ninguna función cambia la configuración del equipo.

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Registro de herramientas
# ---------------------------------------------------------------------------
function Get-ToolRegistry {
    <#
    .SYNOPSIS
        Devuelve la tabla de herramientas del kit (repo, script y argumentos).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    return @(
        # -Format Json,Html es el valor por defecto de Invoke-HardeningAudit (ambos formatos);
        # no se pasa -Format porque -File no admite listas separadas por coma en un [string[]].
        [pscustomobject]@{ Repo = 'windows-hardening-audit'; Script = 'Invoke-HardeningAudit.ps1'; Args = @('-Quiet'); ArgsQuick = @('-Quiet'); Formato = 'Hardening' }
        [pscustomobject]@{ Repo = 'cert-expiry-scanner'; Script = 'Get-CertExpiry.ps1'; Args = @(); ArgsQuick = @(); Formato = 'Cert' }
        [pscustomobject]@{ Repo = 'writable-path-audit'; Script = 'Invoke-WritablePathAudit.ps1'; Args = @(); ArgsQuick = @(); Formato = 'WritablePath' }
        [pscustomobject]@{ Repo = 'autostart-inventory'; Script = 'Get-AutostartInventory.ps1'; Args = @('-OnlySuspicious'); ArgsQuick = @('-OnlySuspicious'); Formato = 'Autostart' }
        [pscustomobject]@{ Repo = 'time-drift-check'; Script = 'Test-TimeDrift.ps1'; Args = @(); ArgsQuick = @(); Formato = 'Common' }
        [pscustomobject]@{ Repo = 'event-log-size-check'; Script = 'Test-EventLogSize.ps1'; Args = @(); ArgsQuick = @(); Formato = 'Common' }
        [pscustomobject]@{ Repo = 'stale-local-accounts'; Script = 'Test-LocalAccounts.ps1'; Args = @(); ArgsQuick = @(); Formato = 'Common' }
        [pscustomobject]@{ Repo = 'patch-status-report'; Script = 'Get-PatchStatus.ps1'; Args = @(); ArgsQuick = @('-SkipOnlineSearch'); Formato = 'Common' }
        [pscustomobject]@{ Repo = 'pc-inventory'; Script = 'Get-PcInventory.ps1'; Args = @('-NoSoftware'); ArgsQuick = @('-NoSoftware'); Formato = 'Common' }
    )
}

# ---------------------------------------------------------------------------
# Utilidades internas
# ---------------------------------------------------------------------------
function Read-JsonFile {
    <#
    .SYNOPSIS
        Lee un archivo JSON y lo convierte en objeto. Devuelve $null si falla.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return (ConvertFrom-Json -InputObject $raw)
    }
    catch {
        return $null
    }
}

function Get-ToolReportHtml {
    <#
    .SYNOPSIS
        Devuelve la ruta completa del informe HTML de una herramienta, si existe.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $report = Join-Path $Path 'report.html'
    if (Test-Path -LiteralPath $report -PathType Leaf) { return $report }
    $html = Get-ChildItem -LiteralPath $Path -Filter '*.html' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $html) { return $html.FullName }
    return $null
}

function Get-RelativePath {
    <#
    .SYNOPSIS
        Ruta relativa de -To respecto a -From (funciona en PS 5.1 y 7).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string]$To
    )
    $fromFull = [System.IO.Path]::GetFullPath($From)
    $toFull = [System.IO.Path]::GetFullPath($To)
    if (-not $fromFull.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $fromFull = $fromFull + [System.IO.Path]::DirectorySeparatorChar
    }
    $fromUri = New-Object System.Uri($fromFull)
    $toUri = New-Object System.Uri($toFull)
    $rel = $fromUri.MakeRelativeUri($toUri).ToString()
    # Ruta para un enlace HTML: siempre con '/', que funciona en cualquier navegador.
    return [System.Uri]::UnescapeDataString($rel).Replace('\', '/')
}

function ConvertTo-ArgumentText {
    <#
    .SYNOPSIS
        Entrecomilla un argumento si contiene espacios (para Start-Process).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )
    if ($Value -match '\s') {
        return '"' + $Value + '"'
    }
    return $Value
}

function Get-EquipoSummary {
    <#
    .SYNOPSIS
        Extrae la ficha del equipo (Resumen/Summary/Equipo) de la salida de pc-inventory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $jsonFile = Get-ChildItem -LiteralPath $Path -Filter '*.json' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' } | Select-Object -First 1
    if (-not $jsonFile) { return $null }
    $data = Read-JsonFile -Path $jsonFile.FullName
    if ($null -eq $data) { return $null }

    foreach ($propName in @('Resumen', 'Summary', 'Equipo')) {
        $node = $data.PSObject.Properties[$propName]
        if ($null -eq $node -or $null -eq $node.Value) { continue }
        $v = $node.Value
        if ($v -is [System.Collections.IDictionary]) { $v = [pscustomobject]$v }
        $tieneFicha = ($null -ne $v.PSObject.Properties['Fabricante']) -or
                      ($null -ne $v.PSObject.Properties['Modelo']) -or
                      ($null -ne $v.PSObject.Properties['SO']) -or
                      ($null -ne $v.PSObject.Properties['RAMGB'])
        if ($tieneFicha) {
            return [pscustomobject]@{
                Equipo     = [string]$v.Equipo
                Fabricante = [string]$v.Fabricante
                Modelo     = [string]$v.Modelo
                SO         = [string]$v.SO
                RAMGB      = [string]$v.RAMGB
            }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Normalizadores (reciben la carpeta de salida de cada herramienta)
# ---------------------------------------------------------------------------
function ConvertFrom-HardeningResult {
    <#
    .SYNOPSIS
        Normaliza hardening_*.json a filas comunes. OK->OK, AVISO->Aviso,
        FALLO->Alta y NO_COMPROBADO se omite.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $jsonFile = Get-ChildItem -LiteralPath $Path -Filter 'hardening_*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $jsonFile) { return @() }
    $data = Read-JsonFile -Path $jsonFile.FullName
    if ($null -eq $data -or $null -eq $data.Resultados) { return @() }

    $filas = foreach ($r in @($data.Resultados)) {
        if ($null -eq $r) { continue }
        $estado = switch ([string]$r.Estado) {
            'OK' { 'OK' }
            'AVISO' { 'Aviso' }
            'FALLO' { 'Alta' }
            default { $null }
        }
        if ($null -eq $estado) { continue }
        [pscustomobject]@{
            Comprobacion = ('{0} {1}' -f [string]$r.Id, [string]$r.Nombre).Trim()
            Estado       = $estado
            Detalle      = [string]$r.Detalle
            Solucion     = [string]$r.Recomendacion
        }
    }
    return @($filas)
}

function ConvertFrom-CertResult {
    <#
    .SYNOPSIS
        Normaliza certs.json. OK->OK, Aviso->Aviso, Critico/Caducado->Alta.
        Sin certificados devuelve una fila OK.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $jsonFile = Join-Path $Path 'certs.json'
    if (-not (Test-Path -LiteralPath $jsonFile -PathType Leaf)) { return @() }
    $raw = Get-Content -LiteralPath $jsonFile -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim() -eq '[]') {
        return @([pscustomobject]@{
                Comprobacion = 'Certificados'
                Estado       = 'OK'
                Detalle      = 'No hay certificados en los almacenes revisados.'
                Solucion     = ''
            })
    }
    $certs = ConvertFrom-Json -InputObject $raw
    $certs = @($certs)
    $filas = foreach ($c in $certs) {
        if ($null -eq $c) { continue }
        $estado = switch ([string]$c.Estado) {
            'OK' { 'OK' }
            'Aviso' { 'Aviso' }
            'Critico' { 'Alta' }
            'Caducado' { 'Alta' }
            default { 'Aviso' }
        }
        $solucion = ''
        if ($estado -eq 'Alta') { $solucion = 'Renovar el certificado de inmediato; puede interrumpir un servicio.' }
        elseif ($estado -eq 'Aviso') { $solucion = 'Planificar la renovación antes de que caduque.' }
        $detalle = 'Caduca el {0} ({1} días restantes). Usado por: {2}' -f [string]$c.Caduca, [string]$c.DiasRestantes, [string]$c.UsadoPor
        [pscustomobject]@{
            Comprobacion = 'Certificado {0}' -f [string]$c.Asunto
            Estado       = $estado
            Detalle      = $detalle
            Solucion     = $solucion
        }
    }
    return @($filas)
}

function ConvertFrom-WritablePathResult {
    <#
    .SYNOPSIS
        Normaliza findings.json. Alta->Alta, Media->Aviso. Vacío -> una fila OK.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $jsonFile = Join-Path $Path 'findings.json'
    if (-not (Test-Path -LiteralPath $jsonFile -PathType Leaf)) { return @() }
    $raw = Get-Content -LiteralPath $jsonFile -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim() -eq '[]') {
        return @([pscustomobject]@{
                Comprobacion = 'Rutas escribibles'
                Estado       = 'OK'
                Detalle      = 'No hay rutas escribibles peligrosas.'
                Solucion     = ''
            })
    }
    $findings = ConvertFrom-Json -InputObject $raw
    $findings = @($findings)
    $filas = foreach ($f in $findings) {
        if ($null -eq $f) { continue }
        $estado = 'Aviso'
        if ([string]$f.Severidad -eq 'Alta') { $estado = 'Alta' }
        $detalle = [string]$f.Detalle
        if (-not [string]::IsNullOrWhiteSpace([string]$f.Ruta)) {
            $detalle = ('{0} Ruta: {1}' -f $detalle, [string]$f.Ruta).Trim()
        }
        [pscustomobject]@{
            Comprobacion = 'Ruta escribible: {0}' -f [string]$f.Nombre
            Estado       = $estado
            Detalle      = $detalle
            Solucion     = [string]$f.Solucion
        }
    }
    return @($filas)
}

function ConvertFrom-AutostartResult {
    <#
    .SYNOPSIS
        Normaliza autostart.json. Cada entrada -> Aviso. Vacío -> una fila OK.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $jsonFile = Join-Path $Path 'autostart.json'
    if (-not (Test-Path -LiteralPath $jsonFile -PathType Leaf)) { return @() }
    $raw = Get-Content -LiteralPath $jsonFile -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim() -eq '[]') {
        return @([pscustomobject]@{
                Comprobacion = 'Arranque automático'
                Estado       = 'OK'
                Detalle      = 'No hay entradas de arranque sospechosas.'
                Solucion     = ''
            })
    }
    $entries = ConvertFrom-Json -InputObject $raw
    $entries = @($entries)
    $filas = foreach ($e in $entries) {
        if ($null -eq $e) { continue }
        $partes = @()
        if (-not [string]::IsNullOrWhiteSpace([string]$e.Origen)) { $partes += 'Origen: {0}' -f [string]$e.Origen }
        if (-not [string]::IsNullOrWhiteSpace([string]$e.Comando)) { $partes += 'Comando: {0}' -f [string]$e.Comando }
        if (-not [string]::IsNullOrWhiteSpace([string]$e.Marcas)) { $partes += 'Marcas: {0}' -f [string]$e.Marcas }
        [pscustomobject]@{
            Comprobacion = 'Arranque: {0}' -f [string]$e.Nombre
            Estado       = 'Aviso'
            Detalle      = ($partes -join ' · ')
            Solucion     = 'Revisar la entrada antes de deshabilitarla.'
        }
    }
    return @($filas)
}

function ConvertFrom-CommonResult {
    <#
    .SYNOPSIS
        Normaliza el formato común: objeto con Hallazgos (o Avisos) o array directo.
        Estado desconocido -> Aviso.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $jsonFile = Get-ChildItem -LiteralPath $Path -Filter '*.json' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '.*' } | Select-Object -First 1
    if (-not $jsonFile) { return @() }
    $data = Read-JsonFile -Path $jsonFile.FullName
    if ($null -eq $data) { return @() }

    $findings = @()
    if ($data -is [System.Management.Automation.PSCustomObject]) {
        $hallazgos = $data.PSObject.Properties['Hallazgos']
        $avisos = $data.PSObject.Properties['Avisos']
        $comprobacion = $data.PSObject.Properties['Comprobacion']
        if ($null -ne $hallazgos -and $null -ne $hallazgos.Value) { $findings = @($hallazgos.Value) }
        elseif ($null -ne $avisos -and $null -ne $avisos.Value) { $findings = @($avisos.Value) }
        elseif ($null -ne $comprobacion -and $null -ne $comprobacion.Value) { $findings = @($data) }
    }
    else {
        $findings = @($data)
    }

    $filas = foreach ($f in $findings) {
        if ($null -eq $f) { continue }
        $estado = switch ([string]$f.Estado) {
            'OK' { 'OK' }
            'Aviso' { 'Aviso' }
            'Alta' { 'Alta' }
            default { 'Aviso' }
        }
        $detalle = [string]$f.Detalle
        if ([string]::IsNullOrWhiteSpace($detalle)) { $detalle = [string]$f.Valor }
        $solucion = [string]$f.Solucion
        if ([string]::IsNullOrWhiteSpace($solucion)) { $solucion = [string]$f.Recomendado }
        [pscustomobject]@{
            Comprobacion = [string]$f.Comprobacion
            Estado       = $estado
            Detalle      = $detalle
            Solucion     = $solucion
        }
    }
    return @($filas)
}

# ---------------------------------------------------------------------------
# Instalación
# ---------------------------------------------------------------------------
function Install-HealthCheckTool {
    <#
    .SYNOPSIS
        Descarga o actualiza una herramienta desde GitHub a <ToolsPath>/<repo>.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$ToolsPath
    )

    # TLS 1.2 para Windows PowerShell 5.1
    try {
        if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
    }
    catch { Write-Verbose "No se pudo ajustar TLS 1.2: $($_.Exception.Message)" }

    $url = "https://github.com/samuelmartindelgado/$Repo/archive/refs/heads/main.zip"
    $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) ("{0}-{1}.zip" -f $Repo, [guid]::NewGuid().ToString('N'))
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("{0}-{1}" -f $Repo, [guid]::NewGuid().ToString('N'))

    try {
        Invoke-WebRequest -Uri $url -OutFile $tmpZip -UseBasicParsing
        Expand-Archive -Path $tmpZip -DestinationPath $tmpDir -Force
        $inner = Get-ChildItem -Path $tmpDir -Directory | Select-Object -First 1
        if (-not $inner) { throw "El archivo descargado de '$Repo' no contiene ninguna carpeta." }

        $dest = Join-Path $ToolsPath $Repo
        $marca = '.instalado-por-health-check'
        if (Test-Path -LiteralPath $dest) {
            # Solo se sustituye una carpeta que haya descargado el propio kit: si
            # -ToolsPath apunta a copias propias (por ejemplo un git clone con
            # cambios), no se borran.
            if (-not (Test-Path -LiteralPath (Join-Path $dest $marca))) {
                throw "La carpeta '$dest' ya existe y no la instaló este kit; no se sobrescribe. Usa otra -ToolsPath o bórrala tú."
            }
            Remove-Item -LiteralPath $dest -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $ToolsPath | Out-Null
        Move-Item -LiteralPath $inner.FullName -Destination $dest
        Set-Content -LiteralPath (Join-Path $dest $marca) -Value ("Descargado de {0} el {1:yyyy-MM-dd HH:mm}" -f $url, (Get-Date)) -Encoding UTF8
        return $dest
    }
    catch {
        throw "No se pudo instalar '$Repo': $($_.Exception.Message)"
    }
    finally {
        if (Test-Path -LiteralPath $tmpZip) { Remove-Item -LiteralPath $tmpZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
# Ejecución de una herramienta en un proceso hijo del mismo motor
# ---------------------------------------------------------------------------
function Invoke-HealthCheckTool {
    <#
    .SYNOPSIS
        Ejecuta una herramienta en un proceso hijo, con tiempo máximo, y normaliza su salida.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Tool,
        [Parameter(Mandatory)][string]$ToolsPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$Quick,
        [double]$TimeoutMinutes = 10
    )

    $repo = [string]$Tool.Repo
    $scriptName = [string]$Tool.Script
    $formato = [string]$Tool.Formato
    $outDir = Join-Path $OutputPath $repo

    $scriptPath = Join-Path $ToolsPath (Join-Path $repo $scriptName)
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $row = [pscustomobject]@{
            Herramienta  = $repo
            Comprobacion = 'No instalada (usa -Install)'
            Estado       = 'Aviso'
            Detalle      = "No se encontró $scriptName en '$scriptPath'"
            Solucion     = 'Ejecute .\Invoke-HealthCheck.ps1 -Install'
            Informe      = $null
        }
        return [pscustomobject]@{
            Repo          = $repo
            Instalada     = $false
            Estado        = 'No instalada'
            ExitCode      = $null
            Seconds       = 0
            Stderr        = ''
            Rows          = @($row)
            Informe       = $null
            EquipoSummary = $null
        }
    }

    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath, '-OutputPath', $outDir)
    if ($Quick) { $argsList += @($Tool.ArgsQuick) }
    else { $argsList += @($Tool.Args) }

    $engine = (Get-Process -Id $PID).Path
    $argString = ($argsList | ForEach-Object { ConvertTo-ArgumentText -Value ([string]$_) }) -join ' '

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $engine
    $psi.Arguments = $argString
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    $exitCode = $null
    $stderrText = ''

    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    }
    catch {
        $sw.Stop()
        return [pscustomobject]@{
            Repo          = $repo
            Instalada     = $true
            Estado        = 'Error'
            ExitCode      = $null
            Seconds       = [math]::Round($sw.Elapsed.TotalSeconds, 2)
            Stderr        = $_.Exception.Message
            Rows          = @()
            Informe       = $null
            EquipoSummary = $null
        }
    }

    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    $timeoutMs = [int]($TimeoutMinutes * 60000)
    $finished = $proc.WaitForExit($timeoutMs)
    if (-not $finished) {
        $timedOut = $true
        try { $proc.Kill() } catch { Write-Verbose "No se pudo terminar el proceso: $($_.Exception.Message)" }
        $proc.WaitForExit()
    }
    $sw.Stop()

    try { $exitCode = $proc.ExitCode } catch { $exitCode = $null }
    try { $stderrText = $stderrTask.Result } catch { $stderrText = '' }
    try { $null = $stdoutTask.Result } catch { }

    if ($timedOut) { $estado = 'Timeout' }
    elseif ($exitCode -in @(0, 1, 2)) { $estado = 'OK' }
    else { $estado = 'Error' }

    $rows = @()
    switch ($formato) {
        'Hardening' { $rows = @(ConvertFrom-HardeningResult -Path $outDir) }
        'Cert' { $rows = @(ConvertFrom-CertResult -Path $outDir) }
        'WritablePath' { $rows = @(ConvertFrom-WritablePathResult -Path $outDir) }
        'Autostart' { $rows = @(ConvertFrom-AutostartResult -Path $outDir) }
        'Common' { $rows = @(ConvertFrom-CommonResult -Path $outDir) }
    }

    $informeRel = $null
    $htmlFull = Get-ToolReportHtml -Path $outDir
    if ($null -ne $htmlFull) {
        $informeRel = Get-RelativePath -From $OutputPath -To $htmlFull
    }

    $rows = @($rows | ForEach-Object {
            [pscustomobject]@{
                Herramienta  = $repo
                Comprobacion = $_.Comprobacion
                Estado       = $_.Estado
                Detalle      = $_.Detalle
                Solucion     = $_.Solucion
                Informe      = $informeRel
            }
        })

    $equipoSummary = $null
    if ($formato -eq 'Common') { $equipoSummary = Get-EquipoSummary -Path $outDir }

    return [pscustomobject]@{
        Repo          = $repo
        Instalada     = $true
        Estado        = $estado
        ExitCode      = $exitCode
        Seconds       = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        Stderr        = $stderrText.Trim()
        Rows          = $rows
        Informe       = $informeRel
        EquipoSummary = $equipoSummary
    }
}

# ---------------------------------------------------------------------------
# Generación del informe HTML
# ---------------------------------------------------------------------------
function ConvertTo-HtmlText {
    <#
    .SYNOPSIS
        Escapa un texto para incrustarlo en HTML.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()][AllowNull()][object]$Text
    )
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function New-HealthCheckHtml {
    <#
    .SYNOPSIS
        Genera el informe HTML autónomo (CSS inline, sin JS externo, modo oscuro).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Summary -is [System.Collections.IDictionary]) { $Summary = [pscustomobject]$Summary }

    $equipo = [string]$Summary.Equipo
    $modelo = [string]$Summary.Modelo
    $so = [string]$Summary.SO
    $fecha = [string]$Summary.Fecha
    $tools = @()
    if ($null -ne $Summary.PSObject.Properties['Tools']) { $tools = @($Summary.Tools) }

    $alta = @($Rows | Where-Object { $_.Estado -eq 'Alta' }).Count
    $aviso = @($Rows | Where-Object { $_.Estado -eq 'Aviso' }).Count
    $ok = @($Rows | Where-Object { $_.Estado -eq 'OK' }).Count

    $semaforo = 'verde'
    if ($alta -gt 0) { $semaforo = 'rojo' }
    elseif ($aviso -gt 0) { $semaforo = 'ambar' }

    $equipoEnc = ConvertTo-HtmlText -Text $equipo
    $modeloEnc = ConvertTo-HtmlText -Text $modelo
    $soEnc = ConvertTo-HtmlText -Text $so
    $fechaEnc = ConvertTo-HtmlText -Text $fecha
    $metaLine = 'Equipo <strong>' + $equipoEnc + '</strong>'
    if ($modeloEnc -ne '') { $metaLine += ' &middot; ' + $modeloEnc }
    if ($soEnc -ne '') { $metaLine += ' &middot; ' + $soEnc }
    $metaLine += ' &middot; ' + $fechaEnc

    # Tarjetas por herramienta
    $cards = New-Object System.Text.StringBuilder
    foreach ($t in $tools) {
        $tNombre = ConvertTo-HtmlText -Text ([string]$t.Herramienta)
        $tEstado = ConvertTo-HtmlText -Text ([string]$t.Estado)
        $tAlta = ConvertTo-HtmlText -Text ([string]$t.Alta)
        $tAviso = ConvertTo-HtmlText -Text ([string]$t.Aviso)
        $tOk = ConvertTo-HtmlText -Text ([string]$t.OK)
        $tSeg = ConvertTo-HtmlText -Text ([string]$t.Seconds)
        $enlace = ''
        if (-not [string]::IsNullOrWhiteSpace([string]$t.Informe)) {
            $href = ConvertTo-HtmlText -Text ([string]$t.Informe)
            $enlace = '<a class="informe" href="' + $href + '">Ver informe</a>'
        }
        [void]$cards.AppendLine('<div class="tool">')
        [void]$cards.AppendLine('<div class="tool-head"><span class="tool-name">' + $tNombre + '</span><span class="tool-state">' + $tEstado + '</span></div>')
        [void]$cards.AppendLine('<div class="tool-cuenta"><span class="alta">' + $tAlta + ' Alta</span> <span class="aviso">' + $tAviso + ' Aviso</span> <span class="ok">' + $tOk + ' OK</span> <span class="sec">' + $tSeg + ' s</span></div>')
        if ($enlace -ne '') { [void]$cards.AppendLine($enlace) }
        [void]$cards.AppendLine('</div>')
    }

    # Tabla "Qué hay que mirar" (Alta primero, luego Aviso)
    $aMirar = @($Rows | Where-Object { $_.Estado -in @('Alta', 'Aviso') })
    $aMirar = @($aMirar | Sort-Object @{ Expression = { if ($_.Estado -eq 'Alta') { 0 } else { 1 } } })
    $tabla = New-Object System.Text.StringBuilder
    foreach ($r in $aMirar) {
        $clase = 'alta'
        if ($r.Estado -eq 'Aviso') { $clase = 'aviso' }
        [void]$tabla.AppendLine('<tr class="' + $clase + '">')
        [void]$tabla.AppendLine('<td>' + (ConvertTo-HtmlText -Text $r.Herramienta) + '</td>')
        [void]$tabla.AppendLine('<td>' + (ConvertTo-HtmlText -Text $r.Comprobacion) + '</td>')
        [void]$tabla.AppendLine('<td>' + (ConvertTo-HtmlText -Text $r.Detalle) + '</td>')
        [void]$tabla.AppendLine('<td>' + (ConvertTo-HtmlText -Text $r.Solucion) + '</td>')
        [void]$tabla.AppendLine('</tr>')
    }

    # Filas OK dentro de <details>
    $okRows = New-Object System.Text.StringBuilder
    $filasOk = @($Rows | Where-Object { $_.Estado -eq 'OK' })
    foreach ($r in $filasOk) {
        [void]$okRows.AppendLine('<tr class="ok">')
        [void]$okRows.AppendLine('<td>' + (ConvertTo-HtmlText -Text $r.Herramienta) + '</td>')
        [void]$okRows.AppendLine('<td>' + (ConvertTo-HtmlText -Text $r.Comprobacion) + '</td>')
        [void]$okRows.AppendLine('<td>' + (ConvertTo-HtmlText -Text $r.Detalle) + '</td>')
        [void]$okRows.AppendLine('</tr>')
    }

    $css = @'
:root{color-scheme:light dark;--fondo:#f4f6f9;--texto:#1b2430;--suave:#5b6673;--tarjeta:#fff;--borde:#d8dee7;--ok:#1a7f37;--aviso:#9a6700;--alta:#c0392b;--rojo:#c0392b;--ambar:#d98300;--verde:#1a7f37;--filaAviso:#fff6e5;--filaAlta:#fdecea}
@media (prefers-color-scheme: dark){:root{--fondo:#12161c;--texto:#e6ebf1;--suave:#9aa7b4;--tarjeta:#1a2029;--borde:#2a323d;--ok:#4ac26b;--aviso:#e3b341;--alta:#ff7b72;--rojo:#ff7b72;--ambar:#e3b341;--verde:#4ac26b;--filaAviso:#3a2f1b;--filaAlta:#3d2222}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1rem;background:var(--fondo);color:var(--texto);font:15px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
main{max-width:1100px;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.15rem;margin:1.6rem 0 .6rem}
.meta{color:var(--suave);margin:0 0 1.5rem;font-size:.92rem}
.semaforo{display:flex;align-items:center;gap:1rem;padding:1.1rem 1.3rem;border:1px solid var(--borde);border-radius:12px;background:var(--tarjeta);margin-bottom:1.5rem}
.luz{width:3.4rem;height:3.4rem;border-radius:50%;border:4px solid rgba(0,0,0,.12);flex:0 0 auto}
.luz.rojo{background:var(--rojo)}
.luz.ambar{background:var(--ambar)}
.luz.verde{background:var(--verde)}
.recuentos{display:flex;gap:1.2rem;flex-wrap:wrap}
.recuentos span{font-weight:600}
.recuentos .alta{color:var(--alta)}
.recuentos .aviso{color:var(--aviso)}
.recuentos .ok{color:var(--ok)}
.tools{display:flex;gap:.8rem;flex-wrap:wrap;margin-bottom:.5rem}
.tool{background:var(--tarjeta);border:1px solid var(--borde);border-radius:10px;padding:.7rem .9rem;min-width:200px}
.tool-head{display:flex;justify-content:space-between;gap:1rem}
.tool-name{font-weight:600}
.tool-state{color:var(--suave);font-size:.85rem}
.tool-cuenta{font-size:.85rem;margin-top:.25rem}
.tool-cuenta .alta{color:var(--alta);font-weight:600}
.tool-cuenta .aviso{color:var(--aviso);font-weight:600}
.tool-cuenta .ok{color:var(--ok);font-weight:600}
.tool-cuenta .sec{color:var(--suave)}
.informe{display:inline-block;margin-top:.35rem;font-size:.85rem}
.tabla{overflow-x:auto;border:1px solid var(--borde);border-radius:10px;background:var(--tarjeta)}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{padding:.6rem .7rem;text-align:left;vertical-align:top;border-bottom:1px solid var(--borde)}
thead th{background:rgba(127,127,127,.12);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--suave)}
tbody tr:last-child td{border-bottom:0}
tbody tr.alta td{background:var(--filaAlta)}
tbody tr.aviso td{background:var(--filaAviso)}
details{margin-top:.6rem}
summary{cursor:pointer;color:var(--suave)}
footer{margin-top:2rem;color:var(--suave);font-size:.82rem}
'@

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chequeo de salud - $equipoEnc</title>
<style>
$css
</style>
</head>
<body>
<main>
<h1>Chequeo de salud del equipo</h1>
<p class="meta">$metaLine</p>

<div class="semaforo">
<div class="luz $semaforo"></div>
<div class="recuentos"><span class="alta">$alta Alta</span><span class="aviso">$aviso Aviso</span><span class="ok">$ok OK</span></div>
</div>

<h2>Herramientas</h2>
<div class="tools">
$($cards.ToString())
</div>

<h2>Qué hay que mirar</h2>
<div class="tabla">
<table>
<thead><tr><th>Herramienta</th><th>Comprobación</th><th>Detalle</th><th>Solución</th></tr></thead>
<tbody>
$($tabla.ToString())
</tbody>
</table>
</div>

<details>
<summary>Comprobaciones correctas ($ok)</summary>
<div class="tabla">
<table>
<thead><tr><th>Herramienta</th><th>Comprobación</th><th>Detalle</th></tr></thead>
<tbody>
$($okRows.ToString())
</tbody>
</table>
</div>
</details>

<footer>Generado por Invoke-HealthCheck.ps1 &middot; Solo lectura: no se ha modificado nada del equipo.</footer>
</main>
</body>
</html>
"@

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($Path, $html, (New-Object System.Text.UTF8Encoding($false)))
}

Export-ModuleMember -Function Get-ToolRegistry, Install-HealthCheckTool, Invoke-HealthCheckTool, `
    ConvertFrom-HardeningResult, ConvertFrom-CertResult, ConvertFrom-WritablePathResult, `
    ConvertFrom-AutostartResult, ConvertFrom-CommonResult, New-HealthCheckHtml, Get-EquipoSummary
