#Requires -Version 5.1
# Pruebas Pester 5 del chequeo de salud del equipo.

BeforeAll {
    $raiz = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    Import-Module -Name (Join-Path $raiz 'lib\HealthCheck.psm1') -Force
    $fixtures = Join-Path $PSScriptRoot 'fixtures'
}

Describe 'Get-ToolRegistry' {
    It 'contiene las 9 herramientas del kit' {
        @(Get-ToolRegistry).Count | Should -Be 9
    }

    It 'cada herramienta declara Repo, Script, Args y ArgsQuick' {
        foreach ($x in @(Get-ToolRegistry)) {
            $x.Repo | Should -Not -BeNullOrEmpty
            $x.Script | Should -Not -BeNullOrEmpty
            ($null -eq $x.Args) | Should -Be $false
            ($null -eq $x.ArgsQuick) | Should -Be $false
        }
    }
}

Describe 'ConvertFrom-HardeningResult' {
    It 'mapea OK, AVISO y FALLO y omite NO_COMPROBADO' {
        $rows = @(ConvertFrom-HardeningResult -Path (Join-Path $fixtures 'windows-hardening-audit'))
        $rows.Count | Should -Be 3
        @($rows | Where-Object { $_.Estado -eq 'OK' }).Count | Should -Be 1
        @($rows | Where-Object { $_.Estado -eq 'Aviso' }).Count | Should -Be 1
        @($rows | Where-Object { $_.Estado -eq 'Alta' }).Count | Should -Be 1
    }

    It 'usa "Id Nombre" como Comprobacion y Recomendacion como Solucion' {
        $rows = @(ConvertFrom-HardeningResult -Path (Join-Path $fixtures 'windows-hardening-audit'))
        $rows[0].Comprobacion | Should -Match 'RED-01'
        $rows[0].Solucion | Should -Be 'Mantener desactivado.'
    }
}

Describe 'ConvertFrom-CertResult' {
    It 'mapea Critico y Caducado a Alta, Aviso a Aviso y OK a OK' {
        $rows = @(ConvertFrom-CertResult -Path (Join-Path $fixtures 'cert-expiry-scanner'))
        @($rows | Where-Object { $_.Estado -eq 'Alta' }).Count | Should -Be 2
        @($rows | Where-Object { $_.Estado -eq 'Aviso' }).Count | Should -Be 1
        @($rows | Where-Object { $_.Estado -eq 'OK' }).Count | Should -Be 1
    }

    It 'sin certificados devuelve una fila OK' {
        $dir = Join-Path $TestDrive 'cert-empty'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'certs.json') -Value '[]' -Encoding UTF8
        $rows = @(ConvertFrom-CertResult -Path $dir)
        $rows.Count | Should -Be 1
        $rows[0].Estado | Should -Be 'OK'
    }
}

Describe 'ConvertFrom-WritablePathResult' {
    It 'mapea Alta a Alta y Media a Aviso' {
        $rows = @(ConvertFrom-WritablePathResult -Path (Join-Path $fixtures 'writable-path-audit'))
        @($rows | Where-Object { $_.Estado -eq 'Alta' }).Count | Should -Be 1
        @($rows | Where-Object { $_.Estado -eq 'Aviso' }).Count | Should -Be 1
    }

    It 'sin hallazgos devuelve una fila OK' {
        $dir = Join-Path $TestDrive 'writable-empty'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'findings.json') -Value '[]' -Encoding UTF8
        $rows = @(ConvertFrom-WritablePathResult -Path $dir)
        $rows.Count | Should -Be 1
        $rows[0].Estado | Should -Be 'OK'
        $rows[0].Detalle | Should -Match 'No hay rutas escribibles'
    }
}

Describe 'ConvertFrom-AutostartResult' {
    It 'cada entrada marcada es un Aviso' {
        $rows = @(ConvertFrom-AutostartResult -Path (Join-Path $fixtures 'autostart-inventory'))
        $rows.Count | Should -Be 2
        @($rows | Where-Object { $_.Estado -eq 'Aviso' }).Count | Should -Be 2
        $rows[0].Comprobacion | Should -Match 'Arranque:'
    }

    It 'sin entradas devuelve una fila OK' {
        $dir = Join-Path $TestDrive 'autostart-empty'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'autostart.json') -Value '[]' -Encoding UTF8
        $rows = @(ConvertFrom-AutostartResult -Path $dir)
        $rows.Count | Should -Be 1
        $rows[0].Estado | Should -Be 'OK'
    }
}

Describe 'ConvertFrom-CommonResult' {
    It 'lee un objeto con Hallazgos' {
        $rows = @(ConvertFrom-CommonResult -Path (Join-Path $fixtures 'time-drift-check'))
        $rows.Count | Should -Be 5
        @($rows | Where-Object { $_.Estado -eq 'Alta' }).Count | Should -Be 1
        @($rows | Where-Object { $_.Estado -eq 'Aviso' }).Count | Should -Be 1
        @($rows | Where-Object { $_.Estado -eq 'OK' }).Count | Should -Be 3
    }

    It 'lee un array directo y un estado desconocido pasa a Aviso' {
        $dir = Join-Path $TestDrive 'common-array'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $json = @(
            [pscustomobject]@{ Comprobacion = 'A'; Estado = 'OK'; Detalle = 'd1'; Valor = ''; Recomendado = ''; Solucion = '' }
            [pscustomobject]@{ Comprobacion = 'B'; Estado = 'Raro'; Detalle = 'd2'; Valor = 'v2'; Recomendado = 'r2'; Solucion = 's2' }
        ) | ConvertTo-Json -Depth 5
        Set-Content -LiteralPath (Join-Path $dir 'x.json') -Value $json -Encoding UTF8
        $rows = @(ConvertFrom-CommonResult -Path $dir)
        $rows.Count | Should -Be 2
        $rows[0].Estado | Should -Be 'OK'
        $rows[1].Estado | Should -Be 'Aviso'
        $rows[1].Solucion | Should -Be 's2'
    }

    It 'lee los avisos de pc-inventory y extrae la ficha del equipo' {
        $rows = @(ConvertFrom-CommonResult -Path (Join-Path $fixtures 'pc-inventory'))
        $rows.Count | Should -Be 1
        $rows[0].Estado | Should -Be 'Aviso'

        $ficha = Get-EquipoSummary -Path (Join-Path $fixtures 'pc-inventory')
        $ficha.Equipo | Should -Be 'PC-DEMO'
        $ficha.Fabricante | Should -Be 'Demo Systems'
        $ficha.Modelo | Should -Be 'DemoBook Pro 15'
        $ficha.SO | Should -Be 'Windows 11 Pro'
    }
}

Describe 'New-HealthCheckHtml' {
    It 'contiene el equipo, el semáforo rojo y escapa <script>' {
        $rows = @(
            [pscustomobject]@{ Herramienta = 'demo'; Comprobacion = 'Prueba'; Estado = 'Alta'; Detalle = '<script>alert(1)</script>'; Solucion = 'Solución'; Informe = $null }
        )
        $summary = [pscustomobject]@{ Equipo = 'PC-DEMO'; Modelo = 'DemoBook'; SO = 'Windows 11'; Fecha = '2026-01-01'; Tools = @() }
        $path = Join-Path $TestDrive 'health-check.html'
        New-HealthCheckHtml -Rows $rows -Summary $summary -Path $path
        $html = Get-Content -LiteralPath $path -Raw -Encoding UTF8
        $html | Should -Match 'PC-DEMO'
        $html | Should -Match 'luz rojo'
        $html | Should -Match '&lt;script&gt;'
        $html | Should -Not -Match '<script>alert'
    }

    It 'semáforo ámbar si hay Aviso y verde si todo OK' {
        $aviso = @([pscustomobject]@{ Herramienta = 'demo'; Comprobacion = 'P'; Estado = 'Aviso'; Detalle = ''; Solucion = ''; Informe = $null })
        $p1 = Join-Path $TestDrive 'aviso.html'
        New-HealthCheckHtml -Rows $aviso -Summary ([pscustomobject]@{ Equipo = 'PC-DEMO'; Modelo = ''; SO = ''; Fecha = ''; Tools = @() }) -Path $p1
        (Get-Content -LiteralPath $p1 -Raw -Encoding UTF8) | Should -Match 'luz ambar'

        $ok = @([pscustomobject]@{ Herramienta = 'demo'; Comprobacion = 'P'; Estado = 'OK'; Detalle = ''; Solucion = ''; Informe = $null })
        $p2 = Join-Path $TestDrive 'ok.html'
        New-HealthCheckHtml -Rows $ok -Summary ([pscustomobject]@{ Equipo = 'PC-DEMO'; Modelo = ''; SO = ''; Fecha = ''; Tools = @() }) -Path $p2
        (Get-Content -LiteralPath $p2 -Raw -Encoding UTF8) | Should -Match 'luz verde'
    }
}

Describe 'Invoke-HealthCheckTool' {
    It 'ejecuta una herramienta falsa, normaliza su JSON y guarda el código de salida' {
        $toolsPath = Join-Path $TestDrive 'tools1'
        $scriptDir = Join-Path $toolsPath 'fake-tool'
        New-Item -ItemType Directory -Force -Path $scriptDir | Out-Null
        $script = Join-Path $scriptDir 'fake.ps1'
        @'
param([string]$OutputPath)
New-Item -ItemType Directory -Force $OutputPath | Out-Null
$o = [pscustomobject]@{ Hallazgos = @([pscustomobject]@{ Comprobacion = 'Prueba'; Estado = 'Alta'; Detalle = 'det'; Valor = ''; Recomendado = ''; Solucion = 'sol' }) }
$o | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputPath 'fake.json') -Encoding UTF8
exit 1
'@ | Set-Content -LiteralPath $script -Encoding UTF8

        $tool = [pscustomobject]@{ Repo = 'fake-tool'; Script = 'fake.ps1'; Args = @(); ArgsQuick = @(); Formato = 'Common' }
        $r = Invoke-HealthCheckTool -Tool $tool -ToolsPath $toolsPath -OutputPath (Join-Path $TestDrive 'out1') -TimeoutMinutes 2

        $r.ExitCode | Should -Be 1
        $r.Estado | Should -Be 'OK'
        $r.Rows.Count | Should -Be 1
        $r.Rows[0].Estado | Should -Be 'Alta'
        $r.Rows[0].Herramienta | Should -Be 'fake-tool'
    }

    It 'mata y registra una herramienta que tarda más que el máximo' {
        $toolsPath = Join-Path $TestDrive 'tools2'
        $scriptDir = Join-Path $toolsPath 'slow-tool'
        New-Item -ItemType Directory -Force -Path $scriptDir | Out-Null
        $script = Join-Path $scriptDir 'slow.ps1'
        @'
param([string]$OutputPath)
Start-Sleep -Seconds 60
'@ | Set-Content -LiteralPath $script -Encoding UTF8

        $tool = [pscustomobject]@{ Repo = 'slow-tool'; Script = 'slow.ps1'; Args = @(); ArgsQuick = @(); Formato = 'Common' }
        $r = Invoke-HealthCheckTool -Tool $tool -ToolsPath $toolsPath -OutputPath (Join-Path $TestDrive 'out2') -TimeoutMinutes 0.02

        $r.Estado | Should -Be 'Timeout'
    }

    It 'registra No instalada si falta el script' {
        $tool = [pscustomobject]@{ Repo = 'ausente'; Script = 'NoExiste.ps1'; Args = @(); ArgsQuick = @(); Formato = 'Common' }
        $r = Invoke-HealthCheckTool -Tool $tool -ToolsPath (Join-Path $TestDrive 'tools3') -OutputPath (Join-Path $TestDrive 'out3')
        $r.Estado | Should -Be 'No instalada'
        $r.Rows[0].Comprobacion | Should -Match 'No instalada'
    }
}

Describe 'Install-HealthCheckTool no borra carpetas ajenas' {
    It 'se niega a sobrescribir una carpeta que no instaló el kit' {
        $tools = Join-Path $TestDrive 'tools-ajenas'
        $ajena = Join-Path $tools 'time-drift-check'
        New-Item -ItemType Directory -Path $ajena -Force | Out-Null
        Set-Content -Path (Join-Path $ajena 'mio.txt') -Value 'no borrar'
        Mock -ModuleName HealthCheck Invoke-WebRequest {
            $dir = Join-Path $TestDrive 'zipsrc/time-drift-check-main'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -Path (Join-Path $dir 'Test-TimeDrift.ps1') -Value '# vacío'
            Compress-Archive -Path $dir -DestinationPath $OutFile -Force
        }
        { Install-HealthCheckTool -Repo 'time-drift-check' -ToolsPath $tools } | Should -Throw '*no se sobrescribe*'
        Test-Path (Join-Path $ajena 'mio.txt') | Should -BeTrue
    }
}
