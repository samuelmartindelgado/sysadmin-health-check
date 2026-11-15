# sysadmin-health-check

[![CI](https://github.com/samuelmartindelgado/sysadmin-health-check/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelmartindelgado/sysadmin-health-check/actions/workflows/ci.yml)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207-5391FE?logo=powershell&logoColor=white)
![Solo lectura](https://img.shields.io/badge/modo-solo%20lectura-16a34a)
![Licencia](https://img.shields.io/badge/licencia-MIT-blue)

**Chequeo de salud de un equipo Windows en un solo comando.** Ejecuta las 9 herramientas del kit sobre el equipo y genera
un informe HTML único tipo semáforo para saber de un vistazo qué está bien y qué hay que mirar. Está pensado para
técnicos de sistemas de empresas pequeñas: en un minuto tienes una foto del estado de cada equipo.

**Es de solo lectura.** Ni este script ni las herramientas cambian nada del equipo: no instalan, no desactivan, no
borran. Se puede pasar en producción sin riesgo.

## Qué revisa

| Herramienta | Qué mira |
|---|---|
| [windows-hardening-audit](https://github.com/samuelmartindelgado/windows-hardening-audit) | 23 puntos de seguridad: SMBv1, LLMNR, NTLM, RDP, UAC, BitLocker, parches... |
| [cert-expiry-scanner](https://github.com/samuelmartindelgado/cert-expiry-scanner) | Certificados del equipo que caducan pronto o ya caducaron. |
| [writable-path-audit](https://github.com/samuelmartindelgado/writable-path-audit) | Rutas escribibles por usuarios sin privilegios (escalada de privilegios). |
| [autostart-inventory](https://github.com/samuelmartindelgado/autostart-inventory) | Qué arranca solo y qué entradas resultan sospechosas. |
| [time-drift-check](https://github.com/samuelmartindelgado/time-drift-check) | Sincronización y desfase de la hora del equipo. |
| [event-log-size-check](https://github.com/samuelmartindelgado/event-log-size-check) | Tamaño y cobertura de los registros de eventos. |
| [stale-local-accounts](https://github.com/samuelmartindelgado/stale-local-accounts) | Cuentas locales olvidadas, sin contraseña o mal configuradas. |
| [patch-status-report](https://github.com/samuelmartindelgado/patch-status-report) | Estado de los parches y reinicios pendientes. |
| [pc-inventory](https://github.com/samuelmartindelgado/pc-inventory) | Inventario del equipo: hardware, Windows, discos y software. |

## Uso

```powershell
# 1. Clona el repositorio
git clone https://github.com/samuelmartindelgado/sysadmin-health-check.git
cd sysadmin-health-check

# 2. Descarga las 9 herramientas y ejecuta el chequeo
.\Invoke-HealthCheck.ps1 -Install
```

Esto deja en `salida/`:

- `health-check.html` — el informe único con el semáforo y lo que hay que mirar.
- `health-check.json` — los mismos datos en JSON (para juntarlos o importarlos).
- `salida/<herramienta>/` — el informe propio de cada herramienta.

### Opciones

| Parámetro | Descripción |
|---|---|
| `-ToolsPath` | Carpeta donde están (o se instalan) las herramientas. Por defecto `./tools`. |
| `-OutputPath` | Carpeta de salida. Por defecto `./salida`. |
| `-Tool repo1,repo2` | Ejecuta solo un subconjunto, por nombre de repositorio. |
| `-Install` | Descarga o actualiza cada herramienta desde GitHub. Solo sustituye carpetas que haya descargado el propio kit: nunca borra una copia tuya. |
| `-Quick` | Modo rápido (p. ej. el estado de parches no consulta Windows Update). |
| `-TimeoutMinutes` | Tiempo máximo por herramienta en minutos. Por defecto 10. |

```powershell
# Solo certificados y hora, usando las herramientas que ya tengas en ..\
.\Invoke-HealthCheck.ps1 -ToolsPath .. -Tool cert-expiry-scanner,time-drift-check -OutputPath .\salida\prueba
```

## Programarlo cada semana

En el **Programador de tareas** de Windows, crea una tarea semanal que ejecute:

- **Programa:** `powershell.exe` (o `pwsh.exe`)
- **Argumentos:** `-NoProfile -ExecutionPolicy Bypass -File C:\ruta\sysadmin-health-check\Invoke-HealthCheck.ps1 -Install -OutputPath C:\Informes\salud`

Marca *Ejecutar tanto si el usuario inició sesión como si no* y deja que escriba el HTML en una carpeta compartida
para revisar los informes de toda la oficina desde un sitio.

## Ejemplo de salida (datos ficticios)

```
Chequeo de salud del equipo
Equipo: PC-DEMO   Fecha: 2026-01-01 12:00:00

Herramienta              Alta Aviso OK Estado de ejecución Segundos
---------                ---- ----- -- ------------------- --------
windows-hardening-audit     2     3 18 OK                    6,4
cert-expiry-scanner         0     1  2 OK                    2,1
writable-path-audit         1     0  0 OK                    1,8
autostart-inventory         0     2  0 OK                    3,0
time-drift-check            0     1  4 OK                    1,5
event-log-size-check        1     1  5 OK                    1,2
stale-local-accounts        0     1  2 OK                    1,0
patch-status-report         1     1  2 OK                    4,5
pc-inventory                0     1  0 OK                    2,0

Resultado: 5 Alta, 11 Aviso, 33 OK - Hay problemas graves (Alta)
Informe: C:\...\salida\health-check.html
```

## Solo lectura

Este proyecto no cambia ninguna configuración del equipo. Los comandos de la columna *Solución* de los informes son
ejemplos orientativos y **nunca se ejecutan automáticamente**. No hace falta ser administrador: lo que no se pueda leer
sin permisos se omite y se indica en el informe.

## Licencia

MIT.

---

## Summary (English)

`sysadmin-health-check` is a read-only, one-command health check for Windows machines aimed at small-business IT techs.
It runs 9 PowerShell tools (hardening audit, certificate expiry, writable paths, autostart inventory, time drift,
event-log size, stale local accounts, patch status and PC inventory), normalizes their JSON output and produces a
single traffic-light HTML report plus a machine-readable JSON. It works on Windows PowerShell 5.1 and PowerShell 7,
has no external dependencies, and never changes anything on the machine. Install and run with
`.\Invoke-HealthCheck.ps1 -Install`; schedule it weekly with Windows Task Scheduler. MIT licensed.
