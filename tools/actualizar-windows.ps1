# Actualiza la Sombra instalada en este PC con el instalador que GitHub compila para main.
#  1) Busca la compilación de Windows del último cambio de main (si no hay, la lanza).
#  2) Espera a que termine y descarga el instalador en <Escritorio>\Sombra\instalador\<cambio>
#     (y lo copia a Sombra_0.1.0_x64-setup.exe).
#  3) Lo instala sin preguntas (/S) encima del que hay. Tus datos (ajustes, sesiones,
#     contraseñas) se conservan: el instalador solo cambia el programa.
# Si Sombra está abierta no la cierra: avisa y sale (código 2) para no perder lo que tengas abierto.
# Con -EsperarCierre, en vez de salir espera (hasta 24 h) a que la cierres y entonces la actualiza.
# Con -Fondo se lanza a sí mismo en segundo plano, sin ventana, y apunta todo en
# <Escritorio>\Sombra\instalador\actualizar.log (sigue aunque se cierre quien lo lanzó).
# Si Windows bloquea el instalador (sin firmar), avisa y sale (código 3).
# Uso: powershell -File tools\actualizar-windows.ps1 [-Sha <cambio>] [-SoloDescargar] [-EsperarCierre] [-Fondo]
param([string]$Sha = "", [switch]$SoloDescargar, [switch]$EsperarCierre, [switch]$Fondo)
$ErrorActionPreference = 'Stop'
$gh = (Get-Command gh -ErrorAction SilentlyContinue).Source
if (-not $gh) { $gh = "C:\Program Files\GitHub CLI\gh.exe" }
$repo = "frankeshb-sudo/sombra"
$dest = Join-Path ([Environment]::GetFolderPath("Desktop")) "Sombra\instalador"
$setup = Join-Path $dest "Sombra_0.1.0_x64-setup.exe"
$exe = Join-Path $env:LOCALAPPDATA "Sombra\sombra.exe"

if ($Fondo) {
    New-Item -ItemType Directory -Force $dest | Out-Null
    $log = Join-Path $dest "actualizar.log"
    $shaArg = if ($Sha) { $Sha } else { "main" }
    $cmd = "& '$PSCommandPath' -Sha '$shaArg' -EsperarCierre *>> '$log'; exit `$LASTEXITCODE"
    # Una sola actualización esperando: la nueva (de un cambio más reciente) sustituye a la anterior.
    $pidFile = Join-Path $dest "actualizar.pid"
    if (Test-Path $pidFile) {
        $old = Get-Process -Id ([int](Get-Content $pidFile)) -ErrorAction SilentlyContinue
        if ($old -and $old.ProcessName -eq 'powershell') { Stop-Process -Id $old.Id -Force }
    }
    $p = Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmd
    Set-Content $pidFile $p.Id
    Write-Output "Actualización en segundo plano ($shaArg). Registro: $log"
    exit 0
}
Write-Output "--- $(Get-Date -Format s)"

if (-not $Sha) { $Sha = "main" }
# Siempre el identificador completo (acepta "main", uno corto como a51c0ae o uno completo).
$Sha = (& $gh api "repos/$repo/commits/$Sha" -q .sha)
if ($LASTEXITCODE -ne 0 -or -not $Sha) { throw "No existe ese cambio en GitHub" }
$Sha = $Sha.Trim()
$short = $Sha.Substring(0, 7)
Write-Output "Cambio: $short"

function Find-Run {
    # La compilación de ese cambio que no se haya cancelado ni fallado (la más reciente).
    # (Se guarda antes en una variable: en PowerShell 5.1, ConvertFrom-Json da la lista de una pieza.)
    $list = (& $gh run list -R $repo -w windows.yml -L 30 --json databaseId,headSha,conclusion) | Out-String | ConvertFrom-Json
    $list | Where-Object { $_.headSha -eq $Sha -and $_.conclusion -notin @('cancelled', 'failure') } | Select-Object -First 1
}

$dir = Join-Path $dest $short
$found = Get-ChildItem -Recurse $dir -Filter "Sombra_*-setup.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $found) {
    $run = Find-Run
    if (-not $run) {
        & $gh workflow run windows.yml --ref main -R $repo | Out-Null
        for ($i = 0; $i -lt 12 -and -not $run; $i++) { Start-Sleep 5; $run = Find-Run }
        if (-not $run) { throw "No encuentro la compilación de $short" }
    }
    Write-Output "Compilación en GitHub: $($run.databaseId) (espera ~10 min si acaba de empezar)"
    & $gh run watch $run.databaseId -R $repo --exit-status *> $null
    if ($LASTEXITCODE -ne 0) { throw "La compilación de Windows ha fallado: https://github.com/$repo/actions/runs/$($run.databaseId)" }
    $found = Get-ChildItem -Recurse $dir -Filter "Sombra_*-setup.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) {
        New-Item -ItemType Directory -Force $dir | Out-Null
        & $gh run download $run.databaseId -R $repo -D $dir
        $found = Get-ChildItem -Recurse $dir -Filter "Sombra_*-setup.exe" | Select-Object -First 1
    }
    if (-not $found) { throw "La descarga no trae el instalador" }
}
Copy-Item $found.FullName $setup -Force
Write-Output "Instalador: $setup"
if ($SoloDescargar) { exit 0 }

if (Get-Process -Name sombra -ErrorAction SilentlyContinue) {
    if (-not $EsperarCierre) {
        Write-Output "Sombra está abierta: ciérrala y vuelve a ejecutar esto para actualizarla."
        exit 2
    }
    Write-Output "Sombra está abierta: se actualizará en cuanto la cierres."
    $limit = (Get-Date).AddHours(24)
    while (Get-Process -Name sombra -ErrorAction SilentlyContinue) {
        if ((Get-Date) -gt $limit) { Write-Output "Sombra lleva 24 h abierta: no se ha actualizado."; exit 2 }
        Start-Sleep 10
    }
    # Que termine de cerrarse del todo (archivos y motor web).
    Start-Sleep 5
    while (Get-Process -Name sombra -ErrorAction SilentlyContinue) { Start-Sleep 5 }
}
$before = if (Test-Path $exe) { (Get-FileHash $exe).Hash } else { "" }
# El instalador no está firmado: el Control de aplicaciones inteligente de Windows puede
# bloquearlo. No se intenta saltar: se avisa y se deja listo para abrirlo a mano.
try {
    $p = Start-Process -FilePath $setup -ArgumentList '/S' -Wait -PassThru
} catch {
    Write-Output "Windows ha bloqueado el instalador (Control de aplicaciones inteligente): ábrelo tú con doble clic en $setup"
    exit 3
}
if ($p.ExitCode -ne 0) { throw "El instalador ha terminado con el código $($p.ExitCode)" }
if (-not (Test-Path $exe)) { throw "No se ha instalado: falta $exe" }
$changed = (Get-FileHash $exe).Hash -ne $before
Set-Content -Encoding utf8 (Join-Path $dest "instalada.txt") "$short $(Get-Date -Format s)"
if ($changed) { Write-Output "Sombra actualizada a $short." } else { Write-Output "Sombra ya tenía la versión $short." }
