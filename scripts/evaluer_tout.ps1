# Evaluation complete PKI-Ops (equivalent Windows de make reproduce). Journaux dans results/logs.
# $args[0] : fichier a attendre avant de commencer (pour ne pas partager le CPU avec une autre evaluation).
$ErrorActionPreference = "Continue"
Set-Location (Split-Path $PSScriptRoot -Parent)
New-Item -ItemType Directory -Force results\logs | Out-Null
if ($args.Count -gt 0) {
    while (-not ((Test-Path $args[0]) -and (Select-String -Path $args[0] -Pattern "TOUT_FINI" -Quiet))) { Start-Sleep 60 }
}
$py = ".venv\Scripts\python.exe"
$etapes = @(
    @("baseline", @("evaluer", "baseline")),
    @("experiences", @("evaluer", "experiences")),
    @("llm_tres_petit", @("evaluer", "llm", "--modele", "tres_petit", "--complet")),
    @("llm_petit", @("evaluer", "llm", "--modele", "petit"))
)
foreach ($e in $etapes) {
    $debut = Get-Date
    & $py -m pki_ops.cli @($e[1]) *> "results\logs\$($e[0]).log"
    "$($e[0]) fini en $([int]((Get-Date) - $debut).TotalSeconds) s" | Add-Content results\logs\etapes.log
}
"TOUT_FINI" | Add-Content results\logs\etapes.log
