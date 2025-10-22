#utilizzo: .\listcluster.ps1 -Domain dominio.lan -OutputPath C:\temp\clusters.csv

[CmdletBinding()]
param(
  [string] $Domain,
  [string] $SearchBase,
  [switch] $IncludeStale,           # per includere account disabilitati/stali
  [string] $OutputPath
)

$ErrorActionPreference = 'Stop'

function Write-Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err ($m){ Write-Host "[ERR ] $m" -ForegroundColor Red }

# 1) Dominio
Import-Module ActiveDirectory -ErrorAction Stop
if (-not $Domain) { $Domain = (Get-ADDomain).DNSRoot }
Write-Info "Dominio: $Domain"

# 2) Filtro LDAP: computer con SPN tipici del clustering
#   MSClusterVirtualServer / MSServerCluster / MSServerClusterMgmtAPI
#   (rilevati nei CNO/VCO dei cluster) 
#   Nota: i cluster AD-detached NON compariranno perché non creano oggetti in AD. 
#   (Vedi doc di prestaging CNO/VCO) 
#   https://learn.microsoft.com/windows-server/failover-clustering/prestage-cluster-adds
$base = '(&(objectCategory=computer)(|(servicePrincipalName=*MSClusterVirtualServer/*)(servicePrincipalName=*MSServerCluster/*)(servicePrincipalName=*MSServerClusterMgmtAPI/*)))'
$enabledFilter = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
$ldapFilter = if ($IncludeStale) { $base } else { "(&${base}${enabledFilter})" }

$params = @{
  LDAPFilter     = $ldapFilter
  Properties     = @('servicePrincipalName','dNSHostName','userAccountControl')
  ResultPageSize = 2000
}
if ($SearchBase) { $params.SearchBase = $SearchBase }

Write-Info "Query AD (solo LDAP/SPN)…"
$ad = Get-ADComputer @params

# 3) Calcola “probabile CNO” in base agli SPN (euristica: presenza di MSServerClusterMgmtAPI)
$rows = $ad | ForEach-Object {
  $spn = $_.servicePrincipalName
  $isCno = $false
  if ($spn) {
    $isCno = ($spn -match '^MSServerClusterMgmtAPI/')
  }
  [pscustomobject]@{
    Name        = $_.Name
    DNSHostName = $_.DNSHostName
    ProbableCNO = $isCno
    Source      = 'AD-SPN'
  }
}

# 4) Dedup e output
$rows = $rows | Sort-Object Name -Unique
Write-Host ""
Write-Host "========= RISULTATO (AD‑only) =========" -ForegroundColor Green
if ($rows.Count -gt 0) {
  $rows | Format-Table Name,ProbableCNO, DNSHostName -AutoSize
} else {
  Write-Warn "Nessun oggetto cluster‑like trovato in AD."
}

if ($OutputPath) {
  $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
  Write-Info "Esportato CSV: $OutputPath"
}

Write-Host ""
Write-Host "NOTE:"
Write-Host "- Questo elenco deriva SOLO da AD. Potrebbero esserci oggetti stali o CNO/VCO di ruoli." -ForegroundColor DarkGray
Write-Host "- I cluster AD‑detached non compariranno perché non creano CNO/VCO in AD." -ForegroundColor DarkGray
