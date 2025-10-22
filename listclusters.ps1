#utilizzo: .\listcluster.ps1 -Domain dominio.lan -OutputPath C:\temp\clusters.csv

[CmdletBinding()]
param(
  [string] $Domain,
  [string] $SearchBase,
  [switch] $IncludeStale,              # include account disabilitati/stali
  [switch] $ValidateWithClusterAPI,    # valida con Get-Cluster se disponibile
  [string] $OutputPath
)

$ErrorActionPreference = 'Stop'

function Write-Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err ($m){ Write-Host "[ERR ] $m" -ForegroundColor Red }

function Ensure-Module([string]$Name){
  try{
    if (-not (Get-Module -ListAvailable -Name $Name)) { return $false }
    Import-Module $Name -ErrorAction Stop
    return $true
  } catch { return $false }
}

# 1) Dominio
if (-not (Ensure-Module ActiveDirectory)) {
  Write-Err "Modulo ActiveDirectory mancante. Installa RSAT-AD-PowerShell."
  return
}
if (-not $Domain) { $Domain = (Get-ADDomain).DNSRoot }
Write-Info "Dominio: $Domain"

# 2) Filtro LDAP costruito a pezzi (niente parentesi “incollate”)
# (&
#   (objectCategory=computer)
#   (| (spn=MSClusterVirtualServer/*)(spn=MSServerCluster/*)(spn=MSServerClusterMgmtAPI/*) )
#   [ !(userAccountControl:...:=2) ]  <-- opzionale se NON vuoi includere stali
# )
$parts = @(
  '(objectCategory=computer)',
  '(|(servicePrincipalName=*MSClusterVirtualServer/*)(servicePrincipalName=*MSServerCluster/*)(servicePrincipalName=*MSServerClusterMgmtAPI/*))'
)
if (-not $IncludeStale) {
  $parts += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
}
$ldapFilter = '(&' + ($parts -join '') + ')'

# 3) Query AD: proviamo con msDS-ManagedBy, se fallisce rifacciamo senza
$wantedProps = @('servicePrincipalName','dNSHostName','userAccountControl','msDS-ManagedBy')
$params = @{
  LDAPFilter     = $ldapFilter
  Properties     = $wantedProps
  ResultPageSize = 2000
}
if ($SearchBase) { $params.SearchBase = $SearchBase }

Write-Info "Query AD…"
$ad = @()
try {
  $ad = Get-ADComputer @params
} catch {
  if ($_.Exception.Message -match 'msDS-ManagedBy') {
    Write-Warn "Attributo msDS-ManagedBy non disponibile: ri-eseguo senza."
    $params.Properties = @('servicePrincipalName','dNSHostName','userAccountControl')
    $ad = Get-ADComputer @params
  } else {
    throw
  }
}
Write-Info ("Oggetti cluster-like trovati in AD: {0}" -f $ad.Count)

# 4) Individua candidati CNO/VCO in base agli SPN
$candidates = foreach($obj in $ad){
  $spn = @($obj.servicePrincipalName)
  $hasMgmtAPI   = ($spn -match '^MSServerClusterMgmtAPI/')
  $hasVirtSrv   = ($spn -match '^MSClusterVirtualServer/')
  $hasGenericMS = ($spn -match '^MSServerCluster/')

  [pscustomobject]@{
    Name               = $obj.Name
    DNSHostName        = $obj.dNSHostName
    DistinguishedName  = $obj.DistinguishedName
    HasMgmtAPI         = [bool]$hasMgmtAPI
    HasVirtualSrv      = [bool]$hasVirtSrv
    HasGenericMS       = [bool]$hasGenericMS
    MsDSManagedBy      = $obj.'msDS-ManagedBy'
    Disabled           = ([int]$obj.userAccountControl -band 0x2) -ne 0
  }
}

# 5) (Facoltativo) mappa CNO referenziati dai VCO se msDS-ManagedBy è disponibile
$cnoByManagedBy = @{}
try {
  $refs = $candidates | Where-Object { $_.MsDSManagedBy } | Select-Object -ExpandProperty MsDSManagedBy -Unique
  if ($refs) {
    $dnFilter = "(|" + (($refs | ForEach-Object { "(distinguishedName=$($_))" }) -join '') + ")"
    $cnoObjs = Get-ADComputer -LDAPFilter $dnFilter -Properties dNSHostName | Select-Object Name,DistinguishedName
    foreach($c in $cnoObjs){ $cnoByManagedBy[$c.DistinguishedName] = $c.Name }
  }
} catch {
  # Se l'attributo non esiste nello schema/contesto, si ignora
}

# 6) (Facoltativo) Validazione con API cluster (se disponibile e richiesto)
$validated = @{}
$clusterModule = $false
if ($ValidateWithClusterAPI) {
  $clusterModule = Ensure-Module FailoverClusters
  if ($clusterModule) {
    Write-Info "Validazione con Get-Cluster -Name…"
    foreach($n in ($candidates | Select-Object -ExpandProperty Name -Unique)){
      try { $null = Get-Cluster -Name $n -ErrorAction Stop; $validated[$n] = $true }
      catch { $validated[$n] = $false }
    }
  } else {
    Write-Warn "Modulo FailoverClusters non disponibile: salto la validazione API."
  }
}

# 7) Classificazione + confidenza
$rows = foreach($c in ($candidates | Sort-Object Name -Unique)){
  $isCnoBySpn = $c.HasMgmtAPI
  $isCnoByRef = $false
  if (-not [string]::IsNullOrEmpty($c.DistinguishedName)) {
    $isCnoByRef = $cnoByManagedBy.ContainsKey($c.DistinguishedName)
  }

  $isCNO  = $isCnoBySpn -or $isCnoByRef
  $apiOk  = ($validated.ContainsKey($c.Name) -and $validated[$c.Name])

  $confidence = if ($apiOk -and $isCNO) { 'High' }
                elseif ($isCNO)          { 'Medium' }
                else                     { 'Low' }

  $role = if ($isCNO) { 'CNO' } else { 'VCO/Other' }

  $parentCNO = $null
  if ($c.MsDSManagedBy) {
    $parentCNO = $cnoByManagedBy[$c.MsDSManagedBy]
    if (-not $parentCNO) { $parentCNO = $c.MsDSManagedBy }
  }

  [pscustomobject]@{
    Name           = $c.Name
    Role           = $role
    Confidence     = $confidence
    ValidatedByAPI = $apiOk
    HasMgmtAPI     = $c.HasMgmtAPI
    HasVirtSPN     = $c.HasVirtualSrv
    Disabled       = $c.Disabled
    DNSHostName    = $c.DNSHostName
    ParentCNO      = $parentCNO
  }
}

# 8) Output
$rows = $rows | Sort-Object -Property Role, Confidence, Name -Descending
Write-Host ""
Write-Host "========= RISULTATO =========" -ForegroundColor Green
if ($rows.Count -gt 0) {
  $rows | Format-Table Name,Role,Confidence,ValidatedByAPI,HasMgmtAPI,HasVirtSPN,Disabled,ParentCNO -AutoSize
} else {
  Write-Warn "Nessun oggetto cluster-like trovato in AD."
}

if ($OutputPath) {
  $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
  Write-Info "Esportato CSV: $OutputPath"
}

Write-Host ""
Write-Host "===== NOTE =====" -ForegroundColor DarkCyan
Write-Host "- AD-only: i cluster AD-detached non compaiono (non creano CNO/VCO in AD)." -ForegroundColor DarkGray
Write-Host "- Per la validazione autoritativa, installa RSAT-Clustering-PowerShell e usa -ValidateWithClusterAPI." -ForegroundColor DarkGray
