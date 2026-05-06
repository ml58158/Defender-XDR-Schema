$repoApi = "https://api.github.com/repos/MicrosoftDocs/defender-docs/contents/defender-xdr?ref=public"
$outputDir = Join-Path $PSScriptRoot "..\schema\raw-md"

$response = Invoke-RestMethod -Uri $repoApi

$files = $response | Where-Object { $_.name -like "advanced-hunting-*-table.md" }

foreach ($file in $files) {
    $dest = Join-Path $outputDir $file.name
    Invoke-WebRequest -Uri $file.download_url -OutFile $dest
    Write-Host "Downloaded $($file.name)"
}
