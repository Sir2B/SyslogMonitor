param(
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$DistributionDir,
    [Parameter(Mandatory)][string]$Screenshot
)

$ErrorActionPreference = "Stop"
$repository = $env:GITHUB_REPOSITORY
if (-not $repository) {
    throw "GITHUB_REPOSITORY is required."
}
if ($Tag -cne "v$Version") {
    throw "Tag $Tag does not match application version $Version."
}

$packages = @(
    (Join-Path $DistributionDir "SyslogMonitor-$Version-setup.exe"),
    (Join-Path $DistributionDir "SyslogMonitor-$Version-portable.zip")
)
$assets = @($Screenshot) + $packages
foreach ($path in $assets) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Expected release asset was not created: $path"
    }
    if ((Get-Item -LiteralPath $path).Length -eq 0) {
        throw "Release asset is empty: $path"
    }
}

$lookup = & gh release view $Tag --repo $repository --json "body,assets" 2>&1
$lookupCode = $LASTEXITCODE
if ($lookupCode -ne 0) {
    $message = ($lookup | Out-String).Trim()
    if ($message -ne "release not found") {
        throw "Could not inspect release $Tag`: $message"
    }
    & gh release create $Tag @assets --repo $repository --verify-tag --title $Tag --generate-notes
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create release $Tag."
    }
    $lookup = & gh release view $Tag --repo $repository --json "body,assets"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read the generated release notes for $Tag."
    }
    $release = $lookup | ConvertFrom-Json
} else {
    $release = $lookup | ConvertFrom-Json
    & gh release upload $Tag $Screenshot --repo $repository --clobber
    if ($LASTEXITCODE -ne 0) {
        throw "Could not upload the screenshot to $Tag."
    }
    $existingNames = @($release.assets | ForEach-Object { $_.name })
    $missingPackages = @(
        foreach ($package in $packages) {
            $name = [System.IO.Path]::GetFileName($package)
            if ($existingNames -ccontains $name) {
                Write-Host "Keeping existing release asset: $name"
            } else {
                $package
            }
        }
    )
    if ($missingPackages.Count -gt 0) {
        & gh release upload $Tag @missingPackages --repo $repository
        if ($LASTEXITCODE -ne 0) {
            throw "Could not upload the Windows packages to $Tag."
        }
    }
}

$encodedTag = [uri]::EscapeDataString($Tag)
$imageUrl = "https://github.com/$repository/releases/download/$encodedTag/screenshot.png"
if (-not ([string]$release.body).Contains($imageUrl)) {
    $notes = New-TemporaryFile
    try {
        $image = "![Syslog Monitor $Tag]($imageUrl)"
        Set-Content -LiteralPath $notes.FullName -Value "$image`n`n$($release.body)" -Encoding utf8
        & gh release edit $Tag --repo $repository --notes-file $notes.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "Could not update the release notes for $Tag."
        }
    } finally {
        Remove-Item -LiteralPath $notes.FullName -Force
    }
}
