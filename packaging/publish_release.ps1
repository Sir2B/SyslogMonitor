param(
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$DistributionDir,
    [Parameter(Mandatory)][string]$Screenshot,
    [string]$ScreenshotGalleryDir = "",
    [string]$GalleryRemote = ""
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
$screenshots = @($Screenshot)
$gallery = @()
if ($ScreenshotGalleryDir) {
    $gallery = @(Get-ChildItem -LiteralPath $ScreenshotGalleryDir -Filter "screenshot-*.png" -File |
        ForEach-Object { $_.FullName })
    if ($gallery.Count -eq 0) {
        throw "No gallery screenshots found in $ScreenshotGalleryDir."
    }
}
$assets = $screenshots + $packages
foreach ($path in $assets + $gallery) {
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
    & gh release upload $Tag @screenshots --repo $repository --clobber
    if ($LASTEXITCODE -ne 0) {
        throw "Could not upload the screenshots to $Tag."
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
        $image = "<img src=`"$imageUrl`" alt=`"Syslog Monitor $Tag`" width=`"640`">"
        Set-Content -LiteralPath $notes.FullName -Value "$image`n`n$($release.body)" -Encoding utf8
        & gh release edit $Tag --repo $repository --notes-file $notes.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "Could not update the release notes for $Tag."
        }
    } finally {
        Remove-Item -LiteralPath $notes.FullName -Force
    }
}

# The README gallery lives on a separate branch so the release assets stay limited
# to the packages and a single preview image. One force-pushed commit keeps it small.
if ($gallery.Count -gt 0) {
    if (-not $GalleryRemote) {
        if (-not $env:GH_TOKEN) {
            throw "GH_TOKEN is required to publish the screenshot gallery."
        }
        $GalleryRemote = "https://x-access-token:$($env:GH_TOKEN)@github.com/$repository.git"
    }
    $branchDir = Join-Path ([System.IO.Path]::GetTempPath()) "syslogmonitor-screenshots-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $branchDir | Out-Null
    try {
        Copy-Item -LiteralPath $gallery -Destination $branchDir
        & git -C $branchDir init --quiet --initial-branch screenshots
        & git -C $branchDir add --all
        & git -C $branchDir -c user.name="github-actions[bot]" `
            -c user.email="41898282+github-actions[bot]@users.noreply.github.com" `
            commit --quiet -m "chore: screenshots for $Tag"
        if ($LASTEXITCODE -ne 0) {
            throw "Could not commit the screenshot gallery."
        }
        & git -C $branchDir push --quiet --force $GalleryRemote screenshots
        if ($LASTEXITCODE -ne 0) {
            throw "Could not push the screenshot gallery."
        }
    } finally {
        Remove-Item -LiteralPath $branchDir -Recurse -Force
    }
}