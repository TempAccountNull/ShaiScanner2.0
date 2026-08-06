param(
    [Parameter(Mandatory = $false)]
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")),

    [Parameter(Mandatory = $false)]
    [string]$Tag = "v1.92.9b"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-ImGuiTree {
    param([Parameter(Mandatory = $true)][string]$Path)

    $required = @(
        "imgui.cpp",
        "imgui.h",
        "imgui_draw.cpp",
        "imgui_tables.cpp",
        "imgui_widgets.cpp",
        "backends\imgui_impl_win32.cpp",
        "backends\imgui_impl_win32.h",
        "backends\imgui_impl_dx11.cpp",
        "backends\imgui_impl_dx11.h"
    )

    foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $Path $relative) -PathType Leaf)) {
            return $false
        }
    }
    return $true
}

$project = [System.IO.Path]::GetFullPath($ProjectRoot)
$versionName = $Tag.TrimStart('v')
# Default pinned directory name: imgui-1.92.9b
$thirdParty = Join-Path $project "third_party"
$destination = Join-Path $thirdParty ("imgui-" + $versionName)
$mutex = New-Object System.Threading.Mutex($false, "ShaiHulud2Scanner.ImGui.$versionName")
$hasMutex = $false
$tempRoot = $null

try {
    $hasMutex = $mutex.WaitOne([TimeSpan]::FromMinutes(10))
    if (-not $hasMutex) {
        throw "Timed out waiting for another Dear ImGui preparation process to finish."
    }

    if (Test-ImGuiTree -Path $destination) {
        Write-Host "[OK] Dear ImGui $Tag is already prepared: $destination"
        Write-Output $destination
        exit 0
    }

    if (Test-Path -LiteralPath $destination) {
        Write-Host "[WARN] Removing incomplete Dear ImGui directory: $destination"
        Remove-Item -LiteralPath $destination -Recurse -Force
    }

    New-Item -ItemType Directory -Path $thirdParty -Force | Out-Null

    # Reuse the source left by older FetchContent-based builds before trying
    # the network. This lets an upgraded source tree build immediately.
    $legacySource = Join-Path $project "build\_deps\imgui-src"
    if (Test-ImGuiTree -Path $legacySource) {
        Write-Host "[INFO] Reusing Dear ImGui from the previous build cache: $legacySource"
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Copy-Item -Path (Join-Path $legacySource "*") -Destination $destination -Recurse -Force
        if (-not (Test-ImGuiTree -Path $destination)) {
            throw "The previous build cache could not be copied into the prepared dependency directory."
        }
        Set-Content -LiteralPath (Join-Path $destination ".shaihulud-version") `
            -Value $Tag -Encoding ASCII
        Write-Host "[OK] Dear ImGui $Tag prepared from the existing build cache: $destination"
        Write-Output $destination
        exit 0
    }

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "ShaiHulud2Scanner-imgui-" + $PID + "-" + [Guid]::NewGuid().ToString("N"))
    $archive = Join-Path $tempRoot "imgui.zip"
    $extractRoot = Join-Path $tempRoot "extract"
    New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $urls = @(
        "https://github.com/ocornut/imgui/archive/refs/tags/$Tag.zip",
        "https://codeload.github.com/ocornut/imgui/zip/refs/tags/$Tag"
    )

    $downloaded = $false
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($url in $urls) {
        try {
            Write-Host "[INFO] Downloading Dear ImGui $Tag from $url"
            Invoke-WebRequest `
                -Uri $url `
                -OutFile $archive `
                -UseBasicParsing `
                -Headers @{ "User-Agent" = "ShaiHulud2Scanner-build/$versionName" } `
                -MaximumRedirection 10

            if ((Get-Item -LiteralPath $archive).Length -lt 100000) {
                throw "Downloaded archive is unexpectedly small."
            }
            $downloaded = $true
            break
        }
        catch {
            $errors.Add("$url -> $($_.Exception.Message)")
            Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $downloaded) {
        throw ("Could not download Dear ImGui $Tag.`n" + ($errors -join "`n"))
    }

    Write-Host "[INFO] Extracting Dear ImGui $Tag once, outside the CMake build graph..."
    Expand-Archive -LiteralPath $archive -DestinationPath $extractRoot -Force

    $source = Get-ChildItem -LiteralPath $extractRoot -Directory |
        Where-Object { Test-ImGuiTree -Path $_.FullName } |
        Select-Object -First 1

    if ($null -eq $source) {
        throw "The downloaded Dear ImGui archive did not contain the expected source tree."
    }

    Move-Item -LiteralPath $source.FullName -Destination $destination
    if (-not (Test-ImGuiTree -Path $destination)) {
        throw "Dear ImGui extraction completed, but required files are missing."
    }

    Set-Content -LiteralPath (Join-Path $destination ".shaihulud-version") `
        -Value $Tag -Encoding ASCII

    Write-Host "[OK] Dear ImGui $Tag prepared: $destination"
    Write-Output $destination
}
finally {
    if ($null -ne $tempRoot -and (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($hasMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
