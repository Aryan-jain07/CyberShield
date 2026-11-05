param([string]$DatabaseUrl = $env:DATABASE_URL)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $projectRoot '.env'

if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*([^#=\s]+)\s*=\s*(.*?)\s*$') {
            Set-Item -Path ("Env:" + $matches[1]) -Value $matches[2]
        }
    }
}

if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) {
    $DatabaseUrl = $env:DATABASE_URL
}

if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) {
    foreach ($name in 'POSTGRES_HOST', 'POSTGRES_PORT', 'POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD') {
        if ([string]::IsNullOrWhiteSpace((Get-Item "Env:$name" -ErrorAction SilentlyContinue).Value)) {
            throw "Set $name in .env or provide DATABASE_URL."
        }
    }
    $env:PGHOST = $env:POSTGRES_HOST
    $env:PGPORT = $env:POSTGRES_PORT
    $env:PGUSER = $env:POSTGRES_USER
    $env:PGPASSWORD = $env:POSTGRES_PASSWORD
    $DatabaseUrl = $env:POSTGRES_DB
    $exists = & psql -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$DatabaseUrl'"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to connect to PostgreSQL with .env credentials.' }
    if ($exists -ne '1') {
        & createdb $DatabaseUrl
        if ($LASTEXITCODE -ne 0) { throw "Unable to create PostgreSQL database $DatabaseUrl." }
    }
}

$files = @('schema.sql', 'indexes.sql', 'views.sql', 'functions.sql', 'triggers.sql', 'seed.sql', 'verify.sql')
foreach ($file in $files) {
    & psql $DatabaseUrl -v ON_ERROR_STOP=1 -f (Join-Path $PSScriptRoot $file)
    if ($LASTEXITCODE -ne 0) { throw "PostgreSQL initialization failed while running $file" }
}
