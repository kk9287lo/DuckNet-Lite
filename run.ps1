<#
.SYNOPSIS
  ChickenNet L7 Security 起動ランチャ (Windows / PowerShell 5+ ・ pwsh)
.DESCRIPTION
  Python を堅牢に検出し、バージョンを確認し、UTF-8 を整えて製品本体へ委譲する。
    .\run.ps1                      # ゲートウェイ(前衛 + 管理ダッシュボード)
    .\run.ps1 --help               # 製品の全オプション
  環境変数:
    CHICKENNET_PYTHON    使う Python を明示(未設定なら .venv -> python -> py)
    CHICKENNET_ENV_FILE  読み込む設定ファイル(既定: スクリプトと同じ場所の app.env)
  終了コード: 製品の終了コードをそのまま返す。起動前提を満たさない場合は 9。
#>
#requires -Version 5
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $Rest)

$ErrorActionPreference = 'Stop'
$self = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $self
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new() } catch {}
if (-not $env:PYTHONUTF8) { $env:PYTHONUTF8 = '1' }
if (-not $env:PYTHONIOENCODING) { $env:PYTHONIOENCODING = 'utf-8' }

function Die([string] $msg) { [Console]::Error.WriteLine("ChickenNet: $msg"); exit 9 }

# 1) 任意の設定ファイル(KEY=VALUE / # はコメント)
$envFile = if ($env:CHICKENNET_ENV_FILE) { $env:CHICKENNET_ENV_FILE } else { Join-Path $self 'app.env' }
if (Test-Path -LiteralPath $envFile) {
  foreach ($line in Get-Content -LiteralPath $envFile) {
    $t = $line.Trim()
    if ($t -and -not $t.StartsWith('#') -and $t.Contains('=')) {
      $k, $v = $t -split '=', 2
      Set-Item -Path ("env:" + $k.Trim()) -Value $v.Trim()
    }
  }
}

# 2) Python を選ぶ: 明示 -> ローカル venv -> python -> py
function Find-Python {
  if ($env:CHICKENNET_PYTHON) {
    $fp = $env:CHICKENNET_PYTHON
    if ((Test-Path -LiteralPath $fp) -or (Get-Command $fp -ErrorAction SilentlyContinue)) { return $fp }
    Die "指定の Python が見つかりません/実行できません: $fp"
  }
  foreach ($p in @(
      (Join-Path $self '.venv\Scripts\python.exe'),
      (Join-Path $self 'venv\Scripts\python.exe'))) {
    if (Test-Path -LiteralPath $p) { return $p }
  }
  foreach ($c in @('python', 'py')) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { return $c }
  }
  return $null
}
$py = Find-Python
if (-not $py) { Die 'Python が見つかりません。Python 3.10+ を導入するか CHICKENNET_PYTHON を設定してください。' }

# 3) バージョンゲート(3.10+)
try { & $py -c "import sys;raise SystemExit(0 if sys.version_info[:2]>=(3,10) else 1)" 2>$null }
catch { Die "Python を実行できません: $py" }
if ($LASTEXITCODE -ne 0) { Die 'Python 3.10 以上が必要です。' }

# 4) 製品本体へ委譲(引数はそのまま渡す)
& $py -m dataplane @Rest
exit $LASTEXITCODE
