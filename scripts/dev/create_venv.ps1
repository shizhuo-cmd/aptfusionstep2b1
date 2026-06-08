param(
    [ValidateSet("cpu", "gpu-cu124")]
    [string]$Mode = "cpu",
    [string]$VenvPath = ".venv",
    [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $VenvPath)) {
    & $PythonExe -m venv $VenvPath
}

$Pip = Join-Path $VenvPath "Scripts\pip.exe"
$Python = Join-Path $VenvPath "Scripts\python.exe"

& $Python -m pip install --upgrade pip setuptools wheel

if ($Mode -eq "cpu") {
    & $Pip install torch==2.6.0 torchvision==0.21.0 torchaudio==2.6.0 --index-url https://download.pytorch.org/whl/cpu
    & $Pip install torch_geometric==2.6.1
    & $Pip install pyg_lib torch_scatter torch_sparse torch_cluster torch_spline_conv -f https://data.pyg.org/whl/torch-2.6.0+cpu.html
    & $Pip install -r ".\requirements\base.txt"
} else {
    & $Pip install torch==2.6.0 torchvision==0.21.0 torchaudio==2.6.0 --index-url https://download.pytorch.org/whl/cu124
    & $Pip install torch_geometric==2.6.1
    & $Pip install pyg_lib torch_scatter torch_sparse torch_cluster torch_spline_conv -f https://data.pyg.org/whl/torch-2.6.0+cu124.html
    & $Pip install -r ".\requirements\base.txt"
}

Write-Host "Virtual environment is ready at $VenvPath with mode $Mode"

