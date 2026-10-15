# AIDR Privacy: Windows built-in OCR (Windows.Media.Ocr) for the local vision worker.
# Trusted script, untrusted image bytes. Reads one PNG (already decoded, oriented and re-encoded
# by vision/worker.py) from stdin and writes Tesseract-compatible TSV (level 5 = word) to stdout,
# one page block per recognizer language, so worker.py parses it with the same strict parser.
# No network, no temp files, no logging of recognised text. Windows PowerShell 5.1 only
# (WinRT projection); run with -NoProfile -NonInteractive.
#
# Windows OCR reports no per-word confidence. Every word is emitted with the fixed confidence
# given by -Confidence (default 90); the engine's "uncertain OCR" review therefore only triggers
# on small word height with this backend. This is documented in docs/VISUAL.md.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Languages,
    [ValidateRange(0, 100)][int]$Confidence = 90
)
$ErrorActionPreference = 'Stop'
try {
    if ($PSVersionTable.PSVersion.Major -ne 5) { exit 3 }
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
    $null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType = WindowsRuntime]
    $null = [Windows.Globalization.Language, Windows.Foundation, ContentType = WindowsRuntime]
    $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
    function Wait-Op($operation, [Type]$type) {
        $task = $asTask.MakeGenericMethod($type).Invoke($null, @($operation))
        if (-not $task.Wait(20000)) { exit 4 }
        return $task.Result
    }
    # Read the whole PNG from stdin (bounded: 64 MiB; worker.py sends at most a re-encoded 12 MP image).
    $stdin = [Console]::OpenStandardInput()
    $buffer = New-Object System.IO.MemoryStream
    $chunk = New-Object byte[] 65536
    while (($n = $stdin.Read($chunk, 0, $chunk.Length)) -gt 0) {
        $buffer.Write($chunk, 0, $n)
        if ($buffer.Length -gt 67108864) { exit 5 }
    }
    $bytes = $buffer.ToArray()
    if ($bytes.Length -lt 8 -or $bytes[0] -ne 0x89 -or $bytes[1] -ne 0x50) { exit 6 }
    $memory = New-Object System.IO.MemoryStream(, $bytes)
    $stream = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($memory)
    $decoder = Wait-Op ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync([Windows.Graphics.Imaging.BitmapDecoder]::PngDecoderId, $stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $bitmap = Wait-Op ($decoder.GetSoftwareBitmapAsync([Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8, [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied)) ([Windows.Graphics.Imaging.SoftwareBitmap])
    $width = [int]$bitmap.PixelWidth; $height = [int]$bitmap.PixelHeight
    if ($width -gt [Windows.Media.Ocr.OcrEngine]::MaxImageDimension -or $height -gt [Windows.Media.Ocr.OcrEngine]::MaxImageDimension) { exit 7 }
    $out = New-Object System.Text.StringBuilder
    [void]$out.Append("level`tpage_num`tblock_num`tpar_num`tline_num`tword_num`tleft`ttop`twidth`theight`tconf`ttext`n")
    $page = 0
    foreach ($tag in ($Languages -split ',')) {
        if ($tag -notmatch '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$') { exit 8 }
        $language = New-Object Windows.Globalization.Language($tag)
        if (-not [Windows.Media.Ocr.OcrEngine]::IsLanguageSupported($language)) { exit 9 }
        $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($language)
        if ($null -eq $engine) { exit 9 }
        $page++
        $result = Wait-Op ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
        $lineNo = 0
        foreach ($line in $result.Lines) {
            $lineNo++; $wordNo = 0
            foreach ($word in $line.Words) {
                $text = ($word.Text -replace '\s', '')
                if ($text.Length -eq 0) { continue }
                $wordNo++
                $r = $word.BoundingRect
                $x = [Math]::Max(0, [int][Math]::Floor($r.X)); $y = [Math]::Max(0, [int][Math]::Floor($r.Y))
                $right = [Math]::Min($width, [int][Math]::Ceiling($r.X + $r.Width)); $bottom = [Math]::Min($height, [int][Math]::Ceiling($r.Y + $r.Height))
                if ($right -le $x -or $bottom -le $y) { continue }
                [void]$out.Append("5`t$page`t1`t1`t$lineNo`t$wordNo`t$x`t$y`t$($right - $x)`t$($bottom - $y)`t$Confidence`t$text`n")
            }
        }
    }
    if ($page -eq 0) { exit 9 }
    $encoded = (New-Object System.Text.UTF8Encoding($false)).GetBytes($out.ToString())
    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($encoded, 0, $encoded.Length)
    $stdout.Flush()
    exit 0
} catch {
    # Never print exception text: it can contain paths. The worker maps a non-zero exit to IMAGE_OCR_FAILED.
    exit 2
}
