# ストア用スクリーンショット（1280x800）を作る（Windows / PowerShell）
#
#   pwsh -File tools/make_store_screenshots.ps1
#
# 入力: store/screenshots/*-raw.png（実際の画面から切り抜いたパネル）
# 出力: store/screenshots/NN-*-1280x800.png
#       Chrome ウェブストアの要件は 1280x800 または 640x400（JPEG / 24bit PNG・最大 5 枚）
#
# 素材をそのまま拡大するのではなく、ブランド色の背景に **見出し＋パネル** を組む
# （パネルは縦横比を保って、拡大は 1.6 倍まで。それ以上は文字がぼやける）。

Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $root 'store\screenshots'

$canvasW = 1280
$canvasH = 800
$marginX = 78
$titleY = 40
$subtitleY = 100
$panelTop = 164
$panelAreaW = $canvasW - 2 * $marginX      # 1124
$panelAreaH = $canvasH - $panelTop - 36    # 600
$maxScale = 1.6

# src  = 素材（*-raw.png）／crop = 素材内の切り抜き範囲（省略時は全体）
$slides = @(
    @{ src = '11-result-red-raw.png'; out = '01-red-1280x800.png';
        title = '危険な構成はひと目で分かる';
        sub = 'サポート終了や攻撃実績のある製品を、危険度つきで表示します' },
    @{ src = '12-result-green-gray-raw.png'; out = '02-green-info-gray-1280x800.png';
        title = '問題なし・情報・不明を色で区別';
        sub = '判定できないものは「不明」として分け、根拠も確認できます' },
    @{ src = '13-composition-raw.png'; out = '03-composition-1280x800.png';
        title = '構成と Version を一覧で';
        sub = '検出した製品・Version・精度（確かさ）・根拠をまとめて表示' },
    @{ src = '03-site-health.png'; out = '04-sitehealth-1280x800.png';
        title = 'WordPress の管理者なら、構成・Version を取得可能';
        sub = 'サイトヘルスページから、プラグインを含む具体的な情報を読み取ります';
        crop = @{ x = 0; y = 0; w = 1020; h = 827 } }
)

function New-FontFamily([string[]]$names) {
    foreach ($name in $names) {
        try { return [System.Drawing.FontFamily]::new($name) } catch { }
    }
    throw "日本語フォントが見つかりません: $($names -join ', ')"
}

$family = New-FontFamily @('Yu Gothic UI', 'Meiryo UI', 'Noto Sans JP')
$titleBaseSize = 40
$subtitleBaseSize = 22
$textMaxWidth = [single]($panelAreaW)
$measureFormat = [System.Drawing.StringFormat]::GenericTypographic
$titleBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(18, 56, 95))
$subtitleBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(70, 104, 140))
$borderPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(195, 216, 238), 1)
$shadowBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(26, 20, 60, 110))

# 幅に収まる最大の文字サイズを返す（長い見出しでもはみ出さない）
function Get-FittedSize($graphics, [string]$text, $style, [single]$baseSize, [single]$maxWidth) {
    $probe = [System.Drawing.Font]::new($family, $baseSize, $style, [System.Drawing.GraphicsUnit]::Pixel)
    $width = $graphics.MeasureString($text, $probe, 10000, $measureFormat).Width
    $probe.Dispose()
    if ($width -le $maxWidth -or $width -le 0) { return $baseSize }
    return [single][Math]::Floor($baseSize * $maxWidth / $width)
}

foreach ($slide in $slides) {
    $srcPath = Join-Path $dir $slide.src
    if (-not (Test-Path -LiteralPath $srcPath)) { throw "素材がありません: $srcPath" }
    $image = [System.Drawing.Image]::FromFile($srcPath)

    if ($slide.crop) {
        $srcRect = New-Object System.Drawing.Rectangle $slide.crop.x, $slide.crop.y, $slide.crop.w, $slide.crop.h
    } else {
        $srcRect = New-Object System.Drawing.Rectangle 0, 0, $image.Width, $image.Height
    }

    $scale = [Math]::Min([Math]::Min($panelAreaW / $srcRect.Width, $panelAreaH / $srcRect.Height), $maxScale)
    $panelW = [int][Math]::Round($srcRect.Width * $scale)
    $panelH = [int][Math]::Round($srcRect.Height * $scale)
    $panelX = [int][Math]::Round(($canvasW - $panelW) / 2)

    $canvas = New-Object System.Drawing.Bitmap $canvasW, $canvasH, ([System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $g = [System.Drawing.Graphics]::FromImage($canvas)
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    # 背景（上から下へ淡いブルー）
    $bg = [System.Drawing.Drawing2D.LinearGradientBrush]::new(
        (New-Object System.Drawing.Rectangle 0, 0, $canvasW, $canvasH),
        [System.Drawing.Color]::FromArgb(247, 251, 255),
        [System.Drawing.Color]::FromArgb(224, 236, 249),
        90)
    $g.FillRectangle($bg, 0, 0, $canvasW, $canvasH)

    # 見出し（幅に収まるよう自動で縮小）
    $titleSize = Get-FittedSize $g $slide.title ([System.Drawing.FontStyle]::Bold) $titleBaseSize $textMaxWidth
    $subSize = Get-FittedSize $g $slide.sub ([System.Drawing.FontStyle]::Regular) $subtitleBaseSize $textMaxWidth
    $titleFont = [System.Drawing.Font]::new($family, $titleSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $subtitleFont = [System.Drawing.Font]::new($family, $subSize, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    $g.DrawString($slide.title, $titleFont, $titleBrush, [single]$marginX, [single]$titleY)
    $g.DrawString($slide.sub, $subtitleFont, $subtitleBrush, [single]$marginX, [single]$subtitleY)
    $titleFont.Dispose(); $subtitleFont.Dispose()

    # パネル（影 → 本体 → 枠線）
    $g.FillRectangle($shadowBrush, $panelX + 3, $panelTop + 5, $panelW, $panelH)
    $destRect = New-Object System.Drawing.Rectangle $panelX, $panelTop, $panelW, $panelH
    $g.DrawImage($image, $destRect, $srcRect, [System.Drawing.GraphicsUnit]::Pixel)
    $g.DrawRectangle($borderPen, $panelX, $panelTop, $panelW - 1, $panelH - 1)

    $outPath = Join-Path $dir $slide.out
    $canvas.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)

    $bg.Dispose(); $g.Dispose(); $canvas.Dispose(); $image.Dispose()
    "{0,-36} <- {1} ({2}x{3}, x{4:N2} -> {5}x{6})" -f $slide.out, $slide.src, $srcRect.Width, $srcRect.Height, $scale, $panelW, $panelH
}

$titleBrush.Dispose(); $subtitleBrush.Dispose(); $borderPen.Dispose(); $shadowBrush.Dispose()
"done: $dir"
