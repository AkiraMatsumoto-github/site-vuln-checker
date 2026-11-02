# ストア用のプロモ画像を、用意したヒーロー画像から作る（Windows / PowerShell）
#
#   pwsh -File tools/make_promo_from_source.ps1
#
# 入力: store/source/hero*.jpg（ヒーロー画像。1296x816 など）
# 出力: store/promo-440x280.png（小さいプロモ画像 440x280）
#
# 元画像の比率が 440:280 に近ければ**ほぼ全体**を縮小する（中央でわずかに切るだけ）。
# かけ離れている場合だけ、中央を切って比率を合わせる（文字が切れるので注意）。

Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
$store = Join-Path $root 'store'
$source = Get-ChildItem (Join-Path $store 'source') -Filter 'hero*.jpg' | Select-Object -First 1
if (-not $source) { throw 'store/source/hero*.jpg が見つかりません' }

$targetWidth = 440
$targetHeight = 280
$targetRatio = $targetWidth / $targetHeight

$image = [System.Drawing.Image]::FromFile($source.FullName)
$sourceRatio = $image.Width / $image.Height

if ($sourceRatio -gt $targetRatio) {
    # 横長すぎる → 左右を均等に切る
    $cropHeight = $image.Height
    $cropWidth = [int][Math]::Round($image.Height * $targetRatio)
} else {
    # 縦長すぎる → 上下を均等に切る
    $cropWidth = $image.Width
    $cropHeight = [int][Math]::Round($image.Width / $targetRatio)
}
$cropX = [int][Math]::Round(($image.Width - $cropWidth) / 2)
$cropY = [int][Math]::Round(($image.Height - $cropHeight) / 2)

$canvas = New-Object System.Drawing.Bitmap $targetWidth, $targetHeight, ([System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$g = [System.Drawing.Graphics]::FromImage($canvas)
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$g.DrawImage(
    $image,
    (New-Object System.Drawing.Rectangle 0, 0, $targetWidth, $targetHeight),
    (New-Object System.Drawing.Rectangle $cropX, $cropY, $cropWidth, $cropHeight),
    [System.Drawing.GraphicsUnit]::Pixel)
$out = Join-Path $store 'promo-440x280.png'
$canvas.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $canvas.Dispose(); $image.Dispose()

"$out  ($($source.Name): ${cropWidth}x${cropHeight} from ($cropX,$cropY) -> ${targetWidth}x${targetHeight})"
Get-Item $out | Select-Object Name, Length | Format-Table -AutoSize
