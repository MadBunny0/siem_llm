# patch_docx.ps1 — вставка скриншотов живого прогона С1 (2026-11-18) в vkr.docx §4.5.
# Исходник: vkr-out/vkr_backup.docx (оригинал пользователя) -> vkr-out/vkr_screenshots.docx
# Рис. 4.5 (сформированный инцидент)  : rId18 -> rId31 -> media/image16.png = run1/b11b9455...png (карточка #1: critical, риск 100/100, Оценка критичности)
# Рис. 4.6 (результат анализа LLM)    : rId19 #1 -> rId32 -> media/image17.png = run1/42cc89ae...png (Результат анализа: Pending, monitor)
# Рис. 4.7 (проверка DVE)             : rId19 #2 -> rId33 -> media/image18.png = run1/5010c36a...png (Предложенные действия, проверка DVE)
# Прежние media (image14/image15) остаются в пакете нессылочными (не удаляем — директива «не удалять»).
$ErrorActionPreference = 'Stop'
$root  = 'E:\VScodeProjects\siem_llm'
$src   = Join-Path $root 'vkr-out\vkr_backup.docx'
$out   = Join-Path $root 'vkr-out\vkr_screenshots.docx'
$run1  = Join-Path $root 'analysis\run1'
$enc   = New-Object System.Text.UTF8Encoding($false)  # без BOM
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Read-PngSize([string]$p) {
  $b = [System.IO.File]::ReadAllBytes($p)
  if ($b[0] -ne 0x89 -or $b[1] -ne 0x50) { throw "not a PNG: $p" }
  $w = ([int]$b[16] -shl 24) -bor ([int]$b[17] -shl 16) -bor ([int]$b[18] -shl 8) -bor [int]$b[19]
  $h = ([int]$b[20] -shl 24) -bor ([int]$b[21] -shl 16) -bor ([int]$b[22] -shl 8) -bor [int]$b[23]
  [pscustomobject]@{ w = $w; h = $h }
}
function Assert-Count([string]$text, [string]$pattern, [int]$expected, [string]$what) {
  $n = ([regex]::Matches($text, [regex]::Escape($pattern))).Count
  if ($n -ne $expected) { throw "ASSERT $what : found $n, expected $expected ($pattern)" }
  Write-Host "  ok: $what x$n"
}

# --- целевые изображения и их новые размеры отображения (EMU) ---
$f45 = Join-Path $run1 'b11b94555b7c3e2910cffb4be83ec47a.png'
$f46 = Join-Path $run1 '42cc89ae6f4a4e722401bc5bb65963ab.png'
$f47 = Join-Path $run1 '5010c36a4a68a7d1bab45fbed610b129.png'
$s45 = Read-PngSize $f45; $s46 = Read-PngSize $f46; $s47 = Read-PngSize $f47
$w45 = 3600000; $h45 = [int][math]::Round($w45 * [double]$s45.h / [double]$s45.w)   # 10 x ~13.2 см
$w46 = 3600000; $h46 = [int][math]::Round($w46 * [double]$s46.h / [double]$s46.w)   # 10 x ~10.9 см
$w47 = 5040000; $h47 = [int][math]::Round($w47 * [double]$s47.h / [double]$s47.w)   # 14 x ~10.9 см
Write-Host ("PNG: 4.5 {0}x{1} -> {2}x{3} EMU; 4.6 {4}x{5} -> {6}x{7}; 4.8 {8}x{9} -> {10}x{11}" -f $s45.w,$s45.h,$w45,$h45,$s46.w,$s46.h,$w46,$h46,$s47.w,$s47.h,$w47,$h47)

$fs = [System.IO.File]::OpenRead($src)
try {
  $zin = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read)

  function Get-EntryText([System.IO.Compression.ZipArchive]$z, [string]$name) {
    $e = $z.GetEntry($name); if (-not $e) { throw "missing entry: $name" }
    $ms = New-Object System.IO.MemoryStream
    $e.Open().CopyTo($ms); $ms.ToArray()
  }

  $docBytes  = Get-EntryText $zin 'word/document.xml'
  $relsBytes = Get-EntryText $zin 'word/_rels/document.xml.rels'
  $ctBytes   = Get-EntryText $zin '[Content_Types].xml'
  $d    = $enc.GetString($docBytes)
  $rels = $enc.GetString($relsBytes)
  $ct   = $enc.GetString($ctBytes)

  Write-Host 'Проверка исходных строк:'
  Assert-Count $d 'r:embed="rId18"' 1 'blip рис.4.5 (rId18)'
  Assert-Count $d 'r:embed="rId19"' 2 'blip рис.4.6/4.7 (rId19, дубль)'
  Assert-Count $d 'cx="6120130" cy="3051175"' 2 'размеры рис.4.5 (wp:extent + a:ext)'
  Assert-Count $d 'cx="5177885" cy="3091560"' 1 'wp:extent рис.4.6 (старый)'
  Assert-Count $d 'cx="5222664" cy="3118296"' 1 'a:ext рис.4.6 (старый)'
  Assert-Count $d 'cx="5763895" cy="5827923"' 2 'размеры рис.4.7 (wp:extent + a:ext)'
  if ($ct -notmatch 'Extension="png"') { throw '[Content_Types].xml: нет Default для png' }
  foreach ($id in 31..33) { if ($rels -match "Id=`"rId$id`"") { throw "rId$id уже занят в rels" } }
  Write-Host '  ok: png в Content_Types; rId31-33 свободны'

  # --- замены в document.xml ---
  $new45 = "cx=`"$w45`" cy=`"$h45`""
  $new46 = "cx=`"$w46`" cy=`"$h46`""
  $new47 = "cx=`"$w47`" cy=`"$h47`""
  $d = $d.Replace('r:embed="rId18"', 'r:embed="rId31"')
  $i1 = $d.IndexOf('r:embed="rId19"')
  if ($i1 -lt 0) { throw 'rId19 #1 not found' }
  $d = $d.Remove($i1, 15).Insert($i1, 'r:embed="rId32"')
  $i2 = $d.IndexOf('r:embed="rId19"', $i1 + 15)
  if ($i2 -lt 0) { throw 'rId19 #2 not found' }
  $d = $d.Remove($i2, 15).Insert($i2, 'r:embed="rId33"')
  $d = $d.Replace('cx="6120130" cy="3051175"', $new45)
  $d = $d.Replace('cx="5177885" cy="3091560"', $new46)
  $d = $d.Replace('cx="5222664" cy="3118296"', $new46)
  $d = $d.Replace('cx="5763895" cy="5827923"', $new47)
  Write-Host 'document.xml: blips rId31/rId32/rId33 + размеры заменены'

  # --- связи ---
  $ins  = '<Relationship Id="rId31" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image16.png"/>'
  $ins += '<Relationship Id="rId32" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image17.png"/>'
  $ins += '<Relationship Id="rId33" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image18.png"/>'
  Assert-Count $rels '</Relationships>' 1 'конец rels'
  $rels = $rels.Replace('</Relationships>', $ins + '</Relationships>')

  # --- сборка нового zip (порядок записей исходника сохранён, медиа добавлены в конец) ---
  if (Test-Path $out) { Remove-Item $out -Force }
  $fos = [System.IO.File]::Open($out, [System.IO.FileMode]::CreateNew)
  try {
    $zout = New-Object System.IO.Compression.ZipArchive($fos, [System.IO.Compression.ZipArchiveMode]::Create)
    foreach ($e in $zin.Entries) {
      $ne = $zout.CreateEntry($e.FullName, [System.IO.Compression.CompressionLevel]::Optimal)
      $st = $ne.Open()
      if ($e.FullName -eq 'word/document.xml')     { $b = $enc.GetBytes($d) }
      elseif ($e.FullName -eq 'word/_rels/document.xml.rels') { $b = $enc.GetBytes($rels) }
      else { $ms = New-Object System.IO.MemoryStream; $e.Open().CopyTo($ms); $b = $ms.ToArray() }
      $st.Write($b, 0, $b.Length); $st.Dispose()
    }
    foreach ($pair in @(@('word/media/image16.png', $f45), @('word/media/image17.png', $f46), @('word/media/image18.png', $f47))) {
      $ne = $zout.CreateEntry($pair[0], [System.IO.Compression.CompressionLevel]::Optimal)
      $st = $ne.Open()
      $b = [System.IO.File]::ReadAllBytes($pair[1]); $st.Write($b, 0, $b.Length); $st.Dispose()
    }
    $zout.Dispose()
  } finally { $fos.Dispose() }
  $zin.Dispose()
} finally { $fs.Dispose() }

Write-Host "ГОТОВО: $out ($((Get-Item $out).Length) bytes)"
