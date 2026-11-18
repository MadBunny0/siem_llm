# patch_docx_c2c3.ps1 — вставка скриншотов прогонов С2/С3 в vkr.docx §4.5 (рис. 4.8–4.11)
# + один новый абзац со ссылками на них. Существующий текст не модифицируется.
# Источник: корневой vkr.docx (уже с рис. 4.5–4.7 от С1) -> vkr-out/vkr_c2c3.docx
# Медиа: image19..22.png (run2/03, run2/12, run3/02, run3/09), связи rId34..37.
# Вставка ПЕРЕД абзацем-заголовком «4.6 Анализ результатов реализации» (якорь w14:paraId="0560A2C1").
$ErrorActionPreference = 'Stop'
$root = 'E:\VScodeProjects\siem_llm'
$src  = Join-Path $root 'vkr.docx'
$out  = Join-Path $root 'vkr-out\vkr_c2c3.docx'
$enc  = New-Object System.Text.UTF8Encoding($false)
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
  if ($n -ne $expected) { throw "ASSERT $what : found $n, expected $expected" }
  Write-Host "  ok: $what x$n"
}

# (файл, mediaName, relId, docPrId, подпись)
$figs = @(
  @{ png = Join-Path $root 'analysis\run2\03_card_top.png';            media = 'image19.png'; rel = 'rId34'; id = 700000001; cap = 'Отображение сформированного инцидента при веб-атаке (SQL-инъекция)' },
  @{ png = Join-Path $root 'analysis\run2\12_responses_vm_tab.png';    media = 'image20.png'; rel = 'rId35'; id = 700000002; cap = 'Результат блокирования IP-адреса источника веб-атаки' },
  @{ png = Join-Path $root 'analysis\run3\02_card_top.png';            media = 'image21.png'; rel = 'rId36'; id = 700000003; cap = 'Отображение сформированного инцидента при создании бэкдор-аккаунта' },
  @{ png = Join-Path $root 'analysis\run3\09_responses_vm_tab.png';    media = 'image22.png'; rel = 'rId37'; id = 700000004; cap = 'Результат блокирования учётной записи svc_helper' }
)
foreach ($f in $figs) {
  $s = Read-PngSize $f.png
  if ($s.w -ne 1908 -or $s.h -ne 930) { throw "unexpected PNG size $($s.w)x$($s.h): $($f.png)" }
  $f.cx = 6120130
  $f.cy = [int][math]::Round(6120130.0 * [double]$s.h / [double]$s.w)
  Write-Host ("  ok: {0} {1}x{2} -> {3}x{4} EMU" -f (Split-Path $f.png -Leaf), $s.w, $s.h, $f.cx, $f.cy)
}

$fs = [System.IO.File]::OpenRead($src)
try {
  $zin = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read)
  function Get-EntryText([System.IO.Compression.ZipArchive]$z, [string]$name) {
    $e = $z.GetEntry($name); if (-not $e) { throw "missing entry: $name" }
    $ms = New-Object System.IO.MemoryStream; $e.Open().CopyTo($ms); $ms.ToArray()
  }
  $docBytes  = Get-EntryText $zin 'word/document.xml'
  $relsBytes = Get-EntryText $zin 'word/_rels/document.xml.rels'
  $d    = $enc.GetString($docBytes)
  $rels = $enc.GetString($relsBytes)

  Write-Host 'Проверка исходных строк:'
  $anchor = '<w:p w14:paraId="0560A2C1"'
  Assert-Count $d $anchor 1 'якорь заголовка 4.6'
  foreach ($i in 34..37) { if ($rels -match "Id=`"rId$i`"") { throw "rId$i занят" } }
  Assert-Count $d 'wp:docPr id="70000000' 0 'docPr 700000001-4 свободны'
  Write-Host '  ok: rId34-37 свободны'

  # --- новый абзац текста + 4 блока (рисунок + подпись) ---
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('<w:p><w:pPr><w:spacing w:line="360" w:lineRule="auto"/><w:ind w:firstLine="708"/><w:jc w:val="both"/><w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:pPr><w:r><w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr><w:t xml:space="preserve">Для подтверждения применимости метода к иным классам атак на том же экспериментальном стенде были выполнены два дополнительных сценария. В первом моделировалась веб-атака (SQL-инъекция) на веб-сервис, размещённый на критичном сервере: инцидент сформирован корреляцией через несколько секунд после запросов (рисунок 4.8), реакция блокирования IP-адреса источника исполнена через Wazuh active response и подтверждена на виртуальной машине (рисунок 4.9). Во втором моделировались действия инсайдера — создание бэкдор-учётной записи непосредственно на сервере: инцидент сформирован по единственному событию (рисунок 4.10), реакция отключения учётной записи исполнена с целью, извлечённой из событий инцидента, и подтверждена физически (рисунок 4.11).</w:t></w:r></w:p>')
  $n = 8
  foreach ($f in $figs) {
    $inline = ('<w:p><w:pPr><w:spacing w:line="360" w:lineRule="auto"/><w:jc w:val="center"/></w:pPr><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{0}" cy="{1}"/><wp:effectExtent l="0" t="0" r="0" b="0"/><wp:docPr id="{2}" name="Рисунок {5}"/><wp:cNvGraphicFramePr><a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" noChangeAspect="1"/></wp:cNvGraphicFramePr><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="{2}" name="Рисунок {5}"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="{3}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{0}" cy="{1}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>' -f $f.cx, $f.cy, $f.id, $f.rel, $f.media, $n)
    [void]$sb.Append($inline)
    $cap = ('<w:p><w:pPr><w:spacing w:line="360" w:lineRule="auto"/><w:ind w:firstLine="708"/><w:jc w:val="center"/><w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:pPr><w:r><w:rPr><w:b/><w:bCs/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr><w:t>Рисунок 4.{5} — {4}</w:t></w:r></w:p>' -f $f.cx, $f.cy, $f.id, $f.rel, $f.cap, $n)
    [void]$sb.Append($cap)
    $n++
  }
  $block = $sb.ToString()

  $d = $d.Replace($anchor, $block + $anchor)
  Write-Host 'document.xml: блок (абзац + 4 рисунка + 4 подписи) вставлен перед 4.6'

  $relLines = ''
  foreach ($f in $figs) {
    $relLines += ('<Relationship Id="{0}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/{1}"/>' -f $f.rel, $f.media)
  }
  Assert-Count $rels '</Relationships>' 1 'конец rels'
  $rels = $rels.Replace('</Relationships>', $relLines + '</Relationships>')

  if (Test-Path $out) { Remove-Item $out -Force }
  $fos = [System.IO.File]::Open($out, [System.IO.FileMode]::CreateNew)
  try {
    $zout = New-Object System.IO.Compression.ZipArchive($fos, [System.IO.Compression.ZipArchiveMode]::Create)
    foreach ($e in $zin.Entries) {
      $ne = $zout.CreateEntry($e.FullName, [System.IO.Compression.CompressionLevel]::Optimal)
      $st = $ne.Open()
      if ($e.FullName -eq 'word/document.xml') { $b = $enc.GetBytes($d) }
      elseif ($e.FullName -eq 'word/_rels/document.xml.rels') { $b = $enc.GetBytes($rels) }
      else { $ms = New-Object System.IO.MemoryStream; $e.Open().CopyTo($ms); $b = $ms.ToArray() }
      $st.Write($b, 0, $b.Length); $st.Dispose()
    }
    foreach ($f in $figs) {
      $ne = $zout.CreateEntry('word/media/' + $f.media, [System.IO.Compression.CompressionLevel]::Optimal)
      $st = $ne.Open()
      $b = [System.IO.File]::ReadAllBytes($f.png); $st.Write($b, 0, $b.Length); $st.Dispose()
    }
    $zout.Dispose()
  } finally { $fos.Dispose() }
  $zin.Dispose()
} finally { $fs.Dispose() }

# --- верификация результата ---
$vf = [System.IO.File]::OpenRead($out)
try {
  $vz = New-Object System.IO.Compression.ZipArchive($vf, [System.IO.Compression.ZipArchiveMode]::Read)
  $ms = New-Object System.IO.MemoryStream; $vz.GetEntry('word/document.xml').Open().CopyTo($ms); $ms.Position = 0
  $x = New-Object System.Xml.XmlDocument; $x.Load($ms)
  Write-Host ("  ok: document.xml well-formed ({0} байт)" -f $ms.Length)
  $ms2 = New-Object System.IO.MemoryStream; $vz.GetEntry('word/_rels/document.xml.rels').Open().CopyTo($ms2); $ms2.Position = 0
  $x2 = New-Object System.Xml.XmlDocument; $x2.Load($ms2)
  Write-Host '  ok: rels well-formed'
  $vd = $enc.GetString((Get-EntryText $vz 'word/document.xml'))
  Assert-Count $vd 'Рисунок 4.8' 1 'подпись 4.8'
  Assert-Count $vd 'Рисунок 4.9' 1 'подпись 4.9'
  Assert-Count $vd 'Рисунок 4.10' 1 'подпись 4.10'
  Assert-Count $vd 'Рисунок 4.11' 1 'подпись 4.11'
  Assert-Count $vd 'r:embed="rId34"' 1 'blip 4.8'
  Assert-Count $vd 'r:embed="rId37"' 1 'blip 4.11'
  Assert-Count $vd '<wp:docPr' 20 'всего inline-рисунков (16 было + 4 новых)'
  $vz.Dispose()
} finally { $vf.Dispose() }

Write-Host "ГОТОВО: $out ($((Get-Item $out).Length) bytes)"
