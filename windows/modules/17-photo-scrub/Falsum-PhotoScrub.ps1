<#---------------------------------------------------------------------------
Falsum Photo Scrub — EXIF/metadata viewer and scrubber.
Pure PowerShell 5.1. Zero external dependencies. Windows 10/11.

WHAT IT DOES
  - Reads JPEG EXIF by parsing the APP1/TIFF structure directly (no GDI+,
    no image decode): camera, timestamps, GPS coordinates, software tags.
    Follows the EXIF sub-IFD pointer (0x8769) so DateTimeOriginal and other
    EXIF-IFD tags actually parse (v1 shipped the tags in the table but
    never walked the pointer — they silently never appeared).
  - Reads PNG tEXt/iTXt/zTXt/eXIf chunks (zTXt decompressed via DeflateStream).
  - Detects WebP and reports VP8X container flags (EXIF/XMP/ICC) honestly
    as flags only — full WebP chunk walk is not implemented.
  - THE FIX (Better-Way Law): Clear-PhotoMetadata strips JPEG APPn/COM
    segments AND rebuilds PNGs without metadata chunks (CRC32 recomputed),
    writes a clean copy, then RE-PARSES the output to prove the metadata
    is gone. A scrub without verification is a claim.
  - Get-PhotoRisk scores exposure: GPS present = High, camera/owner serial
    numbers and MakerNote flagged (serials are the real tracking leak),
    timestamps = Medium.

v1.2 hardened 2026-10-30 (cron run): EXIF sub-IFD follow fix, SOS stop in
the JPEG walker, iTXt/zTXt/eXIf PNG parsing, Clear-PngMetadata with CRC32
recompute + verify, WebP flag detection, expanded tag table (serial/owner/
lens tags), richer risk scoring, hygiene battery 7 -> 20 checks.

WHY IT MATTERS (problems 1301-1350)
  - A photo posted online carries where you were (GPS), when (timestamps),
    and with what (camera serial in MakerNote). Scrubbing before sharing
    is the fix; viewing first is how you learn what's leaking.

BUILT 2026-10-30 by the main agent, in-chat, per Gregg's order.
----------------------------------------------------------------------------#>

$script:ExifTags = @{
    0x010E="ImageDescription"; 0x010F="Make"; 0x0110="Model"; 0x0131="Software";
    0x0132="DateTime"; 0x013B="Artist"; 0x8298="Copyright";
    0x9003="DateTimeOriginal"; 0x9004="DateTimeDigitized";
    0x9286="UserComment"; 0x927C="MakerNote";
    0x829A="ExposureTime"; 0x8827="ISOSpeed"; 0xA002="PixelXDimension"; 0xA003="PixelYDimension";
    0xA430="OwnerName"; 0xA431="CameraSerialNumber"; 0xA432="LensSerialNumber";
    0xA433="LensMake"; 0xA434="LensModel"
    # NOTE: 0x8769 (EXIF sub-IFD pointer) and 0x8825 (GPS IFD pointer) are
    # followed by Read-ExifIfd and never need table rows.
}
$script:GpsTags = @{
    0x00="GPSVersionID"; 0x01="GPSLatitudeRef"; 0x02="GPSLatitude";
    0x03="GPSLongitudeRef"; 0x04="GPSLongitude"; 0x06="GPSAltitude";
    0x1D="GPSDateStamp"
}

function Read-U16 { param([byte[]]$B,[int]$O,[bool]$LE) if ($LE) { return [BitConverter]::ToUInt16($B,$O) } else { return [uint16](($B[$O] -shl 8) -bor $B[$O+1]) } }
function Read-U32 { param([byte[]]$B,[int]$O,[bool]$LE) if ($LE) { return [BitConverter]::ToUInt32($B,$O) } else { return [uint32](($B[$O] -shl 24) -bor ($B[$O+1] -shl 16) -bor ($B[$O+2] -shl 8) -bor $B[$O+3]) } }

function Get-ExifValue {
    param([byte[]]$Tiff,[int]$EntryOff,[int]$TiffStart,[bool]$LE)
    $tag   = Read-U16 $Tiff $EntryOff $LE
    $type  = Read-U16 $Tiff ($EntryOff+2) $LE
    $count = Read-U32 $Tiff ($EntryOff+4) $LE
    $valOff= $EntryOff + 8
    $typeSize = @{1=1;2=1;3=2;4=4;5=8;7=1;9=4;10=8}[$type]
    if (-not $typeSize) { return @{Tag=$tag;Value="<type $type>"} }
    $total = $typeSize * $count
    $dataOff = $valOff
    if ($total -gt 4) { $dataOff = $TiffStart + (Read-U32 $Tiff $valOff $LE) }
    $val = $null
    try {
        switch ($type) {
            2 {
                $raw = $Tiff[$dataOff..($dataOff+[Math]::Min($count,4096)-1)]
                $val = ([System.Text.Encoding]::ASCII.GetString($raw)).Trim("`0")
            }
            3 { $val = Read-U16 $Tiff $dataOff $LE }
            4 { $val = Read-U32 $Tiff $dataOff $LE }
            5 {
                $vals = @()
                for ($i=0; $i -lt [Math]::Min($count,8); $i++) {
                    $n = Read-U32 $Tiff ($dataOff+$i*8) $LE
                    $d = Read-U32 $Tiff ($dataOff+$i*8+4) $LE
                    if ($d -eq 0) { $vals += "0" } else { $vals += ("{0}/{1}={2:N6}" -f $n,$d,([double]$n/[double]$d)) }
                }
                $val = $vals -join ", "
            }
            default { $val = "<$total bytes>" }
        }
    } catch { $val = "<read error>" }
    return @{Tag=$tag;Value=$val;RawOffset=$dataOff}
}

function Read-ExifIfd {
    param([byte[]]$Tiff,[int]$IfdOff,[int]$TiffStart,[bool]$LE,[hashtable]$TagNames,[int]$Depth=0)
    $found = @{}
    if ($Depth -gt 2) { return $found }  # malformed self-referential IFDs stop here
    try {
        $n = Read-U16 $Tiff ($TiffStart+$IfdOff) $LE
        if ($n -gt 200) { return $found }  # sanity: no real IFD has 200+ entries
        for ($i=0; $i -lt $n; $i++) {
            $e = Get-ExifValue $Tiff ($TiffStart+$IfdOff+2+$i*12) $TiffStart $LE
            $name = if ($TagNames.ContainsKey($e.Tag)) { $TagNames[$e.Tag] } else { "Tag_0x{0:X4}" -f $e.Tag }
            $found[$name] = $e.Value
            if (($e.Tag -eq 0x8825 -or $e.Tag -eq 0x8769) -and ("$($e.Value)" -match '^\d+$')) {
                # 0x8825 = GPS IFD pointer, 0x8769 = EXIF sub-IFD pointer (LONG type:
                # the value IS the offset). v1 never followed 0x8769, so
                # DateTimeOriginal and friends silently never parsed.
                $subOff = [int]$e.Value
                if ($subOff -gt 8 -and ($TiffStart + $subOff) -lt ($Tiff.Length - 2)) {
                    $subNames = if ($e.Tag -eq 0x8825) { $script:GpsTags } else { $script:ExifTags }
                    $sub = Read-ExifIfd $Tiff $subOff $TiffStart $LE $subNames ($Depth+1)
                    foreach ($k in $sub.Keys) {
                        if ($e.Tag -eq 0x8825) { $found["GPS_$k"] = $sub[$k] } else { $found[$k] = $sub[$k] }
                    }
                }
            }
        }
    } catch { }
    return $found
}

function Get-TiffMeta {
    <#
    .SYNOPSIS Parses a TIFF header (EXIF) at a byte offset: byte order,
    magic 42, IFD0, EXIF sub-IFD, GPS IFD. Shared by JPEG APP1 and PNG eXIf.
    #>
    param([byte[]]$Bytes,[int]$Start)
    $meta = @{}
    try {
        if ($Start + 8 -gt $Bytes.Length) { return $meta }
        $bo = [System.Text.Encoding]::ASCII.GetString($Bytes[$Start..($Start+1)])
        if ($bo -ne "II" -and $bo -ne "MM") { return $meta }
        $le = $bo -eq "II"
        if ((Read-U16 $Bytes $Start $le) -ne 42) { return $meta }
        $ifd0 = Read-U32 $Bytes ($Start+4) $le
        $ifd = Read-ExifIfd $Bytes $ifd0 $Start $le $script:ExifTags
        foreach ($k in $ifd.Keys) { $meta[$k] = $ifd[$k] }
    } catch { }
    return $meta
}

$script:Crc32Table = $null
function Get-Crc32Table {
    if ($script:Crc32Table) { return $script:Crc32Table }
    $t = New-Object uint32[] 256
    for ($n=0; $n -lt 256; $n++) {
        $c = [uint32]$n
        for ($k=0; $k -lt 8; $k++) {
            if (($c -band 1) -eq 1) { $c = [uint32]3988292384 -bxor ($c -shr 1) } else { $c = $c -shr 1 }
        }
        $t[$n] = $c
    }
    $script:Crc32Table = $t
    return $t
}

function Get-Crc32 {
    <#
    .SYNOPSIS Pure CRC-32 (ISO 3309, the PNG chunk checksum). Table-driven,
    no dependencies. Test vector: "123456789" -> 0xCBF43926.
    #>
    param([byte[]]$Data)
    $table = Get-Crc32Table
    $crc = [uint32]4294967295
    foreach ($b in $Data) {
        $crc = $table[($crc -bxor $b) -band 0xFF] -bxor ($crc -shr 8)
    }
    return ($crc -bxor [uint32]4294967295)
}

function Expand-ZlibDeflate {
    <#
    .SYNOPSIS Decompresses a zlib-wrapped deflate payload (PNG zTXt, iTXt
    compressed form). Skips the 2-byte zlib header; the adler32 trailer is
    not required. Returns $null on failure.
    #>
    param([byte[]]$Data)
    try {
        if ($Data.Length -lt 8) { return $null }
        $ms = New-Object System.IO.MemoryStream(, $Data)
        $ms.Position = 2
        $ds = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
        $out = New-Object System.IO.MemoryStream
        $ds.CopyTo($out)
        $ds.Close(); $ms.Close()
        return $out.ToArray()
    } catch { return $null }
}

function Get-PngITxtFields {
    <#
    .SYNOPSIS Parses one iTXt chunk data area: keyword, compression flag,
    language tag, translated keyword, text (UTF-8, decompressed if flagged).
    #>
    param([byte[]]$Data)
    $fields = @{}
    try {
        $z1 = [Array]::IndexOf($Data, [byte]0, 0)
        if ($z1 -le 0) { return $fields }
        $keyword = [System.Text.Encoding]::GetEncoding("ISO-8859-1").GetString($Data[0..($z1-1)])
        $p = $z1 + 1
        if ($p + 1 -ge $Data.Length) { return $fields }
        $compFlag = $Data[$p]; $p += 2
        $z2 = [Array]::IndexOf($Data, [byte]0, $p)
        if ($z2 -lt 0) { return $fields }
        $p = $z2 + 1
        $z3 = [Array]::IndexOf($Data, [byte]0, $p)
        if ($z3 -lt 0) { return $fields }
        $p = $z3 + 1
        if ($p -ge $Data.Length) { return $fields }
        $textBytes = $Data[$p..($Data.Length-1)]
        if ($compFlag -eq 1) {
            $dec = Expand-ZlibDeflate $textBytes
            if ($dec) { $textBytes = $dec }
            else { $fields["PNG_iTXt_$keyword"] = "<compressed iTXt, $($textBytes.Length) bytes, not decoded>"; return $fields }
        }
        $fields["PNG_iTXt_$keyword"] = [System.Text.Encoding]::UTF8.GetString($textBytes)
    } catch { }
    return $fields
}

function Get-JpegExif {
    param([byte[]]$Bytes)
    $meta = @{}
    try {
        if ($Bytes.Length -lt 2 -or $Bytes[0] -ne 0xFF -or $Bytes[1] -ne 0xD8) { return $meta }
        $o = 2
        while ($o -lt $Bytes.Length - 4) {
            if ($Bytes[$o] -ne 0xFF) { break }
            $marker = $Bytes[$o+1]
            if ($marker -eq 0xD9) { break }  # EOI
            if ($marker -eq 0xDA) { break }  # SOS: compressed scan data follows, NOT segments
            if ($marker -eq 0x01 -or ($marker -ge 0xD0 -and $marker -le 0xD7)) { $o += 2; continue }
            $segLen = ($Bytes[$o+2] -shl 8) -bor $Bytes[$o+3]
            if ($segLen -lt 2) { break }  # corrupt length: stop rather than walk garbage
            if ($marker -eq 0xE1 -and $segLen -gt 8 -and ($o + 9) -lt $Bytes.Length) {
                $head = [System.Text.Encoding]::ASCII.GetString($Bytes[($o+4)..($o+9)])
                if ($head.StartsWith("Exif")) {
                    $sub = Get-TiffMeta $Bytes ($o + 10)
                    foreach ($k in $sub.Keys) { $meta[$k] = $sub[$k] }
                }
            }
            $o += 2 + $segLen
        }
    } catch { }
    return $meta
}

function Get-PngText {
    param([byte[]]$Bytes)
    $meta = @{}
    try {
        $pngSig = [byte[]](0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)
        for ($i=0; $i -lt 8; $i++) { if ($Bytes[$i] -ne $pngSig[$i]) { return $meta } }
        $o = 8
        while ($o -lt $Bytes.Length - 12) {
            $len = ([uint32]$Bytes[$o] -shl 24) -bor ([uint32]$Bytes[$o+1] -shl 16) -bor ([uint32]$Bytes[$o+2] -shl 8) -bor [uint32]$Bytes[$o+3]
            if ($len -gt 200000000) { break }
            $ctype = [System.Text.Encoding]::ASCII.GetString($Bytes[($o+4)..($o+7)])
            if ($o + 12 + $len -gt $Bytes.Length) { break }  # corrupt chunk: stop
            if ($ctype -eq "tEXt" -and $len -gt 0 -and $len -lt 100000) {
                $data = $Bytes[($o+8)..($o+8+$len-1)]
                $zi = [Array]::IndexOf($data, [byte]0)
                if ($zi -gt 0) {
                    $k = [System.Text.Encoding]::ASCII.GetString($data[0..($zi-1)])
                    $v = [System.Text.Encoding]::ASCII.GetString($data[($zi+1)..($data.Length-1)])
                    $meta["PNG_$k"] = $v
                }
            }
            if ($ctype -eq "iTXt" -and $len -gt 0 -and $len -lt 200000) {
                $data = $Bytes[($o+8)..($o+8+$len-1)]
                $f = Get-PngITxtFields $data
                foreach ($k in $f.Keys) { $meta[$k] = $f[$k] }
            }
            if ($ctype -eq "zTXt" -and $len -gt 0 -and $len -lt 200000) {
                $data = $Bytes[($o+8)..($o+8+$len-1)]
                $zi = [Array]::IndexOf($data, [byte]0)
                if ($zi -gt 0 -and ($zi + 2) -lt $data.Length) {
                    $k = [System.Text.Encoding]::ASCII.GetString($data[0..($zi-1)])
                    $comp = $data[($zi+2)..($data.Length-1)]
                    $dec = Expand-ZlibDeflate $comp
                    if ($dec) { $meta["PNG_$k"] = [System.Text.Encoding]::UTF8.GetString($dec) }
                    else { $meta["PNG_$k"] = "<compressed zTXt, $($comp.Length) bytes, not decoded>" }
                }
            }
            if ($ctype -eq "eXIf" -and $len -gt 8 -and $len -lt 1000000) {
                $exif = Get-TiffMeta $Bytes ($o+8)
                foreach ($k in $exif.Keys) { $meta[$k] = $exif[$k] }
            }
            if ($ctype -eq "IEND") { break }
            $o += 12 + $len
        }
    } catch { }
    return $meta
}

function Get-PhotoMetadata {
    <#
    .SYNOPSIS Reads metadata from a JPEG or PNG without decoding the image.
    #>
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        if (-not (Test-Path $Path)) { throw "File not found: $Path" }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $meta = @{}
        $kind = "unknown"
        if ($bytes.Length -gt 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8) {
            $kind = "JPEG"; $meta = Get-JpegExif $bytes
        } elseif ($bytes.Length -gt 8 -and $bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50) {
            $kind = "PNG"; $meta = Get-PngText $bytes
        } elseif ($bytes.Length -gt 12 -and $bytes[0] -eq 0x52 -and $bytes[1] -eq 0x49 -and
                  $bytes[2] -eq 0x46 -and $bytes[3] -eq 0x46 -and
                  $bytes[8] -eq 0x57 -and $bytes[9] -eq 0x45 -and $bytes[10] -eq 0x42 -and $bytes[11] -eq 0x50) {
            # "RIFF" .... "WEBP"
            $kind = "WebP"
            if ($bytes.Length -gt 21) {
                $vtag = [System.Text.Encoding]::ASCII.GetString($bytes[12..15])
                if ($vtag -eq "VP8X") {
                    # VP8X feature flags byte at offset 20: bit1=ICC, bit3=EXIF, bit5=XMP
                    $flags = $bytes[20]
                    if (($flags -band 8) -ne 0)  { $meta["WebP_EXIF_Flag"] = "present (container flag only; full WebP chunk walk not in v1.2)" }
                    if (($flags -band 32) -ne 0) { $meta["WebP_XMP_Flag"]  = "present (container flag only)" }
                    if (($flags -band 2) -ne 0)  { $meta["WebP_ICC_Flag"]  = "present (container flag only)" }
                }
            }
        }
        $gps = Get-GpsDecimal $meta
        return [PSCustomObject]@{
            Path=$Path; Kind=$kind; Bytes=$bytes.Length
            Fields=$meta; Gps=$gps
        }
    } catch {
        Write-Host "[photo] ERROR reading metadata: $($_.Exception.Message)"
        throw
    }
}

function Get-GpsDecimal {
    param([hashtable]$Meta)
    try {
        if (-not $Meta.ContainsKey('GPS_GPSLatitude') -or -not $Meta.ContainsKey('GPS_GPSLongitude')) { return $null }
        $parse = {
            param($s)
            $parts = [regex]::Matches($s, '(\d+)/(\d+)=([\d\.]+)') | ForEach-Object { [double]$_.Groups[3].Value }
            if ($parts.Count -lt 3) { return $null }
            return $parts[0] + $parts[1]/60 + $parts[2]/3600
        }
        $lat = &$parse $Meta['GPS_GPSLatitude']
        $lon = &$parse $Meta['GPS_GPSLongitude']
        if ($null -eq $lat -or $null -eq $lon) { return $null }
        if (($Meta['GPS_GPSLatitudeRef'] -eq "S")) { $lat = -$lat }
        if (($Meta['GPS_GPSLongitudeRef'] -eq "W")) { $lon = -$lon }
        return [PSCustomObject]@{
            Latitude=[math]::Round($lat,6); Longitude=[math]::Round($lon,6)
            MapUrl=("https://www.openstreetmap.org/?mlat={0}&mlon={1}#map=15/{0}/{1}" -f $lat,$lon)
        }
    } catch { return $null }
}

function Get-PhotoRisk {
    <#
    .SYNOPSIS Scored exposure rating for a photo's metadata.
    GPS = 50. Camera/owner serial numbers = 15 (the real tracking leak:
    a serial ties every photo you ever post to one device). MakerNote = 10
    (often hides the serial in vendor binary). Timestamps = 15. Device =
    10. Identity tags (artist/copyright/description/comment) = 5. WebP
    container EXIF flag = 15. Scored, never binary.
    #>
    param([Parameter(Mandatory=$true)]$Photo)
    $score = 0; $reasons = New-Object System.Collections.ArrayList
    if ($Photo.Gps) { $score += 50; [void]$reasons.Add("GPS coordinates embedded: $($Photo.Gps.Latitude), $($Photo.Gps.Longitude)") }
    foreach ($f in @('CameraSerialNumber','LensSerialNumber','OwnerName')) {
        if ($Photo.Fields.ContainsKey($f)) { $score += 15; [void]$reasons.Add("Serial/owner tag: $f = $($Photo.Fields[$f])"); break }
    }
    if ($Photo.Fields.ContainsKey('MakerNote')) { $score += 10; [void]$reasons.Add("MakerNote present (vendor binary, often contains the camera serial)") }
    foreach ($f in @('DateTimeOriginal','DateTime','DateTimeDigitized')) {
        if ($Photo.Fields.ContainsKey($f)) { $score += 15; [void]$reasons.Add("Timestamp: $f = $($Photo.Fields[$f])"); break }
    }
    foreach ($f in @('Make','Model')) {
        if ($Photo.Fields.ContainsKey($f)) { $score += 10; [void]$reasons.Add("Device: $($Photo.Fields['Make']) $($Photo.Fields['Model'])"); break }
    }
    foreach ($f in @('Artist','Copyright','ImageDescription','UserComment')) {
        if ($Photo.Fields.ContainsKey($f)) { $score += 5; [void]$reasons.Add("Identity tag: $f = $($Photo.Fields[$f])"); break }
    }
    if ($Photo.Fields.ContainsKey('Software')) { $score += 5; [void]$reasons.Add("Software tag: $($Photo.Fields['Software'])") }
    if ($Photo.Fields.ContainsKey('WebP_EXIF_Flag')) { $score += 15; [void]$reasons.Add("WebP container flags an EXIF chunk") }
    $level = "Low"
    if ($score -ge 50) { $level = "High" } elseif ($score -ge 20) { $level = "Medium" }
    return [PSCustomObject]@{ Path=$Photo.Path; Score=$score; Level=$level; Reasons=$reasons }
}

function Clear-PhotoMetadata {
    <#
    .SYNOPSIS THE FIX: strips metadata segments (JPEG) or metadata chunks
    (PNG), writes a clean copy, then re-parses the output to PROVE the
    metadata is gone.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$OutPath
    )
    try {
        if (-not (Test-Path $Path)) { throw "File not found: $Path" }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $isJpeg = ($bytes.Length -gt 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xD8)
        $isPng  = ($bytes.Length -gt 8 -and $bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50)
        if ($isPng) { return Clear-PngMetadata -Path $Path -OutPath $OutPath }
        if (-not $isJpeg) { throw "Only JPEG and PNG scrubbing are implemented in v1.2 (WebP: flag report only)." }
        $keepMarkers = @(0xD8,0xD9,0xDA)  # SOI, EOI, SOS handled specially
        $out = New-Object System.Collections.Generic.List[byte]
        $out.Add(0xFF); $out.Add(0xD8)
        $o = 2
        $stripped = 0
        while ($o -lt $bytes.Length - 4) {
            if ($bytes[$o] -ne 0xFF) { break }
            $marker = $bytes[$o+1]
            if ($marker -eq 0xD9) { $out.Add(0xFF); $out.Add(0xD9); break }
            if ($marker -eq 0xDA) {
                # Start of scan: copy the rest verbatim (compressed data)
                for ($i=$o; $i -lt $bytes.Length; $i++) { $out.Add($bytes[$i]) }
                break
            }
            if ($marker -eq 0x01 -or ($marker -ge 0xD0 -and $marker -le 0xD7)) { $o += 2; continue }
            $segLen = ($bytes[$o+2] -shl 8) -bor $bytes[$o+3]
            $isMeta = $marker -in @(0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,0xFE)
            if ($isMeta) { $stripped++ } else {
                for ($i=$o; $i -lt $o+2+$segLen; $i++) { $out.Add($bytes[$i]) }
            }
            $o += 2 + $segLen
        }
        if (-not $OutPath) {
            $dir = [System.IO.Path]::GetDirectoryName($Path)
            $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
            $OutPath = Join-Path $dir ($base + "-scrubbed.jpg")
        }
        [System.IO.File]::WriteAllBytes($OutPath, $out.ToArray())
        # VERIFY: re-parse the output — the scrub is only done if this is clean
        $check = Get-PhotoMetadata $OutPath
        $clean = ($check.Fields.Count -eq 0)
        Write-Host "[photo] Stripped $stripped metadata segments."
        Write-Host "[photo] Clean copy: $OutPath"
        if ($clean) { Write-Host "[photo] VERIFIED: re-parse found zero metadata fields." }
        else { Write-Host "[photo] WARNING: re-parse still found $($check.Fields.Count) fields." }
        return [PSCustomObject]@{ OutPath=$OutPath; StrippedSegments=$stripped; VerifiedClean=$clean; FieldsLeft=$check.Fields.Count }
    } catch {
        Write-Host "[photo] ERROR scrubbing: $($_.Exception.Message)"
        throw
    }
}

function Clear-PngMetadata {
    <#
    .SYNOPSIS THE FIX for PNG: rebuilds the file chunk by chunk, dropping
    metadata chunks (tEXt, iTXt, zTXt, eXIf, tIME) and recomputing the
    CRC32 of every kept chunk (a chunk with a stale CRC is a corrupt PNG).
    Re-parses the output to prove clean.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$OutPath
    )
    try {
        if (-not (Test-Path $Path)) { throw "File not found: $Path" }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $pngSig = [byte[]](0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)
        if ($bytes.Length -lt 8) { throw "File too small to be a PNG." }
        for ($i=0; $i -lt 8; $i++) { if ($bytes[$i] -ne $pngSig[$i]) { throw "Not a PNG file." } }
        $drop = @('tEXt','iTXt','zTXt','eXIf','tIME')
        $out = New-Object System.Collections.Generic.List[byte]
        $out.AddRange($pngSig)
        $o = 8; $dropped = 0; $kept = 0; $sawIdat = $false
        while ($o -lt $bytes.Length - 8) {
            $len = ([uint32]$bytes[$o] -shl 24) -bor ([uint32]$bytes[$o+1] -shl 16) -bor ([uint32]$bytes[$o+2] -shl 8) -bor [uint32]$bytes[$o+3]
            if ($len -gt 200000000) { throw "Corrupt PNG: chunk length $len at offset $o." }
            if ($o + 12 + $len -gt $bytes.Length) { throw "Corrupt PNG: chunk overruns file at offset $o." }
            $ctype = [System.Text.Encoding]::ASCII.GetString($bytes[($o+4)..($o+7)])
            if ($drop -contains $ctype) {
                $dropped++
            } else {
                if ($ctype -eq "IDAT") { $sawIdat = $true }
                for ($i=$o; $i -lt ($o+8+$len); $i++) { $out.Add($bytes[$i]) }
                $crcData = New-Object byte[] ($len + 4)
                [Array]::Copy($bytes, $o+4, $crcData, 0, $len+4)
                $crc = Get-Crc32 $crcData
                $out.Add([byte](($crc -shr 24) -band 0xFF))
                $out.Add([byte](($crc -shr 16) -band 0xFF))
                $out.Add([byte](($crc -shr 8) -band 0xFF))
                $out.Add([byte]($crc -band 0xFF))
                $kept++
            }
            if ($ctype -eq "IEND") { break }
            $o += 12 + $len
        }
        if (-not $sawIdat) { Write-Host "[photo] WARNING: no IDAT chunk seen — output may not be a valid image." }
        if (-not $OutPath) {
            $dir = [System.IO.Path]::GetDirectoryName($Path)
            $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
            $OutPath = Join-Path $dir ($base + "-scrubbed.png")
        }
        [System.IO.File]::WriteAllBytes($OutPath, $out.ToArray())
        # VERIFY: re-parse the output — the scrub is only done if this is clean
        $check = Get-PhotoMetadata $OutPath
        $clean = ($check.Fields.Count -eq 0)
        Write-Host "[photo] Dropped $dropped metadata chunks, kept $kept."
        Write-Host "[photo] Clean copy: $OutPath"
        if ($clean) { Write-Host "[photo] VERIFIED: re-parse found zero metadata fields." }
        else { Write-Host "[photo] WARNING: re-parse still found $($check.Fields.Count) fields." }
        return [PSCustomObject]@{ OutPath=$OutPath; DroppedChunks=$dropped; KeptChunks=$kept; VerifiedClean=$clean; FieldsLeft=$check.Fields.Count }
    } catch {
        Write-Host "[photo] ERROR scrubbing PNG: $($_.Exception.Message)"
        throw
    }
}

function Test-PhotoScrubHygiene {
    <#
    .SYNOPSIS Offline battery: CRC32 test vector; synthetic JPEG with EXIF
    sub-IFD (parse, risk, scrub, verify); SOS-stop regression (fake segment
    inside scan data must not parse); synthetic PNG with tEXt/iTXt/zTXt/eXIf
    (parse each, scrub, verify, IHDR CRC rewrite check); WebP flag report.
    No network.
    #>
    $checks = New-Object System.Collections.ArrayList
    $ok = { param($n,$c) [void]$checks.Add([PSCustomObject]@{Check=$n;Pass=[bool]$c}) }.GetNewClosure()
    $tmpDir = [System.IO.Path]::GetTempPath()

    # --- 1. CRC32 test vector ---
    $crcHex = "{0:X8}" -f (Get-Crc32 ([System.Text.Encoding]::ASCII.GetBytes("123456789")))
    &$ok "CRC32 vector 0xCBF43926" ($crcHex -eq "CBF43926")

    # --- 2. Synthetic JPEG: SOI + APP1(EXIF, IFD0 + GPS IFD + EXIF sub-IFD) + SOS + EOI ---
    $tiff = New-Object System.Collections.Generic.List[byte]
    $tiff.AddRange([byte[]](0x49,0x49,0x2A,0x00,0x08,0x00,0x00,0x00))  # II 42 ifd0@8
    $tiff.AddRange([byte[]](0x03,0x00))                                # 3 entries
    $strOff = 8 + 2 + 36 + 4   # header + count + 3 entries + next-ifd = 50
    $e1 = New-Object System.Collections.Generic.List[byte]
    $e1.AddRange([byte[]](0x0F,0x01, 0x02,0x00, 0x08,0x00,0x00,0x00))  # Make ASCII count 8
    $e1.AddRange([BitConverter]::GetBytes([uint32]$strOff))
    $gpsIfdOff = $strOff + 8 + 20   # after "TestCam\0" (8) + datetime (20)
    $e2 = New-Object System.Collections.Generic.List[byte]
    $e2.AddRange([byte[]](0x25,0x88, 0x04,0x00, 0x01,0x00,0x00,0x00))  # GPS ptr LONG
    $e2.AddRange([BitConverter]::GetBytes([uint32]$gpsIfdOff))
    $exifIfdOff = $gpsIfdOff + 18   # gps ifd: count(2)+entry(12)+next(4)
    $e3 = New-Object System.Collections.Generic.List[byte]
    $e3.AddRange([byte[]](0x69,0x87, 0x04,0x00, 0x01,0x00,0x00,0x00))  # EXIF sub-IFD ptr LONG
    $e3.AddRange([BitConverter]::GetBytes([uint32]$exifIfdOff))
    $tiff.AddRange($e1); $tiff.AddRange($e2); $tiff.AddRange($e3)
    $tiff.AddRange([byte[]](0x00,0x00,0x00,0x00))  # next IFD = 0
    $tiff.AddRange([System.Text.Encoding]::ASCII.GetBytes("TestCam`0"))
    $tiff.AddRange([System.Text.Encoding]::ASCII.GetBytes("2026:10:30 08:44:00`0"))
    # GPS IFD: GPSLatitudeRef "N" inline
    $tiff.AddRange([byte[]](0x01,0x00))
    $tiff.AddRange([byte[]](0x01,0x00, 0x02,0x00, 0x02,0x00,0x00,0x00, 0x4E,0x00,0x00,0x00))
    $tiff.AddRange([byte[]](0x00,0x00,0x00,0x00))
    # EXIF IFD: DateTimeOriginal (0x9003) ASCII count 20 -> string at strOff+8
    $tiff.AddRange([byte[]](0x01,0x00))
    $ex = New-Object System.Collections.Generic.List[byte]
    $ex.AddRange([byte[]](0x03,0x90, 0x02,0x00, 0x14,0x00,0x00,0x00))
    $ex.AddRange([BitConverter]::GetBytes([uint32]($strOff+8)))
    $tiff.AddRange($ex)
    $tiff.AddRange([byte[]](0x00,0x00,0x00,0x00))
    $exifHead = [System.Text.Encoding]::ASCII.GetBytes("Exif`0`0")
    $app1data = New-Object System.Collections.Generic.List[byte]
    $app1data.AddRange($exifHead); $app1data.AddRange($tiff)
    $segLen = $app1data.Count + 2
    $jpg = New-Object System.Collections.Generic.List[byte]
    $jpg.Add([byte]0xFF); $jpg.Add([byte]0xD8)
    $jpg.Add([byte]0xFF); $jpg.Add([byte]0xE1)
    $jpg.Add([byte](($segLen -shr 8) -band 0xFF)); $jpg.Add([byte]($segLen -band 0xFF))
    $jpg.AddRange($app1data)
    $jpg.AddRange([byte[]](0xFF,0xDA, 0x00,0x08, 0x01,0x01,0x00,0x00,0x3F,0x00))  # SOS minimal
    $jpg.AddRange([byte[]](0xFF,0xD9))
    $tmpJpg = Join-Path $tmpDir "bb-exiftest.jpg"
    [System.IO.File]::WriteAllBytes($tmpJpg, $jpg.ToArray())

    $ph = Get-PhotoMetadata $tmpJpg
    &$ok "synthetic EXIF parsed" ($ph.Fields.Count -gt 0)
    &$ok "Make=TestCam" ($ph.Fields['Make'] -eq "TestCam")
    &$ok "GPS ref found" ($ph.Fields['GPS_GPSLatitudeRef'] -eq "N")
    &$ok "EXIF sub-IFD DateTimeOriginal parsed" ($ph.Fields['DateTimeOriginal'] -eq "2026:10:30 08:44:00")
    $risk = Get-PhotoRisk $ph
    &$ok "risk score 25 (Make 10 + DateTimeOriginal 15)" ($risk.Score -eq 25)
    &$ok "risk level Medium" ($risk.Level -eq "Medium")
    $res = Clear-PhotoMetadata -Path $tmpJpg
    &$ok "JPEG scrub verified clean" ($res.VerifiedClean -eq $true)
    &$ok "clean file smaller or equal" ((Get-Item $res.OutPath).Length -le (Get-Item $tmpJpg).Length)

    # --- 3. SOS-stop regression: fake APP1 inside scan data must not parse ---
    $sos = New-Object System.Collections.Generic.List[byte]
    $sos.AddRange([byte[]](0xFF,0xD8))
    $sos.AddRange([byte[]](0xFF,0xDA, 0x00,0x08, 0x01,0x01,0x00,0x00,0x3F,0x00))
    $sos.AddRange([byte[]](0xFF,0xE1, 0x00,0x10))
    $sos.AddRange([System.Text.Encoding]::ASCII.GetBytes("Exif`0`0II*`0junk"))
    $sos.AddRange([byte[]](0xFF,0xD9))
    $tmpSos = Join-Path $tmpDir "bb-sostest.jpg"
    [System.IO.File]::WriteAllBytes($tmpSos, $sos.ToArray())
    $psos = Get-PhotoMetadata $tmpSos
    &$ok "SOS stop: fake segment in scan data not parsed" ($psos.Fields.Count -eq 0)

    # --- 4. Synthetic PNG: IHDR + tEXt + iTXt + zTXt + eXIf + IDAT + IEND ---
    $png = New-Object System.Collections.Generic.List[byte]
    $png.AddRange([byte[]](0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A))
    $addChunk = {
        param($type, $data)
        $tb = [System.Text.Encoding]::ASCII.GetBytes($type)
        $len = $data.Length
        $png.Add([byte](($len -shr 24) -band 0xFF))
        $png.Add([byte](($len -shr 16) -band 0xFF))
        $png.Add([byte](($len -shr 8) -band 0xFF))
        $png.Add([byte]($len -band 0xFF))
        $png.AddRange($tb)
        $png.AddRange($data)
        $crcIn = New-Object byte[] ($data.Length + 4)
        [Array]::Copy($tb, 0, $crcIn, 0, 4)
        [Array]::Copy($data, 0, $crcIn, 4, $data.Length)
        $crc = Get-Crc32 $crcIn
        $png.Add([byte](($crc -shr 24) -band 0xFF))
        $png.Add([byte](($crc -shr 16) -band 0xFF))
        $png.Add([byte](($crc -shr 8) -band 0xFF))
        $png.Add([byte]($crc -band 0xFF))
    }.GetNewClosure()
    &$addChunk "IHDR" ([byte[]](0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x01, 0x08,0x02,0x00,0x00,0x00))
    &$addChunk "tEXt" ([System.Text.Encoding]::ASCII.GetBytes("Comment`0hello"))
    $itxt = New-Object System.Collections.Generic.List[byte]
    $itxt.AddRange([System.Text.Encoding]::ASCII.GetBytes("Title`0"))
    $itxt.Add(0x00); $itxt.Add(0x00); $itxt.Add(0x00); $itxt.Add(0x00)  # flag, method, lang\0, tkey\0
    $itxt.AddRange([System.Text.Encoding]::UTF8.GetBytes("MyTitle"))
    &$addChunk "iTXt" ($itxt.ToArray())
    $zraw = [System.Text.Encoding]::UTF8.GetBytes("secret-desc")
    $cms = New-Object System.IO.MemoryStream
    $cds = New-Object System.IO.Compression.DeflateStream($cms, [System.IO.Compression.CompressionMode]::Compress)
    $cds.Write($zraw, 0, $zraw.Length)
    $cds.Close(); $deflated = $cms.ToArray(); $cms.Close()
    $ztxt = New-Object System.Collections.Generic.List[byte]
    $ztxt.AddRange([System.Text.Encoding]::ASCII.GetBytes("Desc`0"))
    $ztxt.Add(0x00); $ztxt.Add(0x78); $ztxt.Add(0x9C)
    $ztxt.AddRange($deflated)
    &$addChunk "zTXt" ($ztxt.ToArray())
    $et = New-Object System.Collections.Generic.List[byte]
    $et.AddRange([byte[]](0x49,0x49,0x2A,0x00,0x08,0x00,0x00,0x00, 0x01,0x00))
    $et.AddRange([byte[]](0x0F,0x01, 0x02,0x00, 0x04,0x00,0x00,0x00, 0x43,0x61,0x6D,0x00))  # Make="Cam" inline
    $et.AddRange([byte[]](0x00,0x00,0x00,0x00))
    &$addChunk "eXIf" ($et.ToArray())
    &$addChunk "IDAT" (New-Object byte[] 0)
    &$addChunk "IEND" (New-Object byte[] 0)
    $tmpPng = Join-Path $tmpDir "bb-pngtest.png"
    [System.IO.File]::WriteAllBytes($tmpPng, $png.ToArray())

    $pp = Get-PhotoMetadata $tmpPng
    &$ok "PNG tEXt parsed" ($pp.Fields['PNG_Comment'] -eq "hello")
    &$ok "PNG iTXt parsed" ($pp.Fields['PNG_iTXt_Title'] -eq "MyTitle")
    &$ok "PNG zTXt decompressed" ($pp.Fields['PNG_Desc'] -eq "secret-desc")
    &$ok "PNG eXIf parsed" ($pp.Fields['Make'] -eq "Cam")
    $resP = Clear-PhotoMetadata -Path $tmpPng
    &$ok "PNG scrub verified clean" ($resP.VerifiedClean -eq $true)
    &$ok "PNG scrub dropped 4 chunks" ($resP.DroppedChunks -eq 4)
    $pp2 = Get-PhotoMetadata $resP.OutPath
    &$ok "scrubbed file still a PNG" ($pp2.Kind -eq "PNG")
    $sb = [System.IO.File]::ReadAllBytes($resP.OutPath)
    $ihdrType = [System.Text.Encoding]::ASCII.GetString($sb[12..15])
    $crcIn2 = New-Object byte[] 17
    [Array]::Copy($sb, 12, $crcIn2, 0, 17)
    $reHex = "{0:X8}" -f (Get-Crc32 $crcIn2)
    $stHex = "{0:X8}" -f (([uint32]$sb[29] -shl 24) -bor ([uint32]$sb[30] -shl 16) -bor ([uint32]$sb[31] -shl 8) -bor [uint32]$sb[32])
    &$ok "IHDR CRC rewritten correctly" (($ihdrType -eq "IHDR") -and ($reHex -eq $stHex))

    # --- 5. WebP container flag report ---
    $webp = New-Object System.Collections.Generic.List[byte]
    $webp.AddRange([System.Text.Encoding]::ASCII.GetBytes("RIFF"))
    $webp.AddRange([byte[]](0x1A,0x00,0x00,0x00))
    $webp.AddRange([System.Text.Encoding]::ASCII.GetBytes("WEBP"))
    $webp.AddRange([System.Text.Encoding]::ASCII.GetBytes("VP8X"))
    $webp.AddRange([byte[]](0x0A,0x00,0x00,0x00))
    $webp.Add(0x08)  # flags: EXIF bit set
    $webp.AddRange([byte[]](0x00,0x00,0x00, 0x01,0x00, 0x01,0x00, 0x00,0x00))
    $tmpWebp = Join-Path $tmpDir "bb-webptest.webp"
    [System.IO.File]::WriteAllBytes($tmpWebp, $webp.ToArray())
    $pw = Get-PhotoMetadata $tmpWebp
    &$ok "WebP kind detected" ($pw.Kind -eq "WebP")
    &$ok "WebP EXIF flag reported" ($pw.Fields.ContainsKey('WebP_EXIF_Flag'))

    Remove-Item $tmpJpg -Force -ErrorAction SilentlyContinue
    Remove-Item $res.OutPath -Force -ErrorAction SilentlyContinue
    Remove-Item $tmpSos -Force -ErrorAction SilentlyContinue
    Remove-Item $tmpPng -Force -ErrorAction SilentlyContinue
    Remove-Item $resP.OutPath -Force -ErrorAction SilentlyContinue
    Remove-Item $tmpWebp -Force -ErrorAction SilentlyContinue

    $pass = ($checks | Where-Object { $_.Pass }).Count
    Write-Host "[photo] Hygiene: $pass/$($checks.Count) checks passed."
    return $checks
}

Write-Host "[photo] Falsum Photo Scrub v1.2 loaded. Get-PhotoMetadata / Get-PhotoRisk / Clear-PhotoMetadata (JPEG+PNG) / Clear-PngMetadata / Get-TiffMeta / Get-Crc32 / Test-PhotoScrubHygiene."


function Strip-PhotoMetadata {
    <#
    .SYNOPSIS
        Remove EXIF/metadata from a photo by re-encoding without metadata.
        Creates a clean copy, preserves original.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutputPath = "",
        [string]$VaultPath = ""
    )
    
    if (-not (Test-Path $Path)) {
        return @{ Success = $false; Message = "File not found: $Path" }
    }
    
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $dir = Split-Path $Path -Parent
        $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $ext = [System.IO.Path]::GetExtension($Path)
        $OutputPath = Join-Path $dir "$base-clean$ext"
    }
    
    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        
        $img = [System.Drawing.Image]::FromFile($Path)
        
        # Create new bitmap without metadata (this strips EXIF)
        $clean = New-Object System.Drawing.Bitmap($img.Width, $img.Height)
        $graphics = [System.Drawing.Graphics]::FromImage($clean)
        $graphics.DrawImage($img, 0, 0, $img.Width, $img.Height)
        $graphics.Dispose()
        $img.Dispose()
        
        # Save without metadata
        $clean.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Jpeg)
        $clean.Dispose()
        
        $result = @{
            Success = $true
            Message = "Stripped metadata: $Path -> $OutputPath"
            Original = $Path
            Clean = $OutputPath
            Timestamp = (Get-Date).ToString('o')
        }
        
        if ($VaultPath -ne "" -and (Test-Path (Split-Path $VaultPath -Parent))) {
            $result | ConvertTo-Json | Add-Content -Path $VaultPath -Encoding UTF8
        }
        
        return $result
    }
    catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}
