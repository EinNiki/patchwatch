//! Strenge Prüfung des Profilbilds ohne Bildbibliothek (keine neue Angriffsfläche).
//!
//! Der Browser kodiert das Bild neu (Zuschnitt auf 128×128, WebP oder PNG, ohne Metadaten). Der Server dekodiert nichts,
//! sondern prüft die Container-Struktur Byte für Byte und lehnt alles ab, was nicht genau so aussieht: falsche Signatur,
//! falsche Abmessungen, Animation, Metadaten-Chunks (Text, EXIF, XMP), Anhängsel hinter dem Ende, beschädigte Prüfsummen.

/// Kantenlänge des Profilbilds in Pixeln.
pub const SIZE: u32 = 128;
/// Höchstgröße in Bytes.
pub const MAX_BYTES: usize = 64 * 1024;

/// Farbprofile (ICC) sind erlaubt, weil Browser sie beim Kodieren anhängen (Chrome: ein sRGB-Profil von ~0,5 KB im WebP);
/// sie bleiben auf diese Größe begrenzt und werden nicht gelesen.
const MAX_ICC: usize = 4096;

const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// CRC-32 (IEEE) wie in PNG.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn le24(b: &[u8]) -> u32 {
    u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16
}

/// Prüft das Bild und liefert den festen Content-Type. Fehlertext ist für Nutzer gedacht (keine Interna).
pub fn validate(data: &[u8]) -> Result<&'static str, &'static str> {
    if data.is_empty() {
        return Err("Leere Datei");
    }
    if data.len() > MAX_BYTES {
        return Err("Bild ist größer als 64 KB");
    }
    if data.starts_with(&PNG_SIG) {
        validate_png(data).map(|()| "image/png")
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        validate_webp(data).map(|()| "image/webp")
    } else {
        Err("Nur PNG und WebP sind erlaubt")
    }
}

fn validate_png(d: &[u8]) -> Result<(), &'static str> {
    const BAD: &str = "Ungültige PNG-Datei";
    let mut pos = 8;
    let mut first = true;
    let mut idat = false;
    loop {
        if pos + 12 > d.len() {
            return Err(BAD);
        }
        let len = be32(&d[pos..]) as usize;
        let kind = &d[pos + 4..pos + 8];
        let end = pos
            .checked_add(12)
            .and_then(|x| x.checked_add(len))
            .ok_or(BAD)?;
        if end > d.len() {
            return Err(BAD);
        }
        if crc32(&d[pos + 4..pos + 8 + len]) != be32(&d[pos + 8 + len..]) {
            return Err(BAD);
        }
        if first {
            if kind != b"IHDR" || len != 13 {
                return Err(BAD);
            }
            let (w, h) = (be32(&d[pos + 8..]), be32(&d[pos + 12..]));
            if w != SIZE || h != SIZE {
                return Err("Das Bild muss 128 × 128 Pixel groß sein");
            }
            first = false;
        } else {
            match kind {
                // Bildaufbau und harmlose Farbangaben; Text, EXIF, Animation und Unbekanntes sind verboten.
                b"IDAT" => idat = true,
                b"PLTE" | b"tRNS" | b"sRGB" | b"gAMA" | b"cHRM" | b"pHYs" => {}
                b"iCCP" if len <= MAX_ICC => {}
                b"IEND" => {
                    if len != 0 || !idat || end != d.len() {
                        return Err(BAD);
                    }
                    return Ok(());
                }
                _ => return Err("Das PNG enthält unzulässige Bereiche (Metadaten oder Animation)"),
            }
        }
        pos = end;
    }
}

fn validate_webp(d: &[u8]) -> Result<(), &'static str> {
    const BAD: &str = "Ungültige WebP-Datei";
    let riff_len = u32::from_le_bytes([d[4], d[5], d[6], d[7]]) as usize;
    if riff_len + 8 != d.len() {
        return Err(BAD);
    }
    let mut pos = 12;
    let mut dims: Option<(u32, u32)> = None;
    let mut bitstream = false;
    let mut first = true;
    while pos < d.len() {
        if pos + 8 > d.len() {
            return Err(BAD);
        }
        let kind = &d[pos..pos + 4];
        let len = u32::from_le_bytes([d[pos + 4], d[pos + 5], d[pos + 6], d[pos + 7]]) as usize;
        let body = pos + 8;
        let end = body.checked_add(len).ok_or(BAD)?;
        // Chunks sind auf gerade Länge aufgefüllt.
        let next = end + (len & 1);
        if next > d.len() {
            return Err(BAD);
        }
        let c = &d[body..end];
        match kind {
            b"VP8X" => {
                // VP8X muss der erste Chunk sein; Animation, EXIF und XMP sind verboten (ICC und Alpha erlaubt).
                if !first || len != 10 || c[0] & 0b0000_1110 != 0 {
                    return Err("Das WebP enthält unzulässige Bereiche (Metadaten oder Animation)");
                }
                dims = Some((le24(&c[4..]) + 1, le24(&c[7..]) + 1));
            }
            b"ALPH" => {}
            // Das Profil muss im VP8X-Kopf angekündigt sein, vor dem Bildstrom stehen und klein bleiben.
            b"ICCP" if !bitstream && len <= MAX_ICC && dims.is_some() => {}
            b"VP8 " => {
                if len < 10 || c[3..6] != [0x9D, 0x01, 0x2A] || bitstream {
                    return Err(BAD);
                }
                let w = u32::from(u16::from_le_bytes([c[6], c[7]]) & 0x3FFF);
                let h = u32::from(u16::from_le_bytes([c[8], c[9]]) & 0x3FFF);
                if dims.is_some_and(|x| x != (w, h)) {
                    return Err(BAD);
                }
                dims = Some((w, h));
                bitstream = true;
            }
            b"VP8L" => {
                if len < 5 || c[0] != 0x2F || bitstream {
                    return Err(BAD);
                }
                let bits = u32::from_le_bytes([c[1], c[2], c[3], c[4]]);
                let (w, h) = ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1);
                if dims.is_some_and(|x| x != (w, h)) {
                    return Err(BAD);
                }
                dims = Some((w, h));
                bitstream = true;
            }
            _ => return Err("Das WebP enthält unzulässige Bereiche (Metadaten oder Animation)"),
        }
        first = false;
        pos = next;
    }
    match dims {
        Some((w, h)) if bitstream && w == SIZE && h == SIZE => Ok(()),
        Some(_) if bitstream => Err("Das Bild muss 128 × 128 Pixel groß sein"),
        _ => Err(BAD),
    }
}

/// Nur für Tests: ein gültiges, unkomprimiert kodiertes Graustufen-PNG der Größe `w`×`h` (Füllwert `v`).
#[doc(hidden)]
pub fn sample_png(w: u32, h: u32, v: u8) -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend((data.len() as u32).to_be_bytes());
        out.extend(kind);
        out.extend(data);
        let mut c = kind.to_vec();
        c.extend(data);
        out.extend(crc32(&c).to_be_bytes());
    }
    let mut raw = Vec::new();
    for _ in 0..h {
        raw.push(0);
        raw.extend(std::iter::repeat_n(v, w as usize));
    }
    // zlib mit gespeicherten (unkomprimierten) Blöcken.
    let mut z = vec![0x78, 0x01];
    let mut chunks = raw.chunks(65_535).peekable();
    while let Some(b) = chunks.next() {
        z.push(u8::from(chunks.peek().is_none()));
        z.extend((b.len() as u16).to_le_bytes());
        z.extend((!(b.len() as u16)).to_le_bytes());
        z.extend(b);
    }
    let (mut a, mut s) = (1u32, 0u32);
    for &x in &raw {
        a = (a + u32::from(x)) % 65_521;
        s = (s + a) % 65_521;
    }
    z.extend(((s << 16) | a).to_be_bytes());
    let mut out = PNG_SIG.to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend(w.to_be_bytes());
    ihdr.extend(h.to_be_bytes());
    ihdr.extend([8, 0, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}

/// Nur für Tests: PNG mit zusätzlichem Chunk `kind` vor IEND.
#[doc(hidden)]
pub fn sample_png_with_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let png = sample_png(SIZE, SIZE, 7);
    let iend = png.len() - 12;
    let mut out = png[..iend].to_vec();
    out.extend((data.len() as u32).to_be_bytes());
    out.extend(kind);
    out.extend(data);
    let mut c = kind.to_vec();
    c.extend(data);
    out.extend(crc32(&c).to_be_bytes());
    out.extend(&png[iend..]);
    out
}

/// Nur für Tests: WebP wie Chrome es kodiert (VP8X mit ICC-Flag, ICCP, VP8L) mit einem Profil der Länge `icc`.
#[doc(hidden)]
pub fn sample_webp_icc(icc: usize) -> Vec<u8> {
    let mut vp8x = vec![0x20, 0, 0, 0];
    vp8x.extend([127, 0, 0, 127, 0, 0]);
    let bits = 127u32 | (127 << 14);
    let mut vp8l = vec![0x2F];
    vp8l.extend(bits.to_le_bytes());
    vp8l.extend([0, 0, 0]);
    let mut body = b"WEBP".to_vec();
    for (k, d) in [
        (&b"VP8X"[..], vp8x),
        (&b"ICCP"[..], vec![1; icc]),
        (&b"VP8L"[..], vp8l),
    ] {
        body.extend(k);
        body.extend((d.len() as u32).to_le_bytes());
        body.extend(&d);
        if d.len() % 2 == 1 {
            body.push(0);
        }
    }
    let mut out = b"RIFF".to_vec();
    out.extend((body.len() as u32).to_le_bytes());
    out.extend(body);
    out
}

/// Nur für Tests: minimales WebP (VP8L-Kopf mit den gegebenen Abmessungen; der Strom selbst wird nicht dekodiert).
#[doc(hidden)]
pub fn sample_webp(w: u32, h: u32) -> Vec<u8> {
    let bits = (w - 1) | ((h - 1) << 14);
    let mut vp8l = vec![0x2F];
    vp8l.extend(bits.to_le_bytes());
    vp8l.extend([0, 0, 0]);
    // Gesamtlänge gerade halten.
    let mut body = b"WEBP".to_vec();
    body.extend(b"VP8L");
    body.extend((vp8l.len() as u32).to_le_bytes());
    body.extend(&vp8l);
    if vp8l.len() % 2 == 1 {
        body.push(0);
    }
    let mut out = b"RIFF".to_vec();
    out.extend((body.len() as u32).to_le_bytes());
    out.extend(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_128_png_and_webp() {
        assert_eq!(validate(&sample_png(128, 128, 9)), Ok("image/png"));
        assert_eq!(validate(&sample_webp(128, 128)), Ok("image/webp"));
    }

    #[test]
    fn accepts_a_small_icc_profile_like_chrome_adds_but_not_a_large_one() {
        assert_eq!(validate(&sample_webp_icc(456)), Ok("image/webp"));
        assert!(validate(&sample_webp_icc(5000)).is_err());
        assert_eq!(
            validate(&sample_png_with_chunk(b"iCCP", &[0; 300])),
            Ok("image/png")
        );
        assert!(validate(&sample_png_with_chunk(b"iCCP", &vec![0; 5000])).is_err());
    }

    #[test]
    fn rejects_wrong_signature_size_and_dimensions() {
        assert!(validate(b"").is_err());
        assert!(validate(b"<svg xmlns='http://www.w3.org/2000/svg'/>").is_err());
        assert!(validate(b"GIF89a\x01\x00\x01\x00").is_err());
        assert!(
            validate(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10]).is_err(),
            "JPEG wird nicht angenommen (der Browser kodiert neu)"
        );
        assert!(validate(&sample_png(64, 64, 1))
            .unwrap_err()
            .contains("128"));
        assert!(validate(&sample_webp(129, 128))
            .unwrap_err()
            .contains("128"));
        let mut big = sample_png(128, 128, 1);
        big.resize(MAX_BYTES + 1, 0);
        assert!(validate(&big).unwrap_err().contains("64 KB"));
    }

    #[test]
    fn rejects_metadata_animation_trailing_data_and_bad_crc() {
        assert!(validate(&sample_png_with_chunk(b"tEXt", b"Comment\0geheim")).is_err());
        assert!(validate(&sample_png_with_chunk(b"eXIf", b"Exif\0\0")).is_err());
        assert!(validate(&sample_png_with_chunk(b"acTL", &[0; 8])).is_err());
        let mut tail = sample_png(128, 128, 1);
        tail.extend(b"anhang");
        assert!(validate(&tail).is_err());
        let mut crc = sample_png(128, 128, 1);
        let n = crc.len();
        crc[n - 20] ^= 0xFF;
        assert!(validate(&crc).is_err());
        let mut cut = sample_png(128, 128, 1);
        cut.truncate(cut.len() - 5);
        assert!(validate(&cut).is_err());
        let mut riff = sample_webp(128, 128);
        riff.extend(b"xx");
        assert!(validate(&riff).is_err(), "RIFF-Länge passt nicht");
    }
}
