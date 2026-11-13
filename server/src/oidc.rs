//! OpenID-Connect-Kern: Discovery, JWKS und Prüfung des ID-Tokens (Signatur und Claims).
//!
//! Alle Abrufe laufen über die SSRF-Prüfung von `notify::ssrf` (Adresse geprüft und gepinnt, keine Weiterleitungen,
//! kein Umgebungs-Proxy), mit Zeitlimit und höchstens 256 KiB Antwort. `http://` ist nur für Hosts erlaubt, die der
//! Betreiber in `PATCHWATCH_NOTIFY_ALLOWED_HOSTS` freigegeben hat (z. B. ein Anbieter im Heimnetz).
//!
//! Signaturen prüft `ring` (schon über rustls im Baum): Positivliste RS256 und ES256, der Algorithmus muss zum
//! Schlüsseltyp (`kty`) passen; `none`, HMAC-Verfahren und alles andere werden abgelehnt.
use crate::notify::ssrf;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Größte akzeptierte Antwort (Discovery, JWKS, Token, UserInfo).
pub const MAX_BODY: usize = 256 * 1024;
/// Toleranz für Uhrenabweichung zwischen Anbieter und Server.
pub const SKEW_SECS: i64 = 60;
const JWKS_TTL: Duration = Duration::from_secs(600);
/// Unbekannte `kid`: JWKS höchstens einmal je Minute neu holen.
const REFETCH_MIN: Duration = Duration::from_secs(60);

/// Kurzer, fester Fehlercode. Geht ins Aktivitätsprotokoll, nie in die Antwort an den Browser, enthält nie Tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    Url,
    Network,
    TooLarge,
    Status,
    BadJson,
    Discovery,
    Jwks,
    Format,
    Alg,
    Kid,
    Signature,
    Iss,
    Aud,
    Azp,
    Expired,
    NotYet,
    Iat,
    Nonce,
    Sub,
}

impl Fail {
    pub fn code(self) -> &'static str {
        match self {
            Self::Url => "url_nicht_erlaubt",
            Self::Network => "netzwerkfehler",
            Self::TooLarge => "antwort_zu_gross",
            Self::Status => "http_status",
            Self::BadJson => "kein_json",
            Self::Discovery => "discovery_ungueltig",
            Self::Jwks => "jwks_ungueltig",
            Self::Format => "token_format",
            Self::Alg => "algorithmus",
            Self::Kid => "kid_unbekannt",
            Self::Signature => "signatur",
            Self::Iss => "iss",
            Self::Aud => "aud",
            Self::Azp => "azp",
            Self::Expired => "abgelaufen",
            Self::NotYet => "nbf",
            Self::Iat => "iat",
            Self::Nonce => "nonce",
            Self::Sub => "sub",
        }
    }
}

/// Prüft eine Adresse und liefert den gepinnten Client. `http` nur für ausdrücklich freigegebene Hosts.
async fn target(raw: &str, allowed: &[String]) -> Result<(reqwest::Url, reqwest::Client), Fail> {
    let url = ssrf::parse_url(raw, false).map_err(|_| Fail::Url)?;
    let host = url.host_str().unwrap_or_default().to_owned();
    if url.scheme() != "https" && !ssrf::host_allowed(&host, allowed) {
        return Err(Fail::Url);
    }
    let t = ssrf::resolve(url, allowed).await.map_err(|_| Fail::Url)?;
    let client = ssrf::pinned_client(&t).map_err(|_| Fail::Network)?;
    Ok((t.url, client))
}

/// Liest den Body in Stücken und bricht bei mehr als `MAX_BODY` Bytes ab.
async fn read_limited(mut resp: reqwest::Response) -> Result<Value, Fail> {
    if !resp.status().is_success() {
        return Err(Fail::Status);
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| Fail::Network)? {
        if buf.len() + chunk.len() > MAX_BODY {
            return Err(Fail::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|_| Fail::BadJson)
}

/// GET mit optionalem Bearer-Token (UserInfo).
pub async fn get_json(raw: &str, allowed: &[String], bearer: Option<&str>) -> Result<Value, Fail> {
    let (url, client) = target(raw, allowed).await?;
    let mut req = client.get(url);
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    read_limited(req.send().await.map_err(|_| Fail::Network)?).await
}

/// POST (Formular) an den Token-Endpunkt; das Client-Secret geht nur im Body bzw. Basic-Header.
pub async fn post_form(
    raw: &str,
    allowed: &[String],
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> Result<Value, Fail> {
    let (url, client) = target(raw, allowed).await?;
    let mut req = client.post(url).form(form);
    if let Some((u, p)) = basic {
        req = req.basic_auth(u, Some(p));
    }
    read_limited(req.send().await.map_err(|_| Fail::Network)?).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

pub fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

fn host_of(raw: &str) -> Option<String> {
    reqwest::Url::parse(raw)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
}

/// Holt die Discovery. Der Aussteller muss exakt stimmen und alle Endpunkte liegen beim selben Host wie der Issuer
/// (ein manipuliertes Dokument kann so keine anderen Ziele einschleusen).
pub async fn discover(issuer: &str, allowed: &[String]) -> Result<Discovery, Fail> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let v = get_json(&url, allowed, None).await?;
    let d: Discovery = serde_json::from_value(v).map_err(|_| Fail::Discovery)?;
    if !same_issuer(&d.issuer, issuer) {
        return Err(Fail::Discovery);
    }
    let host = host_of(issuer);
    let ends = [&d.authorization_endpoint, &d.token_endpoint, &d.jwks_uri]
        .into_iter()
        .chain(d.userinfo_endpoint.as_ref());
    for e in ends {
        if host_of(e) != host || host.is_none() {
            return Err(Fail::Discovery);
        }
    }
    Ok(d)
}

/// Öffentlicher Schlüssel aus dem JWKS (nur RSA und P-256).
#[derive(Debug, Clone)]
pub enum Key {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ec { point: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct Jwk {
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub key: Key,
}

fn b64(v: &Value) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(v.as_str()?.trim_end_matches('='))
        .ok()
}

/// Liest das JWKS; unbrauchbare, verschlüsselnde ("use":"enc") oder unbekannte Schlüssel werden übersprungen.
pub fn parse_jwks(v: &Value) -> Vec<Jwk> {
    let mut out = Vec::new();
    for k in v["keys"].as_array().into_iter().flatten() {
        if k["use"].as_str().is_some_and(|u| u != "sig") {
            continue;
        }
        let key = match k["kty"].as_str() {
            Some("RSA") => match (b64(&k["n"]), b64(&k["e"])) {
                (Some(n), Some(e)) if !n.is_empty() && !e.is_empty() => Key::Rsa { n, e },
                _ => continue,
            },
            Some("EC") if k["crv"].as_str() == Some("P-256") => {
                match (b64(&k["x"]), b64(&k["y"])) {
                    (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => {
                        let mut point = vec![0x04];
                        point.extend(x);
                        point.extend(y);
                        Key::Ec { point }
                    }
                    _ => continue,
                }
            }
            _ => continue,
        };
        out.push(Jwk {
            kid: k["kid"].as_str().map(str::to_owned),
            alg: k["alg"].as_str().map(str::to_owned),
            key,
        });
    }
    out
}

struct Cached {
    keys: Vec<Jwk>,
    fetched: Instant,
}

/// Schlüsselspeicher je JWKS-Adresse: 10 Minuten gültig, Neuabruf wegen unbekannter `kid` höchstens 1×/Minute.
#[derive(Default)]
pub struct JwksCache(Mutex<HashMap<String, Cached>>);

impl JwksCache {
    fn get(&self, uri: &str) -> Option<(Vec<Jwk>, Instant)> {
        let g = self.0.lock().ok()?;
        g.get(uri).map(|c| (c.keys.clone(), c.fetched))
    }

    fn put(&self, uri: &str, keys: Vec<Jwk>) {
        if let Ok(mut g) = self.0.lock() {
            g.insert(
                uri.to_owned(),
                Cached {
                    keys,
                    fetched: Instant::now(),
                },
            );
        }
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.0.lock() {
            g.clear();
        }
    }

    pub async fn refresh(&self, uri: &str, allowed: &[String]) -> Result<Vec<Jwk>, Fail> {
        let keys = parse_jwks(&get_json(uri, allowed, None).await?);
        if keys.is_empty() {
            return Err(Fail::Jwks);
        }
        self.put(uri, keys.clone());
        Ok(keys)
    }

    /// Schlüssel für den Token; holt das JWKS bei leerem/abgelaufenem Speicher oder (rate-limitiert) bei neuer `kid`.
    pub async fn keys_for(
        &self,
        uri: &str,
        allowed: &[String],
        kid: Option<&str>,
    ) -> Result<Vec<Jwk>, Fail> {
        let Some((keys, fetched)) = self.get(uri) else {
            return self.refresh(uri, allowed).await;
        };
        if fetched.elapsed() > JWKS_TTL {
            return self.refresh(uri, allowed).await;
        }
        let known = match kid {
            Some(k) => keys.iter().any(|j| j.kid.as_deref() == Some(k)),
            None => true,
        };
        if known {
            return Ok(keys);
        }
        if fetched.elapsed() >= REFETCH_MIN {
            return self.refresh(uri, allowed).await;
        }
        Err(Fail::Kid)
    }

    /// Ablauf des Speichers erzwingen (nur Tests).
    #[doc(hidden)]
    pub fn age_for_tests(&self, by: Duration) {
        if let Ok(mut g) = self.0.lock() {
            for c in g.values_mut() {
                c.fetched = c.fetched.checked_sub(by).unwrap_or(c.fetched);
            }
        }
    }
}

/// Zerlegt ein kompaktes JWS in (Header-JSON, Claims-JSON, signierte Bytes, Signatur).
fn split(jwt: &str) -> Result<(Value, Value, &str, Vec<u8>), Fail> {
    if jwt.len() > MAX_BODY {
        return Err(Fail::Format);
    }
    let mut it = jwt.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(Fail::Format);
    };
    let dec = |x: &str| URL_SAFE_NO_PAD.decode(x).map_err(|_| Fail::Format);
    let header: Value = serde_json::from_slice(&dec(h)?).map_err(|_| Fail::Format)?;
    let claims: Value = serde_json::from_slice(&dec(p)?).map_err(|_| Fail::Format)?;
    let signed = &jwt[..h.len() + 1 + p.len()];
    Ok((header, claims, signed, dec(s)?))
}

/// Algorithmus und `kid` aus dem ungeprüften Header (für die Schlüsselwahl; Vertrauen entsteht erst durch die Signatur).
pub fn peek_header(jwt: &str) -> Result<(String, Option<String>), Fail> {
    let (h, _, _, _) = split(jwt)?;
    Ok((
        h["alg"].as_str().unwrap_or_default().to_owned(),
        h["kid"].as_str().map(str::to_owned),
    ))
}

/// Prüft die Signatur gegen die Schlüssel und liefert die Claims. Positivliste: RS256 und ES256.
pub fn verify(jwt: &str, keys: &[Jwk]) -> Result<Value, Fail> {
    let (header, claims, signed, sig) = split(jwt)?;
    if header.get("crit").is_some() {
        return Err(Fail::Alg);
    }
    let alg = header["alg"].as_str().unwrap_or_default();
    if !matches!(alg, "RS256" | "ES256") {
        return Err(Fail::Alg);
    }
    let kid = header["kid"].as_str();
    let mut any = false;
    for k in keys {
        // Der Algorithmus muss zum Schlüsseltyp passen; ein anderer Typ wird nie "umgedeutet" (kein HMAC mit RSA-Schlüssel).
        let fits = matches!(
            (&k.key, alg),
            (Key::Rsa { .. }, "RS256") | (Key::Ec { .. }, "ES256")
        );
        if !fits || k.alg.as_deref().is_some_and(|a| a != alg) {
            continue;
        }
        if kid.is_some() && k.kid.is_some() && k.kid.as_deref() != kid {
            continue;
        }
        any = true;
        let ok = match &k.key {
            Key::Rsa { n, e } => RsaPublicKeyComponents { n, e }
                .verify(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    signed.as_bytes(),
                    &sig,
                )
                .is_ok(),
            Key::Ec { point } => UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(signed.as_bytes(), &sig)
                .is_ok(),
        };
        if ok {
            return Ok(claims);
        }
    }
    Err(if any { Fail::Signature } else { Fail::Kid })
}

/// Geprüfte Identität aus dem ID-Token (oder UserInfo).
#[derive(Debug, Clone)]
pub struct Identity {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub groups: Vec<String>,
}

fn aud_list(v: &Value) -> Vec<&str> {
    match v {
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Prüft die Claims eines (bereits signaturgeprüften) ID-Tokens.
pub fn check_claims(
    c: &Value,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<(), Fail> {
    if !c["iss"].as_str().is_some_and(|i| same_issuer(i, issuer)) {
        return Err(Fail::Iss);
    }
    let aud = aud_list(&c["aud"]);
    if !aud.contains(&client_id) {
        return Err(Fail::Aud);
    }
    // Mehrere Zielgruppen: azp ist Pflicht und muss unser Client sein; ein vorhandenes azp muss immer passen.
    match c["azp"].as_str() {
        Some(a) if a != client_id => return Err(Fail::Azp),
        None if aud.len() > 1 => return Err(Fail::Azp),
        _ => {}
    }
    match c["exp"].as_i64() {
        Some(e) if e + SKEW_SECS > now => {}
        _ => return Err(Fail::Expired),
    }
    match c["iat"].as_i64() {
        Some(i) if i <= now + SKEW_SECS => {}
        _ => return Err(Fail::Iat),
    }
    if c["nbf"].as_i64().is_some_and(|n| n > now + SKEW_SECS) {
        return Err(Fail::NotYet);
    }
    if c["nonce"].as_str().is_none_or(|n| n != nonce) {
        return Err(Fail::Nonce);
    }
    Ok(())
}

/// `sub` und Profilangaben (E-Mail dient nur der Anzeige, nie der Zuordnung).
pub fn identity(profile: &Value, group_claim: &str) -> Result<Identity, Fail> {
    let sub = profile["sub"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 255 && !s.chars().any(char::is_control))
        .ok_or(Fail::Sub)?;
    // Manche Anbieter senden email_verified als Text.
    let verified = matches!(&profile["email_verified"], Value::Bool(true))
        || profile["email_verified"].as_str() == Some("true");
    let groups = match &profile[group_claim] {
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    };
    let text = |k: &str| {
        profile[k]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 255 && !s.chars().any(char::is_control))
            .map(str::to_owned)
    };
    Ok(Identity {
        sub: sub.to_owned(),
        email: text("email").map(|e| e.to_ascii_lowercase()),
        email_verified: verified,
        name: text("name").or_else(|| text("preferred_username")),
        groups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    fn good() -> Value {
        json!({"iss":"https://idp/","aud":"cid","exp":NOW+300,"iat":NOW-5,"nonce":"n1","sub":"u1"})
    }

    #[test]
    fn claims_positive_and_each_failure() {
        assert_eq!(
            check_claims(&good(), "https://idp", "cid", "n1", NOW),
            Ok(())
        );
        let cases: [(&str, Value, Fail); 9] = [
            ("iss", json!("https://evil"), Fail::Iss),
            ("aud", json!("other"), Fail::Aud),
            ("exp", json!(NOW - 61), Fail::Expired),
            ("iat", json!(NOW + 61), Fail::Iat),
            ("nbf", json!(NOW + 61), Fail::NotYet),
            ("nonce", json!("x"), Fail::Nonce),
            ("azp", json!("other"), Fail::Azp),
            ("aud", json!(["cid", "second"]), Fail::Azp),
            ("exp", json!("text"), Fail::Expired),
        ];
        for (k, v, want) in cases {
            let mut c = good();
            c[k] = v;
            assert_eq!(
                check_claims(&c, "https://idp", "cid", "n1", NOW),
                Err(want),
                "{k}"
            );
        }
        // Mehrere Zielgruppen mit passendem azp sind in Ordnung; Toleranz von 60 s gilt.
        let mut c = good();
        c["aud"] = json!(["cid", "second"]);
        c["azp"] = json!("cid");
        c["exp"] = json!(NOW - 59);
        assert_eq!(check_claims(&c, "https://idp", "cid", "n1", NOW), Ok(()));
    }

    #[test]
    fn rejects_foreign_algorithms_and_garbage() {
        let enc = |v: Value| URL_SAFE_NO_PAD.encode(v.to_string());
        for alg in ["none", "HS256", "RS512", "PS256", ""] {
            let t = format!("{}.{}.AAAA", enc(json!({"alg": alg})), enc(good()));
            assert_eq!(verify(&t, &[]), Err(Fail::Alg), "{alg}");
        }
        let crit = format!(
            "{}.{}.AAAA",
            enc(json!({"alg":"RS256","crit":["x"]})),
            enc(good())
        );
        assert_eq!(verify(&crit, &[]), Err(Fail::Alg));
        for bad in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert_eq!(verify(bad, &[]), Err(Fail::Format), "{bad}");
        }
        // Richtiger Algorithmus, aber kein passender Schlüssel.
        let t = format!("{}.{}.AAAA", enc(json!({"alg":"RS256"})), enc(good()));
        assert_eq!(verify(&t, &[]), Err(Fail::Kid));
    }

    #[test]
    fn identity_reads_groups_and_never_trusts_unverified_mail() {
        let p = json!({"sub":"s","email":"A@B.de","email_verified":"true","groups":["x","y"],"name":"Ada"});
        let i = identity(&p, "groups").unwrap();
        assert_eq!(
            (i.sub.as_str(), i.email.as_deref(), i.email_verified),
            ("s", Some("a@b.de"), true)
        );
        assert_eq!(i.groups, ["x", "y"]);
        assert!(
            !identity(&json!({"sub":"s","email_verified":false}), "groups")
                .unwrap()
                .email_verified
        );
        assert_eq!(
            identity(&json!({"sub":""}), "groups").unwrap_err(),
            Fail::Sub
        );
        assert_eq!(identity(&json!({}), "groups").unwrap_err(), Fail::Sub);
    }

    /// RS256-Prüfung mit einem festen Testvektor (nur der öffentliche Schlüssel liegt hier; erzeugt mit `openssl`).
    #[test]
    fn rs256_signature_verifies_and_rejects_tampering() {
        let jwks = json!({"keys":[{"kty":"RSA","kid":"rsa1","use":"sig","n":"2a0hgNSNY3tbvByMABNyMQo_pb3Q7ZCZVYTLDP93DULC4-ZDIQiSVeKKVCzNdDYNd6Bz3I724ShHueRrMaZWSUsQKXLkLjOOT4QBcgGVRJrtzvXY8tbFT_mNck74SglLkY4VGjoLkIQF6Nq_trBGvsZmuQ1ZL5le8hVPQf0wbEBbSiWiNFixle0M-oB6n72B60ik1HQOVKdvqrBvlNatq-Ef8ET2vAgpMJoLbjIuwzgwaL4JtjK0Aa6lUNac4h1tmVfUNfbq_Eiqy4XB9Ecpp21DaQz0MOigQhmld82pjBU7Icc7fl_Cx3ZEmYgt3J_VcmEpPeevTPvcw6Ser3wRTQ","e":"AQAB"}]});
        let keys = parse_jwks(&jwks);
        assert_eq!(keys.len(), 1);
        let token = "eyJhbGciOiAiUlMyNTYiLCAia2lkIjogInJzYTEifQ.eyJzdWIiOiAieCJ9.uh4YavtNrTRIajlLuWT9vmv_mMLSzf2ppXV4TWmvnQSxY2FRdUP0gbzUA0b8CkwuaPGKOCcLNSPB-cfIjUrQDE7i5Y4-Wt4wir9jF0nypKnSPZVhngyx7WU6yLXhyYd396WRBfmKacat7i2b9dyiZgQ_4L0d2O9Rvdvzv9R_rQ6FGV4cdXt1_i8bmnF6zjIBY7fytFUVQlqXeTUrlGDZWZNh6bpDXaLNEEn9eE5eZXV0-QhWx7tAD_j40TrrERI6bILnTlPuEsXQagmbd4fRDzW8XeZY2oIJgJgGP9s4Q-NDEP3gB9esigUpqkJV7I2BtsQOjE5M72SG3ChLCqPYBQ";
        assert_eq!(verify(token, &keys).unwrap()["sub"], "x");
        // Anderer Inhalt bei gleicher Signatur, und ein EC-Schlüssel darf RS256 nie prüfen.
        let (h, rest) = token.split_once('.').unwrap();
        let (_, sig) = rest.split_once('.').unwrap();
        let forged = format!("{h}.{}.{sig}", URL_SAFE_NO_PAD.encode(r#"{"sub":"admin"}"#));
        assert_eq!(verify(&forged, &keys), Err(Fail::Signature));
        let ec = Jwk {
            kid: None,
            alg: None,
            key: Key::Ec { point: vec![4; 65] },
        };
        assert_eq!(verify(token, &[ec]), Err(Fail::Kid));
    }
}
