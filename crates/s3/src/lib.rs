use std::{iter::once, time::Duration};

use chrono::{DateTime, Datelike, TimeZone, Timelike};
use hmac::{Hmac, Mac};
use sha2::Digest;

pub struct UriEncoded(String);

impl UriEncoded {
    pub fn new_line() -> Self {
        Self("\n".to_string())
    }
}

pub enum Verb {
    Get,
    Put,
    Post,
}

impl std::fmt::Display for UriEncoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <str as std::fmt::Display>::fmt(self.0.as_str(), f)
    }
}

impl From<Verb> for UriEncoded {
    fn from(value: Verb) -> UriEncoded {
        match value {
            Verb::Get => Self("GET".to_string()),
            Verb::Put => Self("PUT".to_string()),
            Verb::Post => Self("POST".to_string()),
        }
    }
}

impl<A: AsRef<str>> From<A> for UriEncoded {
    fn from(raw: A) -> Self {
        let raw = raw.as_ref();

        Self(urlencoding::encode(raw).to_string())
    }
}

fn intersperse_with<'a, Item: 'a>(
    iter: impl IntoIterator<Item = Item> + 'a,
    mut with: impl FnMut() -> Item + 'a,
) -> impl Iterator<Item = Item> + 'a
where
    Item: std::fmt::Debug,
{
    let mut iter = iter.into_iter();
    let (mut now, mut ahead) = (iter.next(), iter.next());
    std::iter::from_fn(move || {
        match (&mut now, &mut ahead) {
            (None, None) => None,
            (now @ Some(_), _) => now.take(),
            (now @ None, ahead @ Some(_)) => {
                // Place separator.
                *now = ahead.take();
                *ahead = iter.next();
                Some(with())
            }
        }
    })
}

pub struct CanonicalRequest(String);

impl CanonicalRequest {
    pub fn new<'a>(
        verb: Verb,
        canonical_url: UriEncoded,
        canonical_query_params: impl IntoIterator<Item = (String, String)>,
        canonical_headers: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        let mut canonical_query_params = canonical_query_params.into_iter().collect::<Vec<_>>();
        canonical_query_params.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mut canonical_headers = canonical_headers.into_iter().collect::<Vec<_>>();
        canonical_headers.sort_by(|(a, _), (b, _)| a.cmp(b));

        Self({
            let iter = once(verb.into())
                .chain(once(UriEncoded::new_line()))
                .chain(once(canonical_url))
                .chain(once(UriEncoded::new_line()))
                .chain(once({
                    let iter = canonical_query_params.into_iter().map(|(param, value)| {
                        format!("{}={}", UriEncoded::from(param), UriEncoded::from(value))
                    });

                    UriEncoded(intersperse_with(iter, || "&".to_string()).collect())
                }))
                .chain(once(UriEncoded::new_line()))
                .chain({
                    canonical_headers
                        .iter()
                        .map(|(name, value)| format!("{}:{}\n", name.to_lowercase(), value.trim()))
                        .map(UriEncoded)
                })
                .chain(once(UriEncoded::new_line()))
                .chain(once({
                    let names = canonical_headers
                        .iter()
                        .map(|(name, _)| name.to_lowercase());

                    UriEncoded(intersperse_with(names, || ";".to_string()).collect())
                }))
                .chain(once(UriEncoded::new_line()))
                .chain(once(UriEncoded("UNSIGNED-PAYLOAD".to_string())));

            iter.map(|a| a.0).collect()
        })
    }
}

pub struct StringToSign<Tz: TimeZone> {
    canonical_req: CanonicalRequest,
    timestamp: chrono::DateTime<Tz>,
    aws_region: String,
    aws_service: String,
}

fn format_date<Tz: TimeZone>(d: &chrono::DateTime<Tz>) -> String {
    format!(
        "{:0>4}{:0>2}{:0>2}T{:0>2}{:0>2}{:0>2}Z",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute(),
        d.second()
    )
}

fn yyyymmdd<Tz: TimeZone>(d: &chrono::DateTime<Tz>) -> String {
    format!("{:0>4}{:0>2}{:0>2}", d.year(), d.month(), d.day(),)
}

impl<Tz: TimeZone> ToString for StringToSign<Tz> {
    fn to_string(&self) -> String {
        format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            format_date(&self.timestamp),
            format!(
                "{}/{}/{}/aws4_request",
                yyyymmdd(&self.timestamp),
                &self.aws_region,
                &self.aws_service,
            ),
            hex::encode(sha2::Sha256::digest(self.canonical_req.0.as_bytes()))
        )
    }
}

pub struct Signature<Tz: TimeZone> {
    secret_access_key: String,
    string_to_sign: StringToSign<Tz>,
}

type HmacSha256 = Hmac<sha2::Sha256>;

fn hmac_sha256(
    key: impl AsRef<[u8]>,
    plaintext: impl AsRef<[u8]>,
) -> Result<hmac::digest::Output<HmacSha256>, hmac::digest::InvalidLength> {
    let mut hmac = HmacSha256::new_from_slice(key.as_ref())?;
    hmac.update(plaintext.as_ref());
    Ok(hmac.finalize().into_bytes())
}

impl<Tz: TimeZone> Signature<Tz> {
    pub fn as_signed(self) -> Result<String, hmac::digest::InvalidLength> {
        let date_key = hmac_sha256(
            format!("AWS4{}", self.secret_access_key),
            yyyymmdd(&self.string_to_sign.timestamp),
        )?;
        let date_region_key = hmac_sha256(date_key, &self.string_to_sign.aws_region)?;
        let date_region_service_key =
            hmac_sha256(date_region_key, &self.string_to_sign.aws_service)?;
        let signing_key = hmac_sha256(date_region_service_key, "aws4_request")?;

        Ok(hex::encode(hmac_sha256(
            signing_key,
            self.string_to_sign.to_string(),
        )?))
    }
}

pub struct Credentials {
    access_key_id: String,
    access_secret: String,
}

impl Credentials {
    pub fn new(access_key_id: impl ToString, access_secret: impl ToString) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            access_secret: access_secret.to_string(),
        }
    }
}

pub fn presigned_url<Tz: TimeZone>(
    verb: Verb,
    host: &str,
    path: &str,
    credentials: &Credentials,
    aws_region: &str,
    aws_service: &str,
    timestamp: DateTime<Tz>,
    expires: Duration,
    query_params: impl IntoIterator<Item = (String, String)>,
    headers: impl IntoIterator<Item = (String, String)>,
) -> url::Url {
    let headers = once(("Host".to_string(), host.to_string()))
        .chain(headers)
        .collect::<Vec<_>>();
    let signed_headers = intersperse_with(headers.iter().map(|(n, _)| n.to_lowercase()), || {
        ";".to_string()
    })
    .collect::<String>();
    let mut query_params = [
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        (
            "X-Amz-Credential".to_string(),
            format!(
                "{}/{}/{}/{}/aws4_request",
                credentials.access_key_id,
                yyyymmdd(&timestamp),
                aws_region,
                aws_service
            ),
        ),
        ("X-Amz-Date".to_string(), format_date(&timestamp)),
        ("X-Amz-Expires".to_string(), expires.as_secs().to_string()),
        ("X-Amz-SignedHeaders".to_string(), signed_headers),
    ]
    .into_iter()
    .chain(query_params)
    .collect::<Vec<_>>();

    let req = CanonicalRequest::new(
        verb,
        UriEncoded(path.to_string()),
        query_params.clone(),
        headers.clone(),
    );

    println!("---CANNONICAL REQUEST---\n{}\n---\n", &req.0);

    let sts = StringToSign {
        canonical_req: req,
        timestamp,
        aws_region: aws_region.to_string(),
        aws_service: aws_service.to_string(),
    };
    println!("---STRING TO SIGN---\n{}\n---\n", sts.to_string());

    let signature = Signature {
        secret_access_key: credentials.access_secret.clone(),
        string_to_sign: sts,
    };

    let signature = signature.as_signed().expect("Valid length");
    println!("---SIGNATURE---\n{}\n---\n", signature);

    query_params.push(("X-Amz-Signature".to_string(), signature));

    let query = if query_params.is_empty() {
        String::new()
    } else {
        once("?".to_string())
            .chain(intersperse_with(
                query_params.into_iter().map(|(p, v)| {
                    format!("{}={}", urlencoding::encode(&p), urlencoding::encode(&v))
                }),
                || "&".to_string(),
            ))
            .collect::<String>()
    };

    url::Url::parse(&format!("https://{host}{path}{query}")).expect("Valid URL")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime, Utc};

    #[test]
    fn test_thingy() {
        let timestamp = chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2013, 5, 24).unwrap(),
                NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            ),
            Utc,
        );

        let req = CanonicalRequest::new(
            Verb::Get,
            UriEncoded("/test.txt".to_string()),
            [
                (
                    "X-Amz-Algorithm".to_string(),
                    "AWS4-HMAC-SHA256".to_string(),
                ),
                (
                    "X-Amz-Credential".to_string(),
                    urlencoding::decode(
                        "AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request",
                    )
                    .unwrap()
                    .to_string(),
                ),
                ("X-Amz-Date".to_string(), "20130524T000000Z".to_string()),
                ("X-Amz-Expires".to_string(), "86400".to_string()),
                ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
            ]
            .into_iter(),
            [(
                "Host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            )],
        );

        assert_eq!(
            req.0,
            "GET\n\
             /test.txt\n\
             X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\n\
             host:examplebucket.s3.amazonaws.com\n\
             \n\
             host\n\
             UNSIGNED-PAYLOAD"
        );

        let sts = StringToSign {
            canonical_req: req,
            timestamp,
            aws_region: "us-east-1".to_string(),
            aws_service: "s3".to_string(),
        };

        assert_eq!(
            sts.to_string(),
            "AWS4-HMAC-SHA256\n\
             20130524T000000Z\n\
             20130524/us-east-1/s3/aws4_request\n\
             3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04"
        );

        let sig = Signature {
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            string_to_sign: sts,
        };

        assert_eq!(
            sig.as_signed(),
            Ok("aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404".to_string())
        );
    }

    #[test]
    fn ex_aws() {
        let example_creds = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            access_secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        };

        let timestamp = chrono::DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2013, 5, 24).unwrap(),
                NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            ),
            Utc,
        );

        let url = presigned_url(
            Verb::Get,
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            &example_creds,
            "us-east-1",
            "s3",
            timestamp,
            Duration::from_secs(86400),
            [],
            [],
        );

        assert_eq!(
            url.as_str(),
            "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        )
    }
}
