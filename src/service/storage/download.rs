use crate::base::credential::Credential;

use std::time::{SystemTime, Duration, SystemTimeError, UNIX_EPOCH};
use std::convert::TryFrom;
use reqwest::{Client,Response};
use url::Url;
use std::future::Future;

pub fn sign_download_url_with_deadline(
    c :&Credential,
    url: Url,
    deadline: SystemTime,
    only_path: bool,
) -> Result<String, SystemTimeError> {
    let mut signed_url = {
        let mut s = String::with_capacity(2048);
        s.push_str(url.as_str());
        s
    };
    let mut to_sign = {
        let mut s = String::with_capacity(2048);
        if only_path {
            s.push_str(url.path());
            if let Some(query) = url.query() {
                s.push('?');
                s.push_str(query);
            }
        } else {
            s.push_str(url.as_str());
        }
        s
    };

    if to_sign.contains('?') {
        to_sign.push_str("&e=");
        signed_url.push_str("&e=");
    } else {
        to_sign.push_str("?e=");
        signed_url.push_str("?e=");
    }

    let deadline = u32::try_from(deadline.duration_since(UNIX_EPOCH)?.as_secs())
        .unwrap_or(std::u32::MAX)
        .to_string();
    to_sign.push_str(&deadline);
    signed_url.push_str(&deadline);
    signed_url.push_str("&token=");
    signed_url.push_str(&c.sign(to_sign.as_bytes()));
    Ok(signed_url)
}

pub fn sign_download_url_with_lifetime(
    c :&Credential,
    url: Url,
    lifetime: Duration,
    only_path: bool,
) -> Result<String, SystemTimeError> {
    let deadline = SystemTime::now() + lifetime;
    sign_download_url_with_deadline(c, url, deadline, only_path)
}

pub fn range_download(url :&str, range :&str) ->impl Future<Output = Result<Response, reqwest::Error>> {
    let client = Client::builder()
        .build()
        .unwrap();
    client.get(url)
        .header("Range", format!("bytes={}", range))
        .send()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{boxed::Box, error::Error, result::Result};

    #[test]
    fn test_sign_download_url_with_deadline() -> Result<(), Box<dyn Error>> {
        let credential = Credential::new("abcdefghklmnopq", "1234567890");
        assert_eq!(
            super::sign_download_url_with_deadline(&credential,
                Url::parse("http://www.qiniu.com/?go=1")?,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567_890 + 3600),
                false
            )?,
            "http://www.qiniu.com/?go=1&e=1234571490&token=abcdefghklmnopq:KjQtlGAkEOhSwtFjJfYtYa2-reE=",
        );
        assert_eq!(
            super::sign_download_url_with_deadline(&credential,
                Url::parse("http://www.qiniu.com/?go=1")?,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567_890 + 3600),
                true
            )?,
            "http://www.qiniu.com/?go=1&e=1234571490&token=abcdefghklmnopq:86uQeCB9GsFFvL2wA0mgBcOMsmk=",
        );
        Ok(())
    }
}