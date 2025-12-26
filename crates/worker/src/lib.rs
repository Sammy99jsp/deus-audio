use std::{collections::HashMap, time::Duration};

use chrono::Utc;
use serde::Deserialize;
use worker::*;

#[derive(Deserialize)]
struct Params {
    shibboleth: String,
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let expected_token = env
        .var("SHIBBOLETH")
        .expect("Ensure secret `SHIBBOLETH` is set")
        .to_string();

    let Ok(Params { shibboleth: token }) = req.query::<Params>() else {
        let mut map = HashMap::new();
        map.insert("error", "Unauthorized");
        map.insert("message", "missing 'shibboleth' query param.");
        return Ok(Response::from_json(&map)?.with_status(401));
    };

    if expected_token != token {
        let mut map = HashMap::new();
        map.insert("error", "Unauthorized");
        return Ok(Response::from_json(&map)?.with_status(401));
    }

    let path = req.path();

    if path == "/podcast.xml" {
        const TEMPLATE_XML: &str = include_str!("../../../podcast.xml");
        let xml = TEMPLATE_XML.replace("{{SHIBBOLETH}}", &expected_token);
        return Ok(Response::builder()
            .body(ResponseBody::Body(xml.into_bytes()))
            .with_status(200)
            .with_headers(Headers::from_iter([("Content-Type", "application/xml")])));
    }

    let host = env
        .var("AWS_S3_HOST")
        .expect("Ensure secret `AWS_S3_HOST` is set")
        .to_string();
    let aws_region = env
        .var("AWS_REGION")
        .expect("Ensure secret `AWS_REGION` is set")
        .to_string();
    let credentials = s3::Credentials::new(
        env.var("AWS_ACCESS_KEY_ID")
            .expect("Ensure secret `AWS_ACCESS_KEY_ID` is set"),
        env.var("AWS_ACCESS_KEY_SECRET")
            .expect("Ensure secret `AWS_ACCESS_KEY_SECRET` is set"),
    );

    let expires = Duration::from_hours(24);

    let url = s3::presigned_url(
        s3::Verb::Get,
        &host,
        &path,
        &credentials,
        &aws_region,
        "s3",
        Utc::now(),
        expires,
        [],
        [],
    );

    worker::Response::redirect(url)
}
