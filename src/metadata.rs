// Copyright (c) 2016 Google Inc (lewinb@google.com).
//
// Refer to the project root for licensing information.
//
use std::convert::AsRef;
use std::sync::{Arc, Mutex};

use futures::prelude::*;
use futures::stream::Stream;
use futures::sync::oneshot;
use hyper;
use hyper::{header, StatusCode, Uri};
use url::form_urlencoded;
use url::percent_encoding::{percent_encode, QUERY_ENCODE_SET};

use crate::authenticator::{DefaultHyperClient, HyperClientBuilder};
use crate::types::{ApplicationSecret, GetToken, RequestError, Token};

fn build_token_request() -> hyper::Request<hyper::Body> {
    let mut builder = hyper::Request::builder();
    let uri = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".to_string();
    builder.uri(uri)
        .header("Metadata-Flavor", "Google")
        .method("GET");
    builder.body(hyper::Body::empty()).unwrap()
}

#[derive(Deserialize)]
struct JSONTokenResponse {
    access_token: String,
    expires_in: i64,
    token_type: String
}

pub struct MetadataAccess<C> {
    client: C
}

impl MetadataAccess<DefaultHyperClient> {
    pub fn new() -> Self {
        Self { client: DefaultHyperClient }
    }
}

impl<C> MetadataAccess<C>
where
    C: HyperClientBuilder,
    C::Connector: 'static
{
    pub fn hyper_client<NewC: HyperClientBuilder>(
        self,
        hyper_client: NewC
    ) -> MetadataAccess<NewC> {
        MetadataAccess {
            client: hyper_client
        }
    }
    pub fn build(self) -> impl GetToken {
        MetadataAccessImpl::new(self.client.build_hyper_client())
    }
}

pub struct MetadataAccessImpl<C> {
    client: hyper::client::Client<C, hyper::Body>
}

impl<C> MetadataAccessImpl<C>
where
    C: hyper::client::connect::Connect
{
    fn new(client: hyper::Client<C>) -> Self {
        MetadataAccessImpl {
            client
        }
    }
}

impl<C: 'static> GetToken for MetadataAccessImpl<C>
where
    C: hyper::client::connect::Connect
{
    fn token<I, T>(
        &mut self,
        scopes: I,
    ) -> Box<dyn Future<Item = Token, Error = RequestError> + Send>
    where
        T: Into<String>,
        I: IntoIterator<Item = T>,
    {
        let op = self.client.request(build_token_request())
            .and_then(move |r| {
                r.into_body()
                    .concat2()
                    .map(|c| String::from_utf8(c.into_bytes().to_vec()).unwrap())
                        // TODO: error handling
            })
            .then(|body_or| {
                let resp = match body_or {
                    Err(e) => return Err(RequestError::ClientError(e)),
                    Ok(s) => s,
                };

                let token_resp: Result<JSONTokenResponse, serde_json::Error> =
                    serde_json::from_str(&resp);

                match token_resp {
                    Err(e) => {
                        return Err(RequestError::JSONError(e));
                    }
                    Ok(tok) => { Ok(tok) }
                }
            })
            .and_then(|tokens| {
                let mut token = Token {
                    access_token: tokens.access_token,
                    refresh_token: None,
                    token_type: tokens.token_type,
                    expires_in: Some(tokens.expires_in),
                    expires_in_timestamp: None,
                };

                token.set_expiry_absolute();
                Ok(token)
            });
        Box::new(op)
    }

    fn api_key(&mut self) -> Option<String> {
        None
    }

    /// Returns an empty ApplicationSecret as tokens for service accounts don't need to be
    /// refreshed (they are simply reissued).
    fn application_secret(&self) -> ApplicationSecret {
        ApplicationSecret::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_e2e() {
        let mut auth = MetadataAccess::new().build();
        let tok = auth.token(vec!["https://www.googleapis.com/auth/drive.file".to_string()]);
        let fut = tok.map_err(|e| println!("error: {:?}", e)).and_then(|t| {
            println!("The token is {:?}", t);
            Ok(())
        });
        tokio::run(fut);
    }
}
