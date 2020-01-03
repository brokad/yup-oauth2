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

use crate::authenticator_delegate::{DefaultFlowDelegate, FlowDelegate};
use crate::types::{ApplicationSecret, GetToken, RequestError, Token};

pub struct MetadataFlow<FD: FlowDelegate> {
    flow_delegate: FD
}

impl MetadataFlow<DefaultFlowDelegate> {
    fn new() -> Self {
        Self { flow_delegate: DefaultFlowDelegate }
    }
}

pub struct MetadataFlowImpl<FD: FlowDelegate, C: hyper::client::connect::Connect + 'static> {
    client: hyper::client::Client<C, hyper::Body>,
    fd: FD
}

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

impl<FD, C> crate::authenticator::AuthFlow<C> for MetadataFlow<FD>
where
    FD: FlowDelegate + Send + 'static,
    C: hyper::client::connect::Connect + 'static,
{
    type TokenGetter = MetadataFlowImpl<FD, C>;

    fn build_token_getter(self, client: hyper::Client<C>) -> Self::TokenGetter {
        MetadataFlowImpl {
            fd: self.flow_delegate,
            client,
        }
    }
}

impl<FD: FlowDelegate + 'static + Send + Clone, C: hyper::client::connect::Connect + 'static>
    GetToken for MetadataFlowImpl<FD, C>
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
    fn application_secret(&self) -> ApplicationSecret {
        ApplicationSecret::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Authenticator;

    #[test]
    fn test_metadata_auth_flow() {
        let mut auth = Authenticator::new(MetadataFlow::new())
            .build()
            .unwrap();
        let tok = auth.token(vec!["https://www.googleapis.com/auth/drive.file".to_string()]);
        let fut = tok.map_err(|e| println!("error: {:?}", e)).and_then(|t| {
            println!("The token is {:?}", t);
            Ok(())
        });
        tokio::run(fut);
    }
}
