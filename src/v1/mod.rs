//! First version of the Fractal Global Credits API.

use std::result::Result;

use hyper::Client as HyperClient;
use hyper::error::Error as HyperError;
use hyper::method::Method;
use hyper::client::response::Response;

use hyper::header::Headers;

/// Application's secret length.
pub const SECRET_LEN: usize = 20;
/// Fractal API server.
pub const FRACTAL_SERVER: &'static str = "https://api.fractal.global/";
/// Fractal development API server.
pub const FRACTAL_DEV_SERVER: &'static str = "https://dev.fractal.global/";

mod client;
mod public;
mod user;
mod friends;
mod transaction;

/// The client struct.
///
/// This struct will be in charge of connections to the Fractal Global Credits API.
pub struct Client {
    client: HyperClient,
    url: String,
}

impl Client {
    fn send_request<S: AsRef<str>>(&self,
                                   method: Method,
                                   url: S,
                                   headers: Headers,
                                   body: Option<S>)
                                   -> Result<Response, HyperError> {
        let mut response = self.client
            .request(method.clone(), url.as_ref())
            .headers(headers.clone());
        if let Some(ref b) = body {
            response = response.body(b.as_ref());
        }
        let response = response.send();
        if response.is_err() {
            let mut response = self.client
                .request(method, url.as_ref())
                .headers(headers.clone());
            if let Some(ref b) = body {
                response = response.body(b.as_ref());
            }
            response.send()
        } else {
            response
        }
    }
}
