//! First version of the Fractal Global Credits API.

use std::result::Result;

use hyper::Client as HyperClient;
use hyper::error::Error as HyperError;
use hyper::header::Headers;
use hyper::method::Method;
use hyper::client::response::Response;

use rustc_serialize::json;
use dto::DTO;

/// Fractal API server.
pub const FRACTAL_SERVER: &'static str = "https://api.fractal.global/";
/// Fractal development API server.
pub const FRACTAL_DEV_SERVER: &'static str = "https://dev.fractal.global/";

pub mod types;
pub mod oauth;
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

#[derive(RustcDecodable, RustcEncodable)]
struct VoidDTO;
impl DTO for VoidDTO {}

impl Client {
    fn send_request<S: AsRef<str>, D: DTO>(&self,
                                           method: Method,
                                           url: S,
                                           headers: Headers,
                                           dto: Option<&D>)
                                           -> Result<Response, HyperError> {

        let body = match dto {
            Some(d) => Some(json::encode(d).unwrap()),
            None => None,
        };
        let mut response = self.client
            .request(method.clone(), url.as_ref())
            .headers(headers.clone());
        if let Some(ref b) = body {
            response = response.body(b);
        }
        let response = response.send();
        if response.is_err() {
            let mut response = self.client
                .request(method, url.as_ref())
                .headers(headers.clone());
            if let Some(ref b) = body {
                response = response.body(b);
            }
            response.send()
        } else {
            response
        }
    }
}
