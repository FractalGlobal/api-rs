//! First version of the Fractal Global Credits API.

use std::io::Read;

use hyper::Client as HyperClient;
use hyper::header::{Headers, Accept, qitem};
use hyper::status::StatusCode;
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use hyper::method::Method;
use hyper::client::response::Response;

use rustc_serialize::json;
use dto::{DTO, ResponseDTO};

/// Fractal API server.
pub const FRACTAL_SERVER: &'static str = "https://api.fractal.global/";
/// Fractal development API server.
pub const FRACTAL_DEV_SERVER: &'static str = "https://dev.fractal.global/";

pub mod types;
mod client;
pub mod oauth;
mod public;
mod user;
mod friends;
mod transaction;

use error::{Result, Error};

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
                                           mut headers: Headers,
                                           dto: Option<&D>)
                                           -> Result<Response> {    
        
        headers.set(Accept(vec![qitem(Mime(TopLevel::Application,
                                           SubLevel::Json,
                                           vec![(Attr::Charset, Value::Utf8)]))]));
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
        let mut response_main = response.send();
        let mut bad_status = false;
        let mut response = if response_main.is_err() {
            while !bad_status {
                let mut response = self.client
                .request(method.clone(), url.as_ref())
                .headers(headers.clone());
                if let Some(ref b) = body {
                    response = response.body(b);
                }
                response_main = response.send();
                if !response_main.is_err() {
                    bad_status = true;
                }
            }
            response_main
        } else {
            response_main
        }?;
           
        match response.status {
            StatusCode::Ok => Ok(response),
            status => {
                let mut response_str = String::new();
                let _ = response.read_to_string(&mut response_str)?;

                match status {
                    StatusCode::Forbidden => {
                        let response_dto: ResponseDTO = json::decode(&response_str)?;
                        Err(Error::Forbidden(response_dto.message))
                    }
                    StatusCode::Accepted => {
                        let response_dto: ResponseDTO = json::decode(&response_str)?;
                        Err(Error::Client(response_dto.message))
                    }
                    StatusCode::BadRequest => {
                        let response_dto: ResponseDTO = json::decode(&response_str)?;
                        Err(Error::BadRequest(response_dto.message))
                    }
                    StatusCode::NotFound => {
                        let response_dto: ResponseDTO = json::decode(&response_str)?;
                        Err(Error::NotFound(response_dto.message))
                    }
                    _ => {                      
                        let response_dto: ResponseDTO = json::decode(&response_str)?;
                        Err(Error::Server(response_dto.message))
                    }
                }
            }
        }
    }
}
