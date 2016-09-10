use std::io::Read;

use hyper::method::Method;
use hyper::header::{Headers, Authorization};
use hyper::status::StatusCode;
use rustc_serialize::json;

use dto::{FromDTO, ScopeDTO as Scope, PendingFriendRequestDTO, FriendRequestDTO,
          ConfirmFriendRequestDTO, ResponseDTO, RelationshipDTO as Relationship};

use error::{Result, Error};
use super::{Client, VoidDTO};
use super::types::PendingFriendRequest;
use super::oauth::AccessToken;


/// Methods for working with friend requests.
impl Client {
    /// Creates a pending invitation to connect to the user
    pub fn send_friend_request<S: AsRef<str>>(&self,
                                              access_token: &AccessToken,
                                              user: u64,
                                              relation: Relationship,
                                              message: Option<S>)
                                              -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = FriendRequestDTO {
                origin_id: access_token.scopes().fold(0, |acc, s| match s {
                    &Scope::User(id) => id,
                    _ => acc,
                }),
                destination_id: user,
                relationship: relation,
                message: match message {
                    Some(m) => Some(String::from(m.as_ref())),
                    None => None,
                },
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}create_friend_request",
                                                              self.url),
                                                      headers,
                                                      Some(&dto)));

            match response.status {
                StatusCode::Ok => Ok(()),
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                StatusCode::Accepted => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    match json::decode::<ResponseDTO>(&response_str) {
                        Ok(r) => Err(Error::ClientError(r)),
                        Err(e) => Err(e.into()),
                    }

                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Confirms a connection
    pub fn confirm_friend_request(&self,
                                  access_token: &AccessToken,
                                  connection_id: u64,
                                  user: u64)
                                  -> Result<()> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(_) => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = ConfirmFriendRequestDTO {
                origin: user,
                destination: access_token.scopes().fold(0, |acc, s| match s {
                    &Scope::User(id) => id,
                    _ => acc,
                }),
                id: connection_id,
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}confirm_friend_request",
                                   self.url,
                                  ),
                                                      headers,
                                                      Some(&dto)));

            match response.status {
                StatusCode::Ok => Ok(()),
                StatusCode::Unauthorized => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    Err(Error::Unauthorized)
                }
                StatusCode::Accepted => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    match json::decode::<ResponseDTO>(&response_str) {
                        Ok(r) => Err(Error::ClientError(r)),
                        Err(e) => Err(e.into()),
                    }

                }
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// Gets all the pending friend requests for the given user.
    pub fn get_friend_requests(&self,
                               access_token: &AccessToken,
                               user_id: u64)
                               -> Result<Vec<PendingFriendRequest>> {
        if access_token.scopes().any(|s| match s {
            &Scope::User(u_id) => u_id == user_id,
            &Scope::Admin => true,
            _ => false,
        }) && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response =
                try!(self.send_request(Method::Get,
                                       format!("{}friend_requests/{}", self.url, user_id),
                                       headers,
                                       None::<&VoidDTO>));
            match response.status {
                StatusCode::Ok => {
                    let mut response_str = String::new();
                    let _ = try!(response.read_to_string(&mut response_str));
                    let connections: Vec<PendingFriendRequestDTO> =
                        try!(json::decode(&response_str));
                    Ok(connections.into_iter()
                        .map(|t| PendingFriendRequest::from_dto(t).unwrap())
                        .collect())
                }
                StatusCode::Unauthorized => Err(Error::Unauthorized),
                _ => Err(Error::ServerError),
            }
        } else {
            Err(Error::Unauthorized)
        }
    }
}
