use std::io::Read;

use hyper::method::Method;
use hyper::header::{Headers, Authorization};
use rustc_serialize::json;

use dto::{ResponseDTO,FromDTO, PendingFriendRequestDTO, FriendRequestDTO, ConfirmFriendRequestDTO, ProfileDTO,
          RelationshipDTO as Relationship};
use hyper::status::StatusCode;
use error::{Result, Error};
use super::{Client, VoidDTO};
use super::types::{PendingFriendRequest, Profile};
use super::oauth::AccessToken;


/// Methods for working with friend requests.
impl Client {
    /// Creates a pending invitation to connect to the user
    pub fn send_friend_request<M: Into<String>>(&self,
                                                access_token: &AccessToken,
                                                user: u64,
                                                relation: Relationship,
                                                message: Option<M>)
                                                -> Result<(ResponseDTO)> {
        let user_id = access_token.get_user_id();
        if user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = FriendRequestDTO {
                origin_id: user_id.unwrap(),
                destination_id: user,
                relationship: relation,
                message: message.and_then(|mess| Some(mess.into())),
            };
            let mut response = self.send_request(Method::Post,
                              format!("{}create_friend_request", self.url),
                              headers,
                              Some(&dto))?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            let res: ResponseDTO = json::decode(&response_str)?;
            match response.status {
                StatusCode::Ok => {
                    Ok(res)
                }
                StatusCode::Accepted => {
                    Ok(res)
                }
                _ => {
                    Err(Error::Forbidden(json::decode::<ResponseDTO>(&response_str)?.message))
                }
            }
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

    /// Confirms a connection
    pub fn confirm_friend_request(&self,
                                  access_token: &AccessToken,
                                  request_id: u64,
                                  user: u64)
                                  -> Result<(ResponseDTO)> {
        let user_id = access_token.get_user_id();
        if user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = ConfirmFriendRequestDTO {
                request_id: request_id,
                origin: user,
                destination: user_id.unwrap(),
            };
            let mut response = self.send_request(Method::Post,
                              format!("{}confirm_friend_request",
                                   self.url,
                                  ),
                              headers,
                              Some(&dto))?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            match response.status {
                StatusCode::Ok => {
                    let res: ResponseDTO = json::decode(&response_str)?;
                    Ok(res)
                }
                _ => {
                    Err(Error::Forbidden(json::decode::<ResponseDTO>(&response_str)?.message))
                }
            }
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

    /// Gets all the pending friend requests for the given user.
    pub fn get_friend_requests(&self,
                               access_token: &AccessToken,
                               user_id: u64)
                               -> Result<Vec<PendingFriendRequest>> {
        if (access_token.is_admin() || access_token.is_user(user_id)) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}friend_requests/{}", self.url, user_id),
                              headers,
                              None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            let connections: Vec<PendingFriendRequestDTO> = json::decode(&response_str)?;
            Ok(connections.into_iter()
                .map(|t| PendingFriendRequest::from_dto(t).unwrap())
                .collect())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user or admin \
                                               token, and in the case of an user token, the ID \
                                               in the token must be the same as the given ID")))
        }
    }

    /// Returns the given users friends
    pub fn get_friends(&self, access_token: &AccessToken, user_id: u64) -> Result<Vec<Profile>> {
        if (access_token.is_admin() || access_token.is_user(user_id)) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}friends/{}", self.url, user_id),
                              headers,
                              None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            let friends: Vec<ProfileDTO> = json::decode(&response_str)?;
            Ok(friends.into_iter()
                .map(|f| Profile::from_dto(f).unwrap())
                .collect())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user or admin \
                                               token, and in the case of an user token, the ID \
                                               in the token must be the same as the given ID")))
        }
    }

    /// Rejects the friend request for the given user
    pub fn reject_friend_request(&self, access_token: &AccessToken, request_id: u64) 
                                -> Result<(ResponseDTO)> {

        if access_token.get_user_id().is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Post,
                              format!("{}reject_friend_request/{}", self.url, request_id),
                              headers,
                              None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            match response.status {
                StatusCode::Ok => {
                    let res: ResponseDTO = json::decode(&response_str)?;
                    Ok(res)
                }
                _ => {
                    Err(Error::Forbidden(json::decode::<ResponseDTO>(&response_str)?.message))
                }
            }
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user or admin \
                                               token, and in the case of an user token, the ID \
                                               in the token must be the same as the given ID")))
        }
    }
    
    /// Unfriends the given user
    pub fn unfriend(&self, access_token: &AccessToken, request_id: u64) -> Result<()> {

        if access_token.get_user_id().is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let _ = self.send_request(Method::Delete,
                              format!("{}friend/{}", self.url, request_id),
                              headers,
                              None::<&VoidDTO>)?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user or admin \
                                               token, and in the case of an user token, the ID \
                                               in the token must be the same as the given ID")))
        }
    }
}
