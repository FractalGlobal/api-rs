use std::io::Read;

use hyper::method::Method;
use hyper::header::{Headers, Authorization};
use rustc_serialize::json;

use chrono::NaiveDate;
use utils::Address;
use dto::{FromDTO, UserDTO, ProfileDTO, AuthenticationCodeDTO, ResponseDTO, UpdateUserDTO,
          SearchUserDTO};
use hyper::status::StatusCode;
use super::{Client, VoidDTO};
use error::{Result, Error};
use super::types::{User, Profile};
use super::oauth::AccessToken;

/// User methods for the client.
///
/// This are the user getters, setters and creators for the client.
impl Client {
    /// Resends the email confirmation
    pub fn resend_email_confirmation(&self, access_token: &AccessToken) -> Result<(ResponseDTO)> {
        if access_token.get_user_id().is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}resend_email_confirmation", self.url),
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
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

    /// Resends the unsubscribe email confirmation
    pub fn unsubscribe_email_confirmation(&self, access_token: &AccessToken) -> Result<()> {
        if access_token.get_user_id().is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let _ = self.send_request(Method::Get,
                              format!("{}unsubscribe_email_confirmation", self.url),
                              headers,
                              None::<&VoidDTO>)?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

    /// Get the unlogged user profile
    pub fn get_unlogged_user(&self, access_token: &AccessToken, user_id: u64) -> Result<User> {
        let logged_user_id = access_token.get_user_id();
        if logged_user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}get_unlogged_user/{}", self.url, user_id),
                              headers,
                              None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            Ok(User::from_dto(json::decode::<UserDTO>(&response_str)?)?)
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

    /// Get the user
    pub fn get_user(&self, access_token: &AccessToken, user_id: u64) -> Result<User> {
        if (access_token.is_user(user_id) || access_token.is_admin()) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}user/{}", self.url, user_id),
                              headers,
                              None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            Ok(User::from_dto(json::decode::<UserDTO>(&response_str)?)?)
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token, and in the case of a user token, the ID \
                                               in the token must match the given ID")))
        }
    }

    /// Gets the logged in users info
    pub fn get_me(&self, access_token: &AccessToken) -> Result<User> {
        let user_id = access_token.get_user_id();
        if user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}user/{}", self.url, user_id.unwrap()),
                              headers,
                              None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            Ok(User::from_dto(json::decode::<UserDTO>(&response_str)?)?)
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

    /// Gets all users.
    pub fn get_all_users(&self, access_token: &AccessToken) -> Result<Vec<User>> {
        if access_token.is_admin() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}all_users", self.url),
                              headers,
                              None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            let dto_users: Vec<UserDTO> = json::decode(&response_str)?;
            Ok(dto_users.into_iter()
                .filter_map(|u| match User::from_dto(u) {
                    Ok(u) => Some(u),
                    Err(_) => None,
                })
                .collect())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin token")))
        }
    }

    /// Deletes the given user.
    pub fn delete_user(&self, access_token: &AccessToken, user_id: u64) -> Result<()> {
        if access_token.is_admin() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let _ = self.send_request(Method::Delete,
                              format!("{}user/{}", self.url, user_id),
                              headers,
                              None::<&VoidDTO>)?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin token")))
        }
    }

    // TODO update user

    /// Generates a new authenticator code, and returns the URL.
    pub fn generate_authenticator_code(&self, access_token: &AccessToken) -> Result<String> {
        if access_token.get_user_id().is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}generate_authenticator_code", self.url),
                              headers,
                              None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            Ok(json::decode::<ResponseDTO>(&response_str)?.message)
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

    /// Authenticates the user with 2FA
    pub fn authenticate(&self, access_token: &AccessToken, code: u32) -> Result<()> {
        if access_token.get_user_id().is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = AuthenticationCodeDTO { code: code };
            let _ = self.send_request(Method::Post,
                              format!("{}authenticate", self.url),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }


    /// Sets the users username
    pub fn set_username<U: Into<String>>(&self,
                                         access_token: &AccessToken,
                                         user_id: u64,
                                         username: U)
                                         -> Result<()> {
        if (access_token.is_user(user_id) || access_token.is_admin()) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: Some(username.into()),
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: None,
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let _ = self.send_request(Method::Post,
                              format!("{}update_user/{}", self.url, user_id),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token, and in the case of a user token, the ID \
                                               in the token must match the given ID")))
        }
    }

    /// Sets the users phone
    pub fn set_phone<P: Into<String>>(&self,
                                      access_token: &AccessToken,
                                      user_id: u64,
                                      phone: P)
                                      -> Result<()> {
        if (access_token.is_user(user_id) || access_token.is_admin()) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: None,
                new_password: None,
                new_phone: Some(phone.into()),
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let _ = self.send_request(Method::Post,
                              format!("{}update_user/{}", self.url, user_id),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token, and in the case of a user token, the ID \
                                               in the token must match the given ID")))
        }
    }

    /// Sets the users birthday
    pub fn set_birthday(&self,
                        access_token: &AccessToken,
                        user_id: u64,
                        birthday: NaiveDate)
                        -> Result<()> {
        if (access_token.is_user(user_id) || access_token.is_admin()) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: None,
                new_password: None,
                new_phone: None,
                new_birthday: Some(birthday),
                new_image: None,
                new_address: None,
            };
            let _ = self.send_request(Method::Post,
                              format!("{}update_user/{}", self.url, user_id),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token, and in the case of a user token, the ID \
                                               in the token must match the given ID")))
        }
    }

    /// Sets the users first and last name
    pub fn set_name<F: Into<String>, L: Into<String>>(&self,
                                                      access_token: &AccessToken,
                                                      user_id: u64,
                                                      first: F,
                                                      last: L)
                                                      -> Result<()> {
        if (access_token.is_user(user_id) || access_token.is_admin()) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: Some(first.into()),
                new_last: Some(last.into()),
                old_password: None,
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let _ = self.send_request(Method::Post,
                              format!("{}update_user/{}", self.url, user_id),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token, and in the case of a user token, the ID \
                                               in the token must match the given ID")))
        }
    }

    /// Sets the users email
    pub fn set_email<E: Into<String>>(&self,
                                      access_token: &AccessToken,
                                      user_id: u64,
                                      email: E)
                                      -> Result<()> {
        if (access_token.is_user(user_id) || access_token.is_admin()) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: Some(email.into()),
                new_first: None,
                new_last: None,
                old_password: None,
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let _ = self.send_request(Method::Post,
                              format!("{}update_user/{}", self.url, user_id),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token, and in the case of a user token, the ID \
                                               in the token must match the given ID")))
        }
    }

    /// Sets the users profile picture to the given URL
    pub fn set_image<I: Into<String>>(&self,
                                      access_token: &AccessToken,
                                      user_id: u64,
                                      image_url: I)
                                      -> Result<()> {
        if (access_token.is_user(user_id) || access_token.is_admin()) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: None,
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: Some(image_url.into()),
                new_address: None,
            };
            let _ = self.send_request(Method::Post,
                              format!("{}update_user/{}", self.url, user_id),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token, and in the case of a user token, the ID \
                                               in the token must match the given ID")))
        }
    }

    /// Sets the users address
    pub fn set_address(&self,
                       access_token: &AccessToken,
                       user_id: u64,
                       address: Address)
                       -> Result<()> {
        if (access_token.is_user(user_id) || access_token.is_admin()) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: None,
                new_password: None,
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: Some(address),
            };
            let _ = self.send_request(Method::Post,
                              format!("{}update_user/{}", self.url, user_id),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token, and in the case of a user token, the ID \
                                               in the token must match the given ID")))
        }
    }

    /// Sets the user password
    pub fn set_password<O: Into<String>, N: Into<String>>(&self,
                                                          access_token: &AccessToken,
                                                          old_password: O,
                                                          new_password: N)
                                                          -> Result<()> {
        let user_id = access_token.get_user_id();
        if user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = UpdateUserDTO {
                new_username: None,
                new_email: None,
                new_first: None,
                new_last: None,
                old_password: Some(old_password.into()),
                new_password: Some(new_password.into()),
                new_phone: None,
                new_birthday: None,
                new_image: None,
                new_address: None,
            };
            let _ = self.send_request(Method::Post,
                              format!("{}update_user/{}", self.url, user_id.unwrap()),
                              headers,
                              Some(&dto))?;
            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

    /// Searches users doing a random search with the given string. It will try to find the string
    /// in names, emails etc.
    ///
    /// It will panic if the `include_me` or `include_friends` variables are set and the token is
    /// not an user scoped token.
    pub fn search_user_random<R: Into<String>>(&self,
                                               access_token: &AccessToken,
                                               random: R,
                                               include_me: bool,
                                               include_friends: bool)
                                               -> Result<Vec<Profile>> {
        let user_id = access_token.get_user_id();
        if (access_token.is_public() || user_id.is_some()) && !access_token.has_expired() {
            if (include_me || include_friends) && user_id.is_none() {
                panic!("to include the current user or friends the token must be a user scoped \
                        token");
            }
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = SearchUserDTO {
                random: Some(random.into()),
                username: None,
                email: None,
                first_name: None,
                last_name: None,
                age: None,
                country: None,
                state: None,
                city: None,
                phone: None,
                all: false,
                include_me: include_me,
                include_friends: include_friends,
            };
            let mut response = self.send_request(Method::Post,
                              format!("{}search_user", self.url),
                              headers,
                              Some(&dto))?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            let dto_users: Vec<ProfileDTO> = json::decode(&response_str)?;
            Ok(dto_users.into_iter()
                .filter_map(|u| match Profile::from_dto(u) {
                    Ok(u) => Some(u),
                    Err(_) => None,
                })
                .collect())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired public or user \
                                               token")))
        }
    }
    ///sends address confirmation
    pub fn send_address_confirmation(&self, access_token: &AccessToken) -> Result<(ResponseDTO)> {
        if access_token.get_user_id().is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}send_address_confirmation", self.url),
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
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

    ///initiates user verification
    pub fn initiate_user_verification(&self, access_token: &AccessToken) -> Result<(ResponseDTO)> {
        if access_token.get_user_id().is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Post,
                            format!("{}initiate_user_verification", self.url),
                            headers,
                            None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            let res: ResponseDTO = json::decode(&response_str)?;
            match response.status {
                StatusCode::Ok => {
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

    /// Generates a new authenticator code, and returns the URL.
    pub fn get_user_verification_status(&self, access_token: &AccessToken) -> Result<String> {
        if access_token.get_user_id().is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = self.send_request(Method::Get,
                              format!("{}get_user_verification_status/{}", self.url, access_token.get_user_id().unwrap()),
                              headers,
                              None::<&VoidDTO>)?;
            let mut response_str = String::new();
            let _ = response.read_to_string(&mut response_str)?;
            Ok(json::decode::<ResponseDTO>(&response_str)?.message)
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }

}
