use std::io::Read;
use std::str::FromStr;
use hyper::method::Method;
use hyper::header::{Headers, Authorization};
use rustc_serialize::json;

use utils::{WalletAddress, Amount};
use dto::{FromDTO, GenerateTransactionDTO, TransactionDTO, PendingTransactionDTO,
          AuthenticationCodeDTO, ResponseDTO};

use super::{Client, VoidDTO};

use error::{Result, Error};
use super::types::Transaction;
use super::oauth::AccessToken;

/// Methods for working with transactions.
impl Client {
    /// Gets the given transaction, if authorized.
    pub fn get_transaction(&self,
                           access_token: &AccessToken,
                           transaction_id: u64)
                           -> Result<Transaction> {
        if (access_token.get_user_id().is_some() || access_token.is_admin()) &&
           !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response =
                try!(self.send_request(Method::Get,
                                       format!("{}transaction/{}", self.url, transaction_id),
                                       headers,
                                       None::<&VoidDTO>));
            let mut response_str = String::new();
            let _ = try!(response.read_to_string(&mut response_str));
            let transaction: TransactionDTO = try!(json::decode(&response_str));
            Ok(try!(Transaction::from_dto(transaction)))
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin or user \
                                               token")))
        }
    }

    /// Generates a new transaction. Returns the code of the transaction
    pub fn new_transaction(&self,
                           access_token: &AccessToken,
                           receiver_wallet: WalletAddress,
                           receiver_id: u64,
                           amount: Amount)
                           -> Result<String> {
        let user_id = access_token.get_user_id();
        if user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = GenerateTransactionDTO {
                origin_id: user_id.unwrap(),
                destination_address: receiver_wallet,
                destination_id: receiver_id,
                amount: amount,
            };
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}new_transaction", self.url),
                                                      headers,
                                                      Some(&dto)));
            let mut response_str = String::new();
            let _ = try!(response.read_to_string(&mut response_str));
            Ok(try!(json::decode::<PendingTransactionDTO>(&response_str)).code)
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user  token")))
        }
    }

    /// Gets all the transactions since the given transaction
    pub fn get_all_transactions(&self,
                                access_token: &AccessToken,
                                first_transaction: u64)
                                -> Result<Vec<Transaction>> {
        if access_token.is_admin() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = try!(self.send_request(Method::Get,
                                                      format!("{}all_transactions/{}",
                                                              self.url,
                                                              first_transaction),
                                                      headers,
                                                      None::<&VoidDTO>));
            let mut response_str = String::new();
            let _ = try!(response.read_to_string(&mut response_str));
            let transactions: Vec<TransactionDTO> = try!(json::decode(&response_str));
            Ok(transactions.into_iter()
                .map(|t| Transaction::from_dto(t).unwrap())
                .collect())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired admin token")))
        }
    }

    /// Authenticates the pending transaction
    pub fn authenticate_transaction<S: AsRef<str>>(&self,
                                                   access_token: &AccessToken,
                                                   transaction_key: S,
                                                   code: u32)
                                                   -> Result<()> {
        let user_id = access_token.get_user_id();
        if user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let dto = AuthenticationCodeDTO { code: code };
            let _ = try!(self.send_request(Method::Post,
                                           format!("{}authenticate_transaction/{}",
                                                   self.url,
                                                   transaction_key.as_ref()),
                                           headers,
                                           Some(&dto)));

            Ok(())
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }


    /// Checks if the given wallet address is a valid wallet address and returns its associated
    /// user id
    pub fn get_user_id_from_wallet_address<S: AsRef<str>>(&self,
                                                          access_token: &AccessToken,
                                                          wallet_address: S)
                                                          -> Result<u64> {
        let user_id = access_token.get_user_id();
        if user_id.is_some() && !access_token.has_expired() {
            let mut headers = Headers::new();
            headers.set(Authorization(access_token.get_token()));
            let mut response = try!(self.send_request(Method::Post,
                                                      format!("{}check_wallet_address/{}",
                                                              self.url,
                                                              wallet_address.as_ref()),
                                                      headers,
                                                      None::<&VoidDTO>));

            let mut response_str = String::new();
            let _ = try!(response.read_to_string(&mut response_str));
            let res: ResponseDTO = try!(json::decode(&response_str));
            // unimplemented!()
            match u64::from_str(&res.message) {
                Ok(d) => Ok(d),
                Err(e) => {
                    println!("{:?}", e);
                    Err(Error::BadRequest(String::from("could not parse result to correct type")))
                }
            }
        } else {
            Err(Error::Forbidden(String::from("the token must be an unexpired user token")))
        }
    }
}
