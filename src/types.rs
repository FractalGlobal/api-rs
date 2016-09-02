//! Types returned by the API.
//!
//! This module contains all the types required by the API to enable an easier use of it.
use utils::{WalletAddress, Amount, Address};
use std::collections::{btree_set, BTreeSet, hash_map, HashMap};
use chrono::{DateTime, UTC, NaiveDate};
use dto::{UserDTO, FromDTO, FromDTOError};
use std::result::Result as StdResult;


/// Struct that holds all personal information for the user
#[derive(Clone, RustcEncodable, RustcDecodable, Debug)]
pub struct User {
    /// The unique ID of the user
    id: u64,
    /// The unique username of the user
    username: String,
    /// The users email
    email: (String, bool),
    /// The users first name
    first: Option<(String, bool)>,
    /// The users last name
    last: Option<(String, bool)>,
    /// The amount of devices the user has
    device_count: u8,
    /// The list of users wallet addresses
    wallet_addresses: BTreeSet<WalletAddress>,
    /// The checking wallet balance
    checking_balance: Amount,
    /// The cold wallet balance
    cold_balance: Amount,
    /// The users bonds
    bonds: HashMap<DateTime<UTC>, u64>,
    /// the users date of birth
    birthday: Option<(NaiveDate, bool)>,
    /// the user's phone #
    phone: Option<(String, bool)>,
    /// The users profile images
    image: Option<String>,
    /// The users Address
    address: Option<(Address, bool)>,
    /// The users sybil score
    sybil_score: i8,
    /// The users trust score
    trust_score: i8,
    /// Whether the user account is enabled
    enabled: bool,
    /// The Date the user registered
    registered: DateTime<UTC>,
    /// The time the user was last seen doing an activity
    last_activity: DateTime<UTC>,
    /// Whether the user is banned
    banned: Option<DateTime<UTC>>,
}

impl User {
    /// Gets the ID of the user.
    pub fn get_id(&self) -> u64 {
        self.id
    }

    /// Gets the username of the user.
    pub fn get_username(&self) -> &str {
        &self.username
    }

    /// Gets the email of the user.
    pub fn get_email(&self) -> &str {
        &self.email.0
    }

    /// Returns wether the email of the user has been confirmed or not.
    pub fn is_email_confirmed(&self) -> bool {
        self.email.1
    }

    /// Gets the first name of the user, if it has been set.
    pub fn get_first_name(&self) -> Option<&str> {
        match self.first {
            Some((ref f, _c)) => Some(f),
            None => None,
        }
    }

    /// Returns wether the first name of the user has been confirmed or not.
    pub fn is_first_name_confirmed(&self) -> bool {
        match self.first {
            Some((_, c)) => c,
            None => false,
        }
    }

    /// Gets the last name of the user, if it has been set.
    pub fn get_last_name(&self) -> Option<&str> {
        match self.last {
            Some((ref l, _c)) => Some(l),
            None => None,
        }
    }

    /// Returns wether the last name of the user has been confirmed or not.
    pub fn is_last_name_confirmed(&self) -> bool {
        match self.last {
            Some((_, c)) => c,
            None => false,
        }
    }

    /// Gets the device count of the user.
    pub fn get_device_count(&self) -> u8 {
        self.device_count
    }

    /// Gets an iterator through the wallet addresses of the user.
    pub fn wallet_addresses(&self) -> btree_set::Iter<WalletAddress> {
        self.wallet_addresses.iter()
    }

    /// Gets the checking balance of the user.
    pub fn get_checking_balance(&self) -> Amount {
        self.checking_balance
    }

    /// Gets the cold balance of the user.
    pub fn get_cold_balance(&self) -> Amount {
        self.cold_balance
    }

    /// Gets the bonds purchased by the user.
    pub fn bonds(&self) -> hash_map::Iter<DateTime<UTC>, u64> {
        self.bonds.iter()
    }

    /// Gets the birthday of the user, if it has been set.
    pub fn get_birthday(&self) -> Option<NaiveDate> {
        match self.birthday {
            Some((b, _c)) => Some(b),
            None => None,
        }
    }

    /// Returns wether the birthday of the user has been confirmed or not.
    pub fn is_birthday_confirmed(&self) -> bool {
        match self.birthday {
            Some((_b, c)) => c,
            None => false,
        }
    }

    /// Gets the phone of the user, if it has been set.
    pub fn get_phone(&self) -> Option<&str> {
        match self.phone {
            Some((ref p, _c)) => Some(p),
            None => None,
        }
    }

    /// Returns wether the phone of the user has been confirmed or not.
    pub fn is_phone_confirmed(&self) -> bool {
        match self.phone {
            Some((_, c)) => c,
            None => false,
        }
    }

    /// Gets the image of the user, if it has been set.
    pub fn get_image(&self) -> Option<&str> {
        match self.image {
            Some(ref i) => Some(i),
            None => None,
        }
    }

    /// Gets the address of the user, if it has been set.
    pub fn get_address(&self) -> Option<&Address> {
        match self.address {
            Some((ref a, _c)) => Some(&a),
            None => None,
        }
    }

    /// Returns wether the address of the user is confirmed or not.
    pub fn is_address_confirmed(&self) -> bool {
        match self.address {
            Some((_, c)) => c,
            None => false,
        }
    }

    /// Gets the sybil score of the user.
    pub fn get_sybil_score(&self) -> i8 {
        self.sybil_score
    }

    /// Gets the trust score of the user.
    pub fn get_trust_score(&self) -> i8 {
        self.trust_score
    }

    /// Returns wether the user is enabled or not.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Gets the registration time of the user.
    pub fn get_registration_time(&self) -> DateTime<UTC> {
        self.registered
    }

    /// Gets the last activity time of the user.
    pub fn get_last_activity(&self) -> DateTime<UTC> {
        self.last_activity
    }

    /// Returns wether the user is banned or not.
    pub fn is_banned(&self) -> bool {
        self.banned.is_none() || self.banned.unwrap() > UTC::now()
    }

    /// Returns the ban's expiration time, if it has been set.
    pub fn ban_expiration(&self) -> Option<DateTime<UTC>> {
        self.banned
    }
}

impl FromDTO<UserDTO> for User {
    fn from_dto(dto: UserDTO) -> StdResult<User, FromDTOError> {

        let first_opt = match dto.first {
            Some(first) => Some((first, dto.first_confirmed)),
            None => None,
        };

        let last_opt = match dto.last {
            Some(last) => Some((last, dto.last_confirmed)),
            None => None,
        };

        let birthday_opt = match dto.birthday {
            Some(birthday) => Some((birthday, dto.birthday_confirmed)),
            None => None,
        };

        let phone_opt = match dto.phone {
            Some(phone) => Some((phone, dto.phone_confirmed)),
            None => None,
        };

        let adress_opt = match dto.address {
            Some(address) => Some((address, dto.address_confirmed)),
            None => None,
        };

        Ok(User {
            id: dto.id,
            username: dto.username,
            email: (dto.email, dto.email_confirmed),
            first: first_opt,
            last: last_opt,
            device_count: dto.device_count,
            wallet_addresses: dto.wallet_addresses,
            checking_balance: dto.checking_balance,
            cold_balance: dto.cold_balance,
            bonds: dto.bonds,
            birthday: birthday_opt,
            phone: phone_opt,
            image: dto.image,
            address: adress_opt,
            sybil_score: dto.sybil_score,
            trust_score: dto.trust_score,
            enabled: dto.enabled,
            registered: dto.registered,
            last_activity: dto.last_activity,
            banned: dto.banned,
        })
    }
}

/// The representation of a global credit transaction
#[derive(Clone, RustcEncodable, RustcDecodable, Debug)]
pub struct Transaction {
    /// The id of the transaction
    id: u64,
    /// The origin of the transaction
    origin_user: u64,
    /// The destination of the transaction
    destination_user: u64,
    /// The destination address of the transaction
    destination: WalletAddress,
    /// The amount of the transaction
    amount: Amount,
    /// The timestamp of the transaction
    timestamp: DateTime<UTC>,
}

impl Transaction {
    /// Returns the id of the transaction
    pub fn get_id(&self) -> u64 {
        self.id
    }
    /// Retruns the id of the user receiving the transaction
    pub fn get_destination_user(&self) -> u64 {
        self.destination_user
    }
    /// Returns the wallet address receiving the transaction
    pub fn get_destination(&self) -> &WalletAddress {
        &self.destination
    }
    /// Returns the user id sending the transaction
    pub fn get_origin_user(&self) -> u64 {
        self.origin_user
    }
    /// The amount of the transaction in global credits
    pub fn get_amount(&self) -> Amount {
        self.amount
    }
    /// The timestamp of the transaction
    pub fn get_timestamp(&self) -> &DateTime<UTC> {
        &self.timestamp
    }
}
