
use utils::{WalletAddress, Amount, Address};
use std::collections::{BTreeSet, HashMap};
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
    last_activty: DateTime<UTC>,
    /// Whether the user is banned
    banned: Option<DateTime<UTC>>,
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
            last_activty: dto.last_activty,
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
