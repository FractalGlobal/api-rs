use std::time::Duration;

use hyper::Client as HyperClient;

use super::{Client, FRACTAL_SERVER, FRACTAL_DEV_SERVER};

/// Client creation and modification.
impl Client {
    /// Creates a new Fractal Global Credits API client.
    pub fn new() -> Client {
        Client {
            client: HyperClient::new(),
            url: format!("{}v1/", FRACTAL_SERVER),
        }
    }

    /// Creates a new Fractal Global Credits API client.
    pub fn new_with_url<S: AsRef<str>>(url: S) -> Client {
        Client {
            client: HyperClient::new(),
            url: format!("{}v1/", url.as_ref()),
        }
    }

    /// Creates a new Fractal Global Credits API development client.
    pub fn new_dev() -> Client {
        Client {
            client: HyperClient::new(),
            url: format!("{}v1/", FRACTAL_DEV_SERVER),
        }
    }

    /// Sets the read timeout for requests.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.client.set_read_timeout(timeout);
    }

    /// Sets the write timeout for requests.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.client.set_write_timeout(timeout);
    }
}
