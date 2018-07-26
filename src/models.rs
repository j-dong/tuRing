//! Models representing database objects.

use std::marker::PhantomData;

extern crate ring;
use self::ring::{digest, pbkdf2};

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
const HASH_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = CREDENTIAL_LEN;
/// A password hash.
/// Generated using the PBKDF2 algorithm.
pub type Credential = [u8; CREDENTIAL_LEN];
/// Password salt.
/// Random bytes to increase hash security.
pub type Salt = [u8; SALT_LEN];

/// A timestamp from the system time.
/// Represents the number of seconds since the Unix epoch.
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct Timestamp(pub u64);

/// An opaque (possible comparable) ID.
/// Guaranteed to be ordered based on creation.
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct OpaqueID<T>(u64, PhantomData<T>);

/// A user ID.
pub type UserID = OpaqueID<User>;
/// A room ID.
pub type RoomID = OpaqueID<Room>;
/// A message ID.
pub type MessageID = OpaqueID<Message>;

/// A user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// User ID.
    pub id: UserID,
    /// User email.
    pub email: String,
    /// Password hash.
    pub credential: Credential,
    /// Salt used for this user's password.
    pub salt: Salt,
    /// User name.
    pub name: String,
}

/// Room visibility.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RoomVisibility {
    /// Visible to all users.
    Public,
    /// Not publicly visible; moreover, not joinable unless invited.
    Private,
}

/// A room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Room {
    /// Room ID.
    pub id: RoomID,
    /// Room name.
    pub name: String,
    /// Room visibility.
    pub visibility: RoomVisibility,
}

/// A message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Message ID.
    pub id: MessageID,
    /// Message date.
    pub date: Timestamp,
    /// User ID.
    pub user_id: UserID,
    /// Room ID.
    pub room_id: RoomID,
    /// Message data.
    pub data: MessageData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageData {
    /// A normal, public message.
    Message {
        /// Message text.
        message: String,
    },
    /// A private message (DM).
    DirectMessage {
        /// Message text.
        message: String,
        /// Recipient of this message.
        recipient: UserID,
    },
    /// An edit of a message.
    Edit {
        /// New message text.
        new_message: String,
        /// Old message ID.
        edit_id: MessageID,
    },
    /// User join notification.
    Join,
    /// User leave notification.
    Leave,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PasswordError {
    IncorrectPassword
}

// password verification
impl User {
    fn verify_password(&self, password: &str) -> Result<(), PasswordError> {
        pbkdf2::verify(DIGEST_ALG, HASH_ITERATIONS, &self.salt, password.as_bytes(), &self.credential)
            .map_err(|_| PasswordError::IncorrectPassword)
    }
}
