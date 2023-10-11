use crate::error::InvalidMessage;
use crate::msgs::codec::{Codec, Reader};

use super::codec::TryPushBytes;

#[derive(Debug)]
pub struct ChangeCipherSpecPayload;

impl Codec for ChangeCipherSpecPayload {
    fn try_encode<B: TryPushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        1u8.try_encode(bytes)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let typ = u8::read(r)?;
        if typ != 1 {
            return Err(InvalidMessage::InvalidCcs);
        }

        r.expect_empty("ChangeCipherSpecPayload")
            .map(|_| Self {})
    }
}
