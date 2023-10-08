use std::fmt;

#[derive(Debug)]
pub enum RtpError {
    InvalidLen(usize),
    InvalidVersion(u8),
    InvalidCSRCCount(usize),
    MissingExtension,
    InvalidExtensionLength(usize),
    InvalidPadding(usize),
}

#[derive(Clone, Eq, PartialEq)]
pub struct RtpPacket<'a> {
    buf: &'a [u8],
}

#[derive(Clone, Eq, PartialEq)]
pub struct RtpExtension<'a> {
    head: u16,
    data: &'a [u8],
}

impl<'a> RtpPacket<'a> {
    // The size of the fixed part of the packet, up to and inclding SSRC.
    const HEADER_SIZE: usize = 12;
    // Fixed RTP protocol version.
    const RTP_VERSION: u8 = 2;

    pub fn from_slice(slice: &'a [u8]) -> Result<RtpPacket<'_>, RtpError> {
        let slice_len = slice.len();
        if slice_len < RtpPacket::HEADER_SIZE {
            return Err(RtpError::InvalidLen(slice_len))
        }
        let version = slice[0] >> 6;
        if version != RtpPacket::RTP_VERSION {
            return Err(RtpError::InvalidVersion(version))
        }
        let packet = RtpPacket { buf: slice };
        // The following additional validation checks are declared as complex and not always possible in the RFC 1889.
        // Perform validation here so that subsequent parsing can rely on offsets and indexes not going out of bounds.
        let ext_off = packet.extension_off();
        if ext_off > packet.buf.len() {
            return Err(RtpError::InvalidCSRCCount(packet.cc()))
        }
        if (packet.buf[0] & 0x10) != 0 && (ext_off + 4) > packet.buf.len() {
            return Err(RtpError::MissingExtension)
        }
        let ext_len = packet.extension_len();
        if (ext_off + ext_len) > packet.buf.len() {
            return Err(RtpError::InvalidExtensionLength(ext_len))
        }
        let pad_len = packet.padding();
        if (ext_off + ext_len + pad_len) > packet.buf.len() {
            return Err(RtpError::InvalidPadding(pad_len))
        }
        Ok(packet)
    }

    #[inline]
    pub fn cc(&self) -> usize {
        (self.buf[0] as usize) & 0x0F
    } 

    #[inline]
    pub fn mark(&self) -> bool {
        (self.buf[1] & 0x80) != 0
    } 

    #[inline]
    pub fn payload_type(&self) -> u8 {
        self.buf[1] & 0x7F
    } 
    
    #[inline]
    pub fn seq_number(&self) -> u16 {
        u16::from_be_bytes([self.buf[2], self.buf[3]])
    }

    #[inline]
    pub fn timestamp(&self) -> u32 {
        u32::from_be_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]])
    }

    #[inline]
    pub fn ssrc(&self) -> u32 {
        u32::from_be_bytes([self.buf[8], self.buf[9], self.buf[10], self.buf[11]])
    }

    #[inline]
    pub fn extension_off(&self) -> usize {
        // Static/minimal header size plus SSRC and CSRC elements.
        RtpPacket::HEADER_SIZE + ((self.buf[0] & 0x0F) as usize) * 4
    }

    pub fn csrc(&self) -> Vec<u32> {
        self.buf[RtpPacket::HEADER_SIZE..]
            .chunks_exact(4)
            .take(self.cc())
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect::<Vec<_>>()
    }

    // Extension length in bytes counting the extension header.
    pub fn extension_len(&self) -> usize {
        if (self.buf[0] & 0x10) == 0 {
            return 0
        }
        let off = self.extension_off();
        (u16::from_be_bytes([self.buf[off + 2], self.buf[off + 3]]) as usize) * 4 + 4
    }

    pub fn extension(&self) -> Option<RtpExtension> {
        let ext_len = self.extension_len();
        if ext_len == 0 {
            return None
        }
        let off = self.extension_off();
        let ext = RtpExtension {
            head: u16::from_be_bytes([self.buf[off], self.buf[off + 1]]),
            data: &self.buf[(off + 4)..(off + ext_len)],
        };
        Some(ext)
    }

    pub fn padding(&self) -> usize {
        let total_len = self.buf.len();
        if (self.buf[0] & 0x20) != 0 {
            return self.buf[total_len - 1] as usize;
        }
        0
    }

    pub fn payload(&self) -> &[u8] {
        let total_len = self.buf.len();
        let pad_len = self.padding();
        let off: usize = RtpPacket::HEADER_SIZE + self.cc() * 4 + self.extension_len();
        &self.buf[off..(total_len - pad_len)]
    }
}

impl<'a> fmt::Debug for RtpPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("RtpPacket")
            .field("cc", &self.cc())
            .field("mark", &self.mark())
            .field("payload_type", &self.payload_type())
            .field("seq_number", &self.seq_number())
            .field("timestamp", &self.timestamp())
            .field("ssrc", &self.ssrc())
            .field("csrc", &self.csrc())
            .field("extension", &self.extension())
            .field("payload_len", &self.payload().len())
            .finish()
    }
}


impl<'a> fmt::Debug for RtpExtension<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("RtpExtension")
            .field("head", &self.head)
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_version_packet() {
        let data: [u8; 25] = [
            0x70, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 
            0x98, 0x36, 0xbe, 0x88, 0x06,
        ];
        let error = RtpPacket::from_slice(&data).unwrap_err();
        assert!(matches!(error, RtpError::InvalidVersion(1)))
    }

    #[test]
    fn parse_invalid_extension_packet() {
        let data: [u8; 16] = [
            0x90, 0x60, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0x99, 0x99, 0x99, 0x99,
        ];
        let error = RtpPacket::from_slice(&data).unwrap_err();
        assert!(matches!(error, RtpError::InvalidExtensionLength(157288)))
    }

    #[test]
    fn parse_missing_extension_packet() {
        let data: [u8; 12] = [
            0x90, 0x60, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82,
        ];
        let error = RtpPacket::from_slice(&data).unwrap_err();
        assert!(matches!(error, RtpError::MissingExtension))
    }

    #[test]
    fn parse_basic_packet() {
        let data: [u8; 25] = [
            0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 
            0x98, 0x36, 0xbe, 0x88, 0x9e,
        ];
        let packet = RtpPacket::from_slice(&data).unwrap();
        assert!(packet.extension().is_some());
        assert_eq!(0, packet.cc());
        assert!(packet.mark());
        assert_eq!(96, packet.payload_type());
        assert_eq!(27023, packet.seq_number());
        assert_eq!(3653407706, packet.timestamp());
        assert_eq!(476325762, packet.ssrc());
        assert_eq!(5, packet.payload().len());
    }

    #[test]
    fn parse_padded_packet() {
        let data: [u8; 25] = [
            0xb0, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 
            0x98, 0x36, 0xbe, 0x88, 0x04,
        ];
        let packet = RtpPacket::from_slice(&data).unwrap();
        assert!(packet.extension().is_some());
        assert_eq!(0, packet.cc());
        assert!(packet.mark());
        assert_eq!(96, packet.payload_type());
        assert_eq!(27023, packet.seq_number());
        assert_eq!(3653407706, packet.timestamp());
        assert_eq!(476325762, packet.ssrc());
        assert_eq!(1, packet.payload().len());
    }

    #[test]
    fn parse_padded_only_packet() {
        let data: [u8; 25] = [
            0xb0, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 
            0x98, 0x36, 0xbe, 0x88, 0x05,
        ];
        let packet = RtpPacket::from_slice(&data).unwrap();
        assert!(packet.extension().is_some());
        assert_eq!(0, packet.cc());
        assert!(packet.mark());
        assert_eq!(96, packet.payload_type());
        assert_eq!(27023, packet.seq_number());
        assert_eq!(3653407706, packet.timestamp());
        assert_eq!(476325762, packet.ssrc());
        assert_eq!(0, packet.payload().len());
    }

    #[test]
    fn parse_excess_padding_packet() {
        let data: [u8; 25] = [
            0xb0, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 
            0x98, 0x36, 0xbe, 0x88, 0x06,
        ];
        let error = RtpPacket::from_slice(&data).unwrap_err();
        assert!(matches!(error, RtpError::InvalidPadding(6)))
    }

    #[test]
    fn parse_no_padding_flag_packet() {
        let data: [u8; 25] = [
            0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 
            0x00, 0x00, 0x00, 0x00, 0x05,
        ];
        let packet = RtpPacket::from_slice(&data).unwrap();
        assert!(packet.extension().is_some());
        assert_eq!(0, packet.cc());
        assert!(packet.mark());
        assert_eq!(96, packet.payload_type());
        assert_eq!(27023, packet.seq_number());
        assert_eq!(3653407706, packet.timestamp());
        assert_eq!(476325762, packet.ssrc());
        assert_eq!(5, packet.payload().len());
    }

    #[test]
    fn parse_one_extension_packet() {
        let data: [u8; 25] = [
            0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0xBE, 0xDE, 0x00, 0x01, 0x50, 0xAA, 0x00, 0x00,
		    0x98, 0x36, 0xbe, 0x88, 0x9e,
        ];
        let packet = RtpPacket::from_slice(&data).unwrap();
        assert!(packet.extension().is_some());
        if let Some(extension) = packet.extension() {
            assert_eq!(4, extension.data.len());
        }
    }
}
