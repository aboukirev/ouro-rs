use std::fmt;
use rand::Rng;

#[derive(Debug)]
pub enum RtpError {
    InvalidLen(usize),
    InvalidVersion(u8),
    InvalidCSRCCount(u8),
    MissingExtension,
    InvalidExtensionLength(usize),
    InvalidPadding(usize),
}

#[derive(Clone, Eq, PartialEq)]
pub struct RtpPacket<'a> {
    cc: u8,
    payload_type: u8,
    seq_number: u16,
    timestamp: u32,
    ssrc: u32,
    csrc: [u32; 15],
    extension: Option<RtpExtension<'a>>,
    payload: &'a [u8],
    mark: bool,
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

    pub fn new(
        mark: bool,
        payload_type: u8,
        seq_number: u16,
        timestamp: u32,
        ssrc: u32,
        payload: &'a [u8],
    ) -> RtpPacket<'_> {
        RtpPacket { 
            cc: 0u8, 
            payload_type: payload_type, 
            seq_number: seq_number, 
            timestamp: timestamp, 
            ssrc: ssrc, 
            csrc: [0u32; 15], 
            extension: None, 
            payload: payload, 
            mark: mark, 
        }
    }

    pub fn from_slice(slice: &'a [u8]) -> Result<RtpPacket<'_>, RtpError> {
        let slice_len = slice.len();
        if slice_len < RtpPacket::HEADER_SIZE {
            return Err(RtpError::InvalidLen(slice_len))
        }
        let version = slice[0] >> 6;
        if version != RtpPacket::RTP_VERSION {
            return Err(RtpError::InvalidVersion(version))
        }
        let cc = slice[0] & 0x0F;
        let mut csrc = [0u32; 15];
        let pad_flag = (slice[0] & 0x20) >> 5;  // 0 or 1
        let mut off = RtpPacket::HEADER_SIZE + (cc as usize) * 4;

        for index in 0..cc as usize {
            let csrc_off = off + (cc as usize) * 4;
            csrc[index] = u32::from_be_bytes([slice[csrc_off], slice[csrc_off + 1], slice[csrc_off + 2], slice[csrc_off + 3]])
        }

        // The following additional validation checks are declared as complex and not always possible in the RFC 1889.
        if off > slice_len {
            return Err(RtpError::InvalidCSRCCount(cc))
        }
        let mut extension: Option<RtpExtension> = None;
        if (slice[0] & 0x10) != 0 {
            if (off + 4) > slice_len {
                return Err(RtpError::MissingExtension)
            }
            let ext_len = (u16::from_be_bytes([slice[off + 2], slice[off + 3]]) as usize) * 4 + 4;
            if (off + ext_len) > slice_len {
                return Err(RtpError::InvalidExtensionLength(ext_len))
            }
            extension = Some(RtpExtension {
                head: u16::from_be_bytes([slice[off], slice[off + 1]]),
                data: &slice[(off + 4)..(off + ext_len)],
            });
            off += ext_len;
        }
        let pad_len = (slice[slice_len - 1] * pad_flag) as usize;
        if (off + pad_len) > slice_len {
            return Err(RtpError::InvalidPadding(pad_len))
        }

        Ok(RtpPacket { 
            cc: cc, 
            payload_type: slice[1] & 0x7F, 
            seq_number: u16::from_be_bytes([slice[2], slice[3]]), 
            timestamp: u32::from_be_bytes([slice[4], slice[5], slice[6], slice[7]]), 
            ssrc: u32::from_be_bytes([slice[8], slice[9], slice[10], slice[11]]), 
            csrc: csrc, 
            extension: extension, 
            payload: &slice[off..(slice_len - pad_len)], 
            mark: (slice[1] & 0x80) != 0, 
        })
    }
}

impl<'a> fmt::Debug for RtpPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("RtpPacket")
            .field("cc", &self.cc)
            .field("mark", &self.mark)
            .field("payload_type", &self.payload_type)
            .field("seq_number", &self.seq_number)
            .field("timestamp", &self.timestamp)
            .field("ssrc", &self.ssrc)
            .field("csrc", &self.csrc)
            .field("extension", &self.extension)
            .field("payload_len", &self.payload.len())
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

pub struct RtpPacketizer {
    mtu: usize,
    payload_type: u8,
    seq_number: u16,
    timestamp: u32,
    ssrc: u32,
}

impl RtpPacketizer {
    pub fn new(
        mtu: usize,
        payload_type: u8,
        ssrc: u32,
    ) -> Self {
        let mut rng = rand::thread_rng();
        RtpPacketizer { 
            mtu: mtu, 
            payload_type: payload_type, 
            seq_number: rng.gen::<u16>(), 
            timestamp: rng.gen::<u32>(), 
            ssrc: ssrc, 
        }
    }

    pub fn packetize<'a>(&'a mut self, payload: &'a [u8], frames: u32) -> Vec<RtpPacket<'_>> {
        self.timestamp = self.timestamp.wrapping_add(frames);
        // At this point assume just a standard fixed header, no csrc, no extension.  Only the last chunk may require padding.
        let chunk_size = self.mtu - RtpPacket::HEADER_SIZE;
        let chunk_count = payload.len().div_ceil(chunk_size);
        let mut packets = Vec::<RtpPacket>::with_capacity(chunk_count);

        for index in 0..chunk_count {
            self.seq_number = self.seq_number.wrapping_add(1);
            let off = chunk_size * index;
            let span = usize::min(chunk_size, payload.len() - off);

            packets.push(RtpPacket::new(
                index == (chunk_count - 1),
                self.payload_type,
                self.seq_number,  
                self.timestamp, 
                self.ssrc,
                &payload[off..off + span], 
            ))
        }
        packets
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
        assert!(packet.extension.is_some());
        assert_eq!(0, packet.cc);
        assert!(packet.mark);
        assert_eq!(96, packet.payload_type);
        assert_eq!(27023, packet.seq_number);
        assert_eq!(3653407706, packet.timestamp);
        assert_eq!(476325762, packet.ssrc);
        assert_eq!(5, packet.payload.len());
    }

    #[test]
    fn parse_padded_packet() {
        let data: [u8; 25] = [
            0xb0, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 
            0x98, 0x36, 0xbe, 0x88, 0x04,
        ];
        let packet = RtpPacket::from_slice(&data).unwrap();
        assert!(packet.extension.is_some());
        assert_eq!(0, packet.cc);
        assert!(packet.mark);
        assert_eq!(96, packet.payload_type);
        assert_eq!(27023, packet.seq_number);
        assert_eq!(3653407706, packet.timestamp);
        assert_eq!(476325762, packet.ssrc);
        assert_eq!(1, packet.payload.len());
    }

    #[test]
    fn parse_padded_only_packet() {
        let data: [u8; 25] = [
            0xb0, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 
            0x98, 0x36, 0xbe, 0x88, 0x05,
        ];
        let packet = RtpPacket::from_slice(&data).unwrap();
        assert!(packet.extension.is_some());
        assert_eq!(0, packet.cc);
        assert!(packet.mark);
        assert_eq!(96, packet.payload_type);
        assert_eq!(27023, packet.seq_number);
        assert_eq!(3653407706, packet.timestamp);
        assert_eq!(476325762, packet.ssrc);
        assert_eq!(0, packet.payload.len());
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
        assert!(packet.extension.is_some());
        assert_eq!(0, packet.cc);
        assert!(packet.mark);
        assert_eq!(96, packet.payload_type);
        assert_eq!(27023, packet.seq_number);
        assert_eq!(3653407706, packet.timestamp);
        assert_eq!(476325762, packet.ssrc);
        assert_eq!(5, packet.payload.len());
    }

    #[test]
    fn parse_one_extension_packet() {
        let data: [u8; 25] = [
            0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		    0x27, 0x82, 0xBE, 0xDE, 0x00, 0x01, 0x50, 0xAA, 0x00, 0x00,
		    0x98, 0x36, 0xbe, 0x88, 0x9e,
        ];
        let packet = RtpPacket::from_slice(&data).unwrap();
        assert!(packet.extension.is_some());
        if let Some(extension) = packet.extension {
            assert_eq!(4, extension.data.len());
        }
    }

    #[test]
    fn packetize_two_packets() {
        let data = [0u8; 128];
        let mut packetizer = RtpPacketizer::new(100, 98, 0x1234ABCD);
        let packets = packetizer.packetize(&data, 2000);
        assert_eq!(2, packets.len());
        let packet = packets.get(1).unwrap();
        assert!(packet.extension.is_none());
        assert_eq!(0, packet.cc);
        assert!(packet.mark);
        assert_eq!(98, packet.payload_type);
        assert_eq!(0x1234ABCD, packet.ssrc);
        assert_eq!(40, packet.payload.len());
    }
}
