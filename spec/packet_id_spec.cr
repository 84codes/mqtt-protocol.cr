require "./spec_helper"

# 2.2.1: a Packet Identifier is never 0. Senders assign non-zero ids
# [MQTT-2.2.1-3] [MQTT-2.2.1-4] and acks echo them [MQTT-2.2.1-5]
# [MQTT-2.2.1-6], so id 0 on any packet that carries one is a Protocol Error.
private def decode(bytes : Bytes, version : MQTT::Protocol::Version)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO.for(version, mio))
end

private def expect_packet_id_zero_rejected(bytes : Bytes, version : MQTT::Protocol::Version)
  ex = expect_raises(MQTT::Protocol::Error::ProtocolError, "packet identifier 0") do
    decode(bytes, version)
  end
  ex.reason_code.should eq 0x82u8
end

# Each packet type with an id 0, as {name, v3 bytes, v5 bytes}. v5 adds an
# empty property section (0x00) after the id where the packet has one.
PACKET_ID_ZERO = [
  {"PUBLISH QoS 1", Bytes[0x32, 0x06, 0x00, 0x01, 0x61, 0x00, 0x00, 0x78],
   Bytes[0x32, 0x07, 0x00, 0x01, 0x61, 0x00, 0x00, 0x00, 0x78]},
  {"PUBLISH QoS 2", Bytes[0x34, 0x06, 0x00, 0x01, 0x61, 0x00, 0x00, 0x78],
   Bytes[0x34, 0x07, 0x00, 0x01, 0x61, 0x00, 0x00, 0x00, 0x78]},
  {"PUBACK", Bytes[0x40, 0x02, 0x00, 0x00], Bytes[0x40, 0x02, 0x00, 0x00]},
  {"PUBREC", Bytes[0x50, 0x02, 0x00, 0x00], Bytes[0x50, 0x02, 0x00, 0x00]},
  {"PUBREL", Bytes[0x62, 0x02, 0x00, 0x00], Bytes[0x62, 0x02, 0x00, 0x00]},
  {"PUBCOMP", Bytes[0x70, 0x02, 0x00, 0x00], Bytes[0x70, 0x02, 0x00, 0x00]},
  {"SUBSCRIBE", Bytes[0x82, 0x06, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00],
   Bytes[0x82, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01, 0x61, 0x00]},
  {"SUBACK", Bytes[0x90, 0x03, 0x00, 0x00, 0x00],
   Bytes[0x90, 0x04, 0x00, 0x00, 0x00, 0x00]},
  {"UNSUBSCRIBE", Bytes[0xA2, 0x05, 0x00, 0x00, 0x00, 0x01, 0x61],
   Bytes[0xA2, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x61]},
  {"UNSUBACK", Bytes[0xB0, 0x02, 0x00, 0x00],
   Bytes[0xB0, 0x04, 0x00, 0x00, 0x00, 0x00]},
]

describe "Packet Identifier 0" do
  PACKET_ID_ZERO.each do |name, v3_bytes, v5_bytes|
    it "is a Protocol Error on a v3.1.1 #{name}" do
      expect_packet_id_zero_rejected(v3_bytes, MQTT::Protocol::Version::V3_1_1)
    end

    it "is a Protocol Error on a v5 #{name}" do
      expect_packet_id_zero_rejected(v5_bytes, MQTT::Protocol::Version::V5)
    end

    it "decodes a v5 #{name} with packet id 1" do
      bytes = v5_bytes.dup
      # The id sits right after the topic on a PUBLISH, right after the fixed
      # header everywhere else.
      bytes[name.starts_with?("PUBLISH") ? 6 : 3] = 0x01u8
      decode(bytes, MQTT::Protocol::Version::V5)
    end
  end
end
