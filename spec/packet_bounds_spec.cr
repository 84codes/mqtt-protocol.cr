require "./spec_helper"

# Regression specs for packet-boundary bounding (FABLE_FINDINGS.md 1.1/1.2).
#
# A malformed packet must never consume bytes past its declared remaining
# length: on a streaming socket those bytes belong to the next packet (desync)
# or never arrive (the parser blocks). A plain expect_raises is not enough to
# pin this - an over-read also raises eventually on a buffered IO - so each
# case appends trailing bytes and asserts the decoder's position stopped at
# the packet boundary.
private def assert_stops_at(bytes : Bytes, pos : Int32, version = MQTT::Protocol::Version::V5)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  io = MQTT::Protocol::IO.for(version, mio)
  ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { MQTT::Protocol::Packet.from_io(io) }
  ex.reason_code.should eq 0x81u8
  mio.pos.should eq pos
end

describe "packet-boundary bounding" do
  # 1.1: a fixed-size property value (here Session Expiry Interval, a four-byte
  # int) must not be read when the packet has no bytes left for it. The section
  # total (1) admits only the identifier byte; the four-byte value would come
  # out of the next packet.
  it "rejects a fixed-size property that overruns the packet without reading past it" do
    # CONNACK rem_len 4: flags (00) + reason (00) + section total 0x01 + id 0x11.
    # Trailing 0xD0 0x00 0xD0 0x00 (two PINGRESPs) must stay untouched.
    bytes = Bytes[0x20, 0x04, 0x00, 0x00, 0x01, 0x11, 0xD0, 0x00, 0xD0, 0x00]
    assert_stops_at(bytes, 6)
  end

  # 1.2: the SUBSCRIBE options byte must not be read when the last topic filter
  # exactly fills the declared remaining length.
  it "rejects a v5 SUBSCRIBE whose topic fills the packet without reading the options byte from beyond it" do
    # rem_len 6: packet id (00 01) + empty props (00) + topic prefix 00 01 + 'a'.
    # The options byte is missing; 0xD0 0x00 trails untouched.
    bytes = Bytes[0x82, 0x06, 0x00, 0x01, 0x00, 0x00, 0x01, 0x61, 0xD0, 0x00]
    assert_stops_at(bytes, 8)
  end

  it "rejects a v3 SUBSCRIBE whose topic fills the packet without reading the options byte from beyond it" do
    # rem_len 5: packet id (00 01) + topic prefix 00 01 + 'a'. No options byte.
    bytes = Bytes[0x82, 0x05, 0x00, 0x01, 0x00, 0x01, 0x61, 0xD0, 0x00]
    assert_stops_at(bytes, 7, MQTT::Protocol::Version::V3_1_1)
  end
end
