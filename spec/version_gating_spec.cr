require "./spec_helper"

# Version gating of v5-only wire elements (FABLE_FINDINGS.md 1.9/2.4): a v3
# connection must reject the AUTH packet type (15 is reserved in v3,
# [MQTT-2.2.1]) and v5-only SUBACK reason codes (v3 allows only the granted
# QoS values and 0x80 Failure, [MQTT-3.9.3-2]).
private def decode(bytes : Bytes, version : MQTT::Protocol::Version)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO.for(version, mio))
end

describe "version gating" do
  it "rejects packet type 15 (AUTH) on a v3 connection" do
    expect_raises(MQTT::Protocol::Error::PacketDecode, /packet type 15/) do
      decode(Bytes[0xF0, 0x00], MQTT::Protocol::Version::V3_1_1)
    end
  end

  it "still decodes AUTH on a v5 connection" do
    packet = decode(Bytes[0xF0, 0x00], MQTT::Protocol::Version::V5)
    packet.should be_a MQTT::Protocol::Auth
  end

  it "rejects v5-only SUBACK reason codes on a v3 connection" do
    # SUBACK, packet id 1, payload byte 0x91 (PacketIdentifierInUse, v5-only).
    bytes = Bytes[0x90, 0x03, 0x00, 0x01, 0x91]
    expect_raises(MQTT::Protocol::Error::PacketDecode, /return code/) do
      decode(bytes, MQTT::Protocol::Version::V3_1_1)
    end
  end

  it "accepts the v3 SUBACK failure code 0x80" do
    bytes = Bytes[0x90, 0x03, 0x00, 0x01, 0x80]
    packet = decode(bytes, MQTT::Protocol::Version::V3_1_1).as(MQTT::Protocol::SubAck)
    packet.reason_codes.should eq [MQTT::Protocol::SubAck::ReasonCode::UnspecifiedError]
  end

  it "still accepts v5 SUBACK reason codes on a v5 connection" do
    # v5 SUBACK: packet id 1 + empty props (00) + 0x91.
    bytes = Bytes[0x90, 0x04, 0x00, 0x01, 0x00, 0x91]
    packet = decode(bytes, MQTT::Protocol::Version::V5).as(MQTT::Protocol::SubAck)
    packet.reason_codes.should eq [MQTT::Protocol::SubAck::ReasonCode::PacketIdentifierInUse]
  end
end
