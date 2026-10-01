require "./spec_helper"

# Version gating of v5-only wire elements (FABLE_FINDINGS.md 1.9/2.4): a v3
# connection must reject the AUTH packet type (15 is reserved in v3, Table
# 2.1, section 2.2.1) and v5-only SUBACK reason codes (v3 allows only the
# granted QoS values and 0x80 Failure, [MQTT-3.9.3-2 v3.1.1]).
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

# Write-side mirrors (FABLE_FINDINGS.md 5.5/5.6): a v3 connection must also
# refuse to EMIT what it cannot express - v5-only SUBACK reason codes and the
# AUTH packet - raising before any byte goes on the wire (like write_connack)
# instead of writing an invalid packet or silently dropping the body.
describe "write-side version gating" do
  it "refuses to encode a v5-only SUBACK reason code on a v3 connection, writing nothing" do
    suback = MQTT::Protocol::SubAck.new([MQTT::Protocol::SubAck::ReasonCode::QuotaExceeded], 1u16)
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)
    expect_raises(MQTT::Protocol::Error::PacketEncode, /return code/) do
      io.write_packet(suback)
    end
    mio.to_slice.should be_empty
  end

  it "encodes the v3-expressible SUBACK codes on a v3 connection" do
    codes = [MQTT::Protocol::SubAck::ReasonCode::GrantedQos1,
             MQTT::Protocol::SubAck::ReasonCode::UnspecifiedError]
    mio = IO::Memory.new
    MQTT::Protocol::IO.v3(mio).write_packet(MQTT::Protocol::SubAck.new(codes, 1u16))
    mio.to_slice.should eq Bytes[0x90, 0x04, 0x00, 0x01, 0x01, 0x80]
  end

  it "refuses to encode AUTH on a v3 connection, writing nothing" do
    auth = MQTT::Protocol::Auth.new(MQTT::Protocol::Auth::ReasonCode::ContinueAuthentication)
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)
    expect_raises(MQTT::Protocol::Error::PacketEncode, /AUTH/) do
      io.write_packet(auth)
    end
    mio.to_slice.should be_empty
  end

  it "still encodes AUTH on a v5 connection" do
    mio = IO::Memory.new
    MQTT::Protocol::IO.v5(mio).write_packet(MQTT::Protocol::Auth.new)
    mio.to_slice.should eq Bytes[0xF0, 0x00]
  end
end
