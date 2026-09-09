require "./spec_helper"

# DISCONNECT (promoted out of SimplePacket) and the new AUTH packet
# (MQTT5_FINDINGS.md section 4).
#
# Both share the same omission rules: an empty remaining length means the
# Normal/Success reason code with no properties; a remaining length of 1 is a
# bare reason code; anything larger carries a properties section after it.

private def encode_v5(packet)
  mio = IO::Memory.new
  io = MQTT::Protocol::IO.v5(mio)
  packet.to_io(io)
  mio.to_slice
end

private def decode_v5(bytes : Bytes)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  io = MQTT::Protocol::IO.v5(mio)
  MQTT::Protocol::Packet.from_io(io)
end

private def encode_v3(packet)
  mio = IO::Memory.new
  io = MQTT::Protocol::IO.v3(mio)
  packet.to_io(io)
  mio.to_slice
end

describe MQTT::Protocol::Disconnect do
  it "encodes a normal disconnect as an empty payload" do
    encode_v5(MQTT::Protocol::Disconnect.new).should eq Bytes[0xE0, 0x00]
  end

  it "tolerates an empty payload on decode as Normal disconnection" do
    disconnect = decode_v5(Bytes[0xE0, 0x00]).as(MQTT::Protocol::Disconnect)
    disconnect.reason_code.should eq MQTT::Protocol::Disconnect::ReasonCode::NormalDisconnection
    disconnect.properties.empty?.should be_true
  end

  it "encodes a bare reason code (remaining length 1) when no properties" do
    disconnect = MQTT::Protocol::Disconnect.new(
      reason_code: MQTT::Protocol::Disconnect::ReasonCode::UnspecifiedError,
    )
    encode_v5(disconnect).should eq Bytes[0xE0, 0x01, 0x80]
  end

  it "encodes reason code and properties" do
    disconnect = MQTT::Protocol::Disconnect.new(
      reason_code: MQTT::Protocol::Disconnect::ReasonCode::UnspecifiedError,
      properties: MQTT::Protocol::DisconnectProperties.new(reason_string: "bye"),
    )
    # 0xE0, rem_len 8, reason(80), props(06 1F 00 03 b y e)
    encode_v5(disconnect).should eq Bytes[
      0xE0, 0x08, 0x80,
      0x06, 0x1F, 0x00, 0x03, 'b'.ord, 'y'.ord, 'e'.ord,
    ]
  end

  it "round-trips reason code and properties" do
    disconnect = MQTT::Protocol::Disconnect.new(
      reason_code: MQTT::Protocol::Disconnect::ReasonCode::SessionTakenOver,
      properties: MQTT::Protocol::DisconnectProperties.new(
        session_expiry_interval: 0u32,
        reason_string: "taken over",
        user_properties: [{"a", "b"}],
        server_reference: "other.example.com",
      ),
    )
    decoded = decode_v5(encode_v5(disconnect)).as(MQTT::Protocol::Disconnect)
    decoded.reason_code.should eq MQTT::Protocol::Disconnect::ReasonCode::SessionTakenOver
    decoded.properties.server_reference.should eq "other.example.com"
  end

  it "encodes a v3 DISCONNECT as an empty payload" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)
    MQTT::Protocol::Disconnect.new.to_io(io)
    mio.to_slice.should eq Bytes[0xE0, 0x00]
  end

  it "reports a bytesize matching the v5 serialization" do
    disconnect = MQTT::Protocol::Disconnect.new(
      reason_code: MQTT::Protocol::Disconnect::ReasonCode::UnspecifiedError)
    disconnect.bytesize(MQTT::Protocol::Version::V5).to_i.should eq encode_v5(disconnect).size
  end

  it "reports a bytesize matching the v3 serialization (empty payload)" do
    disconnect = MQTT::Protocol::Disconnect.new(
      reason_code: MQTT::Protocol::Disconnect::ReasonCode::UnspecifiedError)
    disconnect.bytesize(MQTT::Protocol::Version::V3_1_1).to_i.should eq encode_v3(disconnect).size
  end

  it "rejects an invalid reason-code byte" do
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(Bytes[0xE0, 0x01, 0x7E]) }
  end
end

describe MQTT::Protocol::Auth do
  it "has packet type 0x0F" do
    MQTT::Protocol::Auth::TYPE.should eq 15u8
  end

  it "encodes Success with no properties as an empty payload" do
    encode_v5(MQTT::Protocol::Auth.new).should eq Bytes[0xF0, 0x00]
  end

  it "decodes a type-15 packet into Auth" do
    auth = decode_v5(Bytes[0xF0, 0x00]).as(MQTT::Protocol::Auth)
    auth.reason_code.should eq MQTT::Protocol::Auth::ReasonCode::Success
  end

  it "round-trips continue-authentication with method and data" do
    auth = MQTT::Protocol::Auth.new(
      reason_code: MQTT::Protocol::Auth::ReasonCode::ContinueAuthentication,
      properties: MQTT::Protocol::AuthProperties.new(
        authentication_method: "SCRAM-SHA-1",
        authentication_data: Bytes[0xAA, 0xBB],
        user_properties: [{"a", "b"}],
      ),
    )
    decoded = decode_v5(encode_v5(auth)).as(MQTT::Protocol::Auth)
    decoded.reason_code.should eq MQTT::Protocol::Auth::ReasonCode::ContinueAuthentication
    decoded.properties.authentication_method.should eq "SCRAM-SHA-1"
    decoded.properties.authentication_data.should eq Bytes[0xAA, 0xBB]
  end

  it "reports a bytesize matching the v5 serialization" do
    auth = MQTT::Protocol::Auth.new(
      reason_code: MQTT::Protocol::Auth::ReasonCode::ContinueAuthentication,
      properties: MQTT::Protocol::AuthProperties.new(authentication_method: "SCRAM-SHA-1"),
    )
    auth.bytesize(MQTT::Protocol::Version::V5).to_i.should eq encode_v5(auth).size
  end
end
