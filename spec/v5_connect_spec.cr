require "./spec_helper"

# CONNECT / CONNACK at protocol level 0x05 (MQTT5_FINDINGS.md section 4).
#
# CONNECT decode is what reveals the version: reading level 0x05 means the rest
# of the connection is framed by an IO::V5 (see IO.read_connect), so every later
# from_io/to_io reads/writes a properties section and reason-code byte.

module V5ConnectHelper
  V5 = MQTT::Protocol::Version::V5

  # Encode on a v5 IO, decode the same bytes on a fresh v5 IO.
  def self.roundtrip(packet)
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V5.new(mio)
    packet.to_io(io)
    mio.rewind
    rio = MQTT::Protocol::IO::V5.new(mio)
    {MQTT::Protocol::Packet.from_io(rio), rio}
  end
end

private def encode(packet, version) : Bytes
  mio = IO::Memory.new
  io = MQTT::Protocol::IO.for(version, mio)
  packet.to_io(io)
  mio.to_slice
end

private def decode(bytes : Bytes, version) : MQTT::Protocol::Packet
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  io = MQTT::Protocol::IO.for(version, mio)
  MQTT::Protocol::Packet.from_io(io)
end

describe MQTT::Protocol::Connect do
  it "detects protocol level 0x05 and bootstraps a V5 IO for the connection" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    io.write_byte 0b0001_0000u8 # CONNECT
    io.write_remaining_length 13u8
    io.write_string "MQTT"      # 0x00 0x04 M Q T T
    io.write_byte 0x05u8        # level 5
    io.write_byte 0b0000_0010u8 # clean start
    io.write_int 60u16          # keepalive
    io.write_byte 0x00u8        # empty CONNECT properties (VBI len 0)
    io.write_string ""          # empty client id
    mio.rewind

    # read_connect detects the version from the wire and hands back the IO to
    # use for every subsequent packet.
    connect, conn_io = MQTT::Protocol::IO.read_connect(mio)
    connect.version.should eq MQTT::Protocol::Version::V5
    conn_io.should be_a MQTT::Protocol::IO::V5
    conn_io.version.should eq MQTT::Protocol::Version::V5
    connect.properties.empty?.should be_true
  end

  it "accepts a client id longer than 255 bytes in v5" do
    long_id = "a" * 300
    connect = MQTT::Protocol::Connect.new(
      client_id: long_id,
      clean_session: true,
      keepalive: 60u16,
      username: nil,
      password: nil,
      will: nil,
      version: MQTT::Protocol::Version::V5,
    )
    decoded = decode(encode(connect, V5ConnectHelper::V5), V5ConnectHelper::V5)
    decoded.as(MQTT::Protocol::Connect).client_id.should eq long_id
  end

  it "rejects a client id longer than 23 bytes in v3.1 (MQIsdp)" do
    v3_1 = MQTT::Protocol::Version::V3_1
    connect = MQTT::Protocol::Connect.new(
      client_id: "a" * 24,
      clean_session: true,
      keepalive: 60u16,
      username: nil,
      password: nil,
      will: nil,
      version: v3_1,
    )
    bytes = encode(connect, v3_1)
    expect_raises(MQTT::Protocol::Error::IdentifierRejected) { decode(bytes, v3_1) }
  end

  it "parses CONNECT properties" do
    props = MQTT::Protocol::ConnectProperties.new(
      session_expiry_interval: 3600u32,
      receive_maximum: 100u16,
      user_properties: [{"a", "b"}],
    )
    connect = MQTT::Protocol::Connect.new(
      client_id: "client",
      clean_session: true,
      keepalive: 60u16,
      username: nil,
      password: nil,
      will: nil,
      version: MQTT::Protocol::Version::V5,
      properties: props,
    )
    decoded, _ = V5ConnectHelper.roundtrip(connect)
    decoded = decoded.should be_a MQTT::Protocol::Connect
    decoded.properties.should eq props
  end

  it "reads Will properties before the will topic [MQTT-3.1.3.2]" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    io.write_byte 0b0001_0000u8 # CONNECT
    io.write_remaining_length 32u8
    io.write_string "MQTT"
    io.write_byte 0x05u8          # level 5
    io.write_byte 0b0000_0110u8   # clean start + will flag, will qos 0
    io.write_int 10u16            # keepalive
    io.write_byte 0x00u8          # empty CONNECT properties
    io.write_string "client"      # client id
    io.write_byte 0x00u8          # empty WILL properties (must precede will topic)
    io.write_string "topic"       # will topic
    io.write_bytes "bye".to_slice # will payload
    mio.rewind

    rio = MQTT::Protocol::IO::V3.new(mio)
    connect = MQTT::Protocol::Packet.from_io(rio).as(MQTT::Protocol::Connect)
    will = connect.will.should_not be_nil
    will.topic.should eq "topic"
    String.new(will.payload).should eq "bye"
    will.properties.empty?.should be_true
  end

  it "round-trips a v5 will with will properties" do
    will = MQTT::Protocol::Will.new(
      topic: "topic",
      payload: "bye".to_slice,
      qos: 1u8,
      retain: false,
      properties: MQTT::Protocol::WillProperties.new(
        will_delay_interval: 30u32,
        content_type: "text/plain",
      ),
    )
    connect = MQTT::Protocol::Connect.new(
      client_id: "client",
      clean_session: true,
      keepalive: 10u16,
      username: "user",
      password: "pass".to_slice,
      will: will,
      version: MQTT::Protocol::Version::V5,
    )
    decoded, _ = V5ConnectHelper.roundtrip(connect)
    decoded = decoded.should be_a MQTT::Protocol::Connect
    decoded.will.not_nil!.properties.should eq will.properties
  end

  it "decodes a v3.1.1 CONNECT with no properties section" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    io.write_byte 0b0001_0000u8
    io.write_remaining_length 12u8
    io.write_string "MQTT"
    io.write_byte 0x04u8 # level 4 (no properties on the wire)
    io.write_byte 0b0000_0010u8
    io.write_int 60u16
    io.write_string ""
    mio.rewind

    rio = MQTT::Protocol::IO::V3.new(mio)
    connect = MQTT::Protocol::Packet.from_io(rio).as(MQTT::Protocol::Connect)
    connect.version.should eq MQTT::Protocol::Version::V3_1_1
    rio.version.should eq MQTT::Protocol::Version::V3_1_1
    connect.properties.empty?.should be_true
  end
end

describe MQTT::Protocol::Connack do
  describe "ReasonCode" do
    it "down-maps to a v3 ReturnCode where one exists" do
      MQTT::Protocol::Connack::ReasonCode::Success
        .to_v3_return_code.should eq MQTT::Protocol::Connack::ReturnCode::Accepted
      MQTT::Protocol::Connack::ReasonCode::UnsupportedProtocolVersion
        .to_v3_return_code.should eq MQTT::Protocol::Connack::ReturnCode::UnacceptableProtocolVersion
      MQTT::Protocol::Connack::ReasonCode::ClientIdentifierNotValid
        .to_v3_return_code.should eq MQTT::Protocol::Connack::ReturnCode::IdentifierRejected
      MQTT::Protocol::Connack::ReasonCode::BadUserNameOrPassword
        .to_v3_return_code.should eq MQTT::Protocol::Connack::ReturnCode::BadCredentials
      MQTT::Protocol::Connack::ReasonCode::NotAuthorized
        .to_v3_return_code.should eq MQTT::Protocol::Connack::ReturnCode::NotAuthorized
    end

    it "returns nil for a v5-only reason code (consumer must just close)" do
      MQTT::Protocol::Connack::ReasonCode::QuotaExceeded.to_v3_return_code.should be_nil
    end
  end

  it "encodes a v5 CONNACK with reason code and properties section" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V5.new(mio)
    connack = MQTT::Protocol::Connack.new(
      session_present: false,
      reason_code: MQTT::Protocol::Connack::ReasonCode::Success,
    )
    connack.to_io(io)
    # 0x20, rem_len 3, flags 0x00, reason 0x00, properties 0x00
    mio.to_slice.should eq Bytes[0x20, 0x03, 0x00, 0x00, 0x00]
  end

  it "encodes a v3 CONNACK as a return code byte with no properties" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    connack = MQTT::Protocol::Connack.new(
      session_present: false,
      reason_code: MQTT::Protocol::Connack::ReasonCode::Success,
    )
    connack.to_io(io)
    # 0x20, rem_len 2, flags 0x00, return code 0x00
    mio.to_slice.should eq Bytes[0x20, 0x02, 0x00, 0x00]
  end

  it "round-trips a v5 CONNACK with properties" do
    props = MQTT::Protocol::ConnackProperties.new(
      session_expiry_interval: 120u32,
      maximum_qos: 1u8,
      assigned_client_identifier: "auto-1",
      user_properties: [{"a", "b"}],
    )
    connack = MQTT::Protocol::Connack.new(
      session_present: true,
      reason_code: MQTT::Protocol::Connack::ReasonCode::Success,
      properties: props,
    )
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V5.new(mio)
    connack.to_io(io)
    mio.rewind
    rio = MQTT::Protocol::IO::V5.new(mio)
    decoded = MQTT::Protocol::Packet.from_io(rio).as(MQTT::Protocol::Connack)
    decoded.session_present?.should be_true
    decoded.reason_code.should eq MQTT::Protocol::Connack::ReasonCode::Success
    decoded.properties.should eq props
  end

  it "decodes a v3 CONNACK return code into the reason-code model" do
    mio = IO::Memory.new
    mio.write Bytes[0x20, 0x02, 0x00, 0x05] # NotAuthorized in v3 == 5
    mio.rewind
    rio = MQTT::Protocol::IO::V3.new(mio)
    decoded = MQTT::Protocol::Packet.from_io(rio).as(MQTT::Protocol::Connack)
    decoded.reason_code.should eq MQTT::Protocol::Connack::ReasonCode::NotAuthorized
  end

  it "reports a bytesize matching the v5 serialization" do
    connack = MQTT::Protocol::Connack.new(
      session_present: false,
      reason_code: MQTT::Protocol::Connack::ReasonCode::Success,
      properties: MQTT::Protocol::ConnackProperties.new(receive_maximum: 10u16),
    )
    connack.bytesize(MQTT::Protocol::Version::V5).to_i.should eq encode(connack, MQTT::Protocol::Version::V5).size
  end

  it "reports a bytesize matching the v3 serialization (properties dropped)" do
    connack = MQTT::Protocol::Connack.new(false, MQTT::Protocol::Connack::ReturnCode::Accepted)
    connack.bytesize(MQTT::Protocol::Version::V3_1_1).to_i.should eq encode(connack, MQTT::Protocol::Version::V3_1_1).size
  end

  it "rejects an invalid v5 reason-code byte" do
    expect_raises(MQTT::Protocol::Error::PacketDecode) do
      decode(Bytes[0x20, 0x03, 0x00, 0x7E, 0x00], MQTT::Protocol::Version::V5)
    end
  end

  it "rejects a v5 CONNACK truncated before its properties section" do
    expect_raises(MQTT::Protocol::Error::PacketDecode) do
      decode(Bytes[0x20, 0x05, 0x00, 0x00], MQTT::Protocol::Version::V5)
    end
  end

  # Golden vector hand-derived from the MQTT 5.0 spec: session_present=false,
  # reason Success, props {receive_maximum: 10, maximum_qos: 1}.
  # Body: 21 00 0A (recv max) 24 01 (max qos) = 5 bytes.
  it "decodes a golden v5 CONNACK and exposes every field" do
    golden = Bytes[0x20, 0x08, 0x00, 0x00, 0x05, 0x21, 0x00, 0x0A, 0x24, 0x01]
    connack = decode(golden, MQTT::Protocol::Version::V5).as(MQTT::Protocol::Connack)
    connack.session_present?.should be_false
    connack.reason_code.should eq MQTT::Protocol::Connack::ReasonCode::Success
    connack.properties.receive_maximum.should eq 10u16
    connack.properties.maximum_qos.should eq 1u8
  end

  it "encodes the golden v5 CONNACK to the exact bytes" do
    golden = Bytes[0x20, 0x08, 0x00, 0x00, 0x05, 0x21, 0x00, 0x0A, 0x24, 0x01]
    connack = MQTT::Protocol::Connack.new(
      session_present: false,
      reason_code: MQTT::Protocol::Connack::ReasonCode::Success,
      properties: MQTT::Protocol::ConnackProperties.new(receive_maximum: 10u16, maximum_qos: 1u8),
    )
    encode(connack, MQTT::Protocol::Version::V5).should eq golden
  end
end
