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

  it "reads CONNECT on a caller-owned bootstrap IO and reframes (instance method)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    io.write_byte 0b0001_0000u8
    io.write_remaining_length 13u8
    io.write_string "MQTT"
    io.write_byte 0x05u8
    io.write_byte 0b0000_0010u8
    io.write_int 60u16
    io.write_byte 0x00u8
    io.write_string ""
    mio.rewind

    # The caller keeps the boot IO; the tuple only rebinds on success, so a
    # rejecting server still has the v3 IO to frame a CONNACK on the error path.
    boot = MQTT::Protocol::IO::V3.new(mio)
    connect, conn_io = boot.read_connect
    connect.version.should eq MQTT::Protocol::Version::V5
    conn_io.should be_a MQTT::Protocol::IO::V5
  end

  it "raises PacketDecode (not TypeCastError) when the first packet is not CONNECT [MQTT-3.1.0-1]" do
    mio = IO::Memory.new(2)
    mio.write Bytes[0xC0, 0x00] # PINGREQ, a well-formed non-CONNECT packet
    mio.rewind
    boot = MQTT::Protocol::IO::V3.new(mio)
    expect_raises(MQTT::Protocol::Error::PacketDecode, /must be CONNECT/) { boot.read_connect }
  end

  it "copy_with changes only the named field and carries the rest over" do
    props = MQTT::Protocol::ConnectProperties.new(session_expiry_interval: 30u32)
    original = MQTT::Protocol::Connect.new(
      client_id: "",
      clean_session: false,
      keepalive: 10u16,
      username: "user",
      password: "pass".to_slice,
      will: nil,
      version: MQTT::Protocol::Version::V5,
      properties: props,
    )
    copy = original.copy_with(client_id: "assigned-id")
    copy.client_id.should eq "assigned-id"
    copy.clean_session?.should be_false
    copy.keepalive.should eq 10u16
    copy.username.should eq "user"
    # version and properties are the fields a manual rebuild silently dropped.
    copy.version.should eq MQTT::Protocol::Version::V5
    copy.properties.should eq props
  end

  it "copy_with can change other fields (e.g. version) and carries the rest over" do
    props = MQTT::Protocol::ConnectProperties.new(session_expiry_interval: 30u32)
    original = MQTT::Protocol::Connect.new(
      client_id: "cid",
      clean_session: true,
      keepalive: 30u16,
      username: nil,
      password: nil,
      will: nil,
      version: MQTT::Protocol::Version::V5,
      properties: props,
    )
    copy = original.copy_with(version: MQTT::Protocol::Version::V3_1_1, keepalive: 60u16)
    copy.version.should eq MQTT::Protocol::Version::V3_1_1
    copy.keepalive.should eq 60u16
    copy.client_id.should eq "cid"
    copy.clean_session?.should be_true
    copy.properties.should eq props
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

  it "reads Will properties before the will topic [MQTT-3.1.3-1]" do
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
    decoded_will = decoded.will.should be_a MQTT::Protocol::Will
    decoded_will.properties.should eq will.properties
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

  it "rejects a CONNECT whose remaining_length over-declares (trailing bytes)" do
    # A valid minimal v5 CONNECT body is 19 bytes; this declares 20 and appends
    # one trailing byte. The fields parse, leaving 1 unconsumed byte that would
    # otherwise desync the next packet (section 2.1.4).
    bytes = Bytes[
      0x10, 0x14,                                     # CONNECT, remaining_length 20 (one more than the 19-byte body)
      0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,             # "MQTT"
      0x05,                                           # protocol version 5
      0x02,                                           # clean start
      0x00, 0x3C,                                     # keepalive 60
      0x00,                                           # empty properties
      0x00, 0x06, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, # client id "client"
      0xAA,                                           # trailing byte covered by the inflated remaining_length
    ]
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) do
      decode(bytes, MQTT::Protocol::Version::V5)
    end
    ex.reason_code.should eq 0x81u8
  end

  # T1: CONNECT is the most complex packet (protocol name + properties +
  # will-properties + username/password arithmetic in remaining_length) and was
  # the one packet without a bytesize==serialized guard. The Medium finding
  # family was "bytesize != bytes written", so pin it here in every shape.
  describe "#bytesize matches the serialized size" do
    will_props = MQTT::Protocol::WillProperties.new(will_delay_interval: 5u32)
    connect_props = MQTT::Protocol::ConnectProperties.new(session_expiry_interval: 10u32)
    will = MQTT::Protocol::Will.new("wt", "bye".to_slice, 1u8, true)
    will_v5 = MQTT::Protocol::Will.new("wt", "bye".to_slice, 1u8, true, will_props)

    {
      "bare"                     => {nil, nil, nil, MQTT::Protocol::ConnectProperties.new},
      "username only"            => {"user", nil, nil, MQTT::Protocol::ConnectProperties.new},
      "username + password"      => {"user", "pass".to_slice, nil, MQTT::Protocol::ConnectProperties.new},
      "will"                     => {nil, nil, will, MQTT::Protocol::ConnectProperties.new},
      "will + username/password" => {"user", "pass".to_slice, will, MQTT::Protocol::ConnectProperties.new},
    }.each do |name, (username, password, w, props)|
      it "for a v3.1.1 CONNECT (#{name})" do
        connect = MQTT::Protocol::Connect.new("cid", false, 30u16, username, password, w,
          MQTT::Protocol::Version::V3_1_1, props)
        connect.bytesize(MQTT::Protocol::Version::V3_1_1).to_i
          .should eq encode(connect, MQTT::Protocol::Version::V3_1_1).size
      end
    end

    {
      "bare"                    => {nil, nil, nil, MQTT::Protocol::ConnectProperties.new},
      "username only"           => {"user", nil, nil, MQTT::Protocol::ConnectProperties.new},
      "username + password"     => {"user", "pass".to_slice, nil, MQTT::Protocol::ConnectProperties.new},
      "will + will properties"  => {nil, nil, will_v5, MQTT::Protocol::ConnectProperties.new},
      "everything + properties" => {"user", "pass".to_slice, will_v5, connect_props},
    }.each do |name, (username, password, w, props)|
      it "for a v5 CONNECT (#{name})" do
        connect = MQTT::Protocol::Connect.new("cid", false, 30u16, username, password, w,
          MQTT::Protocol::Version::V5, props)
        connect.bytesize(MQTT::Protocol::Version::V5).to_i
          .should eq encode(connect, MQTT::Protocol::Version::V5).size
      end
    end
  end

  # Exact-byte vectors (decode + re-encode), hand-derived from the wire format.
  # Round-trips can pass when encode and decode share the same wrong assumption;
  # these pin the actual bytes.
  describe "a minimal v5 CONNECT" do
    # 0x10 | rem_len 19 | "MQTT" | level 5 | flags 0x02 (clean) | keepalive 60
    # | props 0x00 (empty) | client id "client"
    bytes = Bytes[0x10, 0x13, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x05,
      0x02, 0x00, 0x3C, 0x00, 0x00, 0x06, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74]

    it "is parsed" do
      connect = decode(bytes, MQTT::Protocol::Version::V5).as(MQTT::Protocol::Connect)
      connect.version.should eq MQTT::Protocol::Version::V5
      connect.client_id.should eq "client"
      connect.clean_session?.should be_true
      connect.keepalive.should eq 60u16
      connect.username.should be_nil
      connect.password.should be_nil
      connect.will.should be_nil
      connect.properties.empty?.should be_true
    end

    it "can write" do
      connect = MQTT::Protocol::Connect.new("client", true, 60u16, nil, nil, nil,
        MQTT::Protocol::Version::V5)
      encode(connect, MQTT::Protocol::Version::V5).should eq bytes
    end
  end

  describe "a full v5 CONNECT" do
    # flags 0xEC (user+pass+will, will qos 1, will retain, clean) |
    # keepalive 30 | connect props {session_expiry 10} | client "cid" |
    # will props {will_delay 5} | will topic "wt" | will payload "bye" |
    # username "user" | password "pass"
    bytes = Bytes[0x10, 0x30, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x05, 0xEC,
      0x00, 0x1E, 0x05, 0x11, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x03, 0x63, 0x69,
      0x64, 0x05, 0x18, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x77, 0x74, 0x00,
      0x03, 0x62, 0x79, 0x65, 0x00, 0x04, 0x75, 0x73, 0x65, 0x72, 0x00, 0x04,
      0x70, 0x61, 0x73, 0x73]

    it "is parsed" do
      connect = decode(bytes, MQTT::Protocol::Version::V5).as(MQTT::Protocol::Connect)
      connect.client_id.should eq "cid"
      connect.clean_session?.should be_false
      connect.keepalive.should eq 30u16
      connect.username.should eq "user"
      String.new(connect.password.should be_a Bytes).should eq "pass"
      connect.properties.session_expiry_interval.should eq 10u32
      will = connect.will.should be_a MQTT::Protocol::Will
      will.topic.should eq "wt"
      String.new(will.payload).should eq "bye"
      will.qos.should eq 1u8
      will.retain?.should be_true
      will.properties.will_delay_interval.should eq 5u32
    end

    it "can write" do
      will = MQTT::Protocol::Will.new("wt", "bye".to_slice, 1u8, true,
        MQTT::Protocol::WillProperties.new(will_delay_interval: 5u32))
      connect = MQTT::Protocol::Connect.new("cid", false, 30u16, "user", "pass".to_slice,
        will, MQTT::Protocol::Version::V5,
        MQTT::Protocol::ConnectProperties.new(session_expiry_interval: 10u32))
      encode(connect, MQTT::Protocol::Version::V5).should eq bytes
    end
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

  # Exact-byte vector hand-derived from the MQTT 5.0 spec: session_present=false,
  # reason Success, props {receive_maximum: 10, maximum_qos: 1}.
  # Body: 21 00 0A (recv max) 24 01 (max qos) = 5 bytes.
  describe "a v5 CONNACK with properties" do
    bytes = Bytes[0x20, 0x08, 0x00, 0x00, 0x05, 0x21, 0x00, 0x0A, 0x24, 0x01]

    it "is parsed" do
      connack = decode(bytes, MQTT::Protocol::Version::V5).as(MQTT::Protocol::Connack)
      connack.session_present?.should be_false
      connack.reason_code.should eq MQTT::Protocol::Connack::ReasonCode::Success
      connack.properties.receive_maximum.should eq 10u16
      connack.properties.maximum_qos.should eq 1u8
    end

    it "can write" do
      connack = MQTT::Protocol::Connack.new(
        session_present: false,
        reason_code: MQTT::Protocol::Connack::ReasonCode::Success,
        properties: MQTT::Protocol::ConnackProperties.new(receive_maximum: 10u16, maximum_qos: 1u8),
      )
      encode(connack, MQTT::Protocol::Version::V5).should eq bytes
    end
  end
end

# 1.3: MQTT 5.0 allows a Password without a User Name (3.1.2.9); the MUST-NOT
# is v3.1.1-only ([MQTT-3.1.2-22 v3.1.1]). Both directions must honor it: decode
# accepts flag bit 6 without bit 7, and encode actually writes the password.
describe "v5 CONNECT password without username" do
  it "round-trips a v5 CONNECT carrying only a password" do
    connect = MQTT::Protocol::Connect.new(
      client_id: "pw-only",
      clean_session: true,
      keepalive: 30u16,
      username: nil,
      password: "token".to_slice,
      will: nil,
      version: MQTT::Protocol::Version::V5,
    )
    mio = IO::Memory.new
    MQTT::Protocol::IO::V5.new(mio).write_packet(connect)
    mio.rewind
    decoded, _io = MQTT::Protocol::IO.read_connect(mio)
    decoded.username.should be_nil
    decoded.password.should eq "token".to_slice
  end

  it "rejects password-without-username at construction for v3" do
    expect_raises(ArgumentError, /username/) do
      MQTT::Protocol::Connect.new(
        client_id: "pw-only",
        clean_session: true,
        keepalive: 30u16,
        username: nil,
        password: "token".to_slice,
        will: nil,
        version: MQTT::Protocol::Version::V3_1_1,
      )
    end
  end
end
