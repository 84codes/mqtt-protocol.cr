require "./spec_helper"

# Property structs (MQTT5_FINDINGS.md 3.4). Each packet context gets its own
# typed struct; a property illegal in that context is structurally absent.
#
# Convention used in these specs:
#   * exact-byte assertions for the empty case and single-property cases
#     (property order on the wire is the encoder's choice, so multi-property
#     encodes are only round-tripped, not byte-pinned)
#   * round-trips for combinations and for every struct's full field set
#
# Wire layout of a properties section: VBI(total_body_len) ++ body, where the
# body is a sequence of (identifier_byte ++ encoded_value).

private def roundtrip(props)
  mio = IO::Memory.new
  io = MQTT::Protocol::IO::V3.new(mio)
  props.to_io(io)
  mio.rewind
  props.class.from_io(io, props.bytesize.to_u32)
end

describe MQTT::Protocol::ConnectProperties do
  it "encodes an empty section as a single zero VBI length" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::ConnectProperties.new.to_io(io)
    mio.to_slice.should eq Bytes[0x00]
  end

  it "reports empty?" do
    MQTT::Protocol::ConnectProperties.new.empty?.should be_true
    MQTT::Protocol::ConnectProperties.new(receive_maximum: 10u16).empty?.should be_false
  end

  it "encodes Session Expiry Interval (0x11, four byte int)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::ConnectProperties.new(session_expiry_interval: 10u32).to_io(io)
    mio.to_slice.should eq Bytes[0x05, 0x11, 0x00, 0x00, 0x00, 0x0A]
  end

  it "encodes Receive Maximum (0x21, two byte int)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::ConnectProperties.new(receive_maximum: 20u16).to_io(io)
    mio.to_slice.should eq Bytes[0x03, 0x21, 0x00, 0x14]
  end

  it "encodes a single User Property (0x26, string pair)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::ConnectProperties.new(user_properties: [{"foo", "bar"}]).to_io(io)
    mio.to_slice.should eq Bytes[
      0x0B, 0x26,
      0x00, 0x03, 'f'.ord, 'o'.ord, 'o'.ord,
      0x00, 0x03, 'b'.ord, 'a'.ord, 'r'.ord,
    ]
  end

  it "round-trips the full field set" do
    props = MQTT::Protocol::ConnectProperties.new(
      session_expiry_interval: 3600u32,
      receive_maximum: 100u16,
      maximum_packet_size: 65_535u32,
      topic_alias_maximum: 10u16,
      request_response_information: true,
      request_problem_information: false,
      authentication_method: "SCRAM-SHA-1",
      authentication_data: Bytes[1, 2, 3, 4],
      user_properties: [{"a", "1"}, {"b", "2"}],
    )
    roundtrip(props).should eq props
  end

  it "preserves User Property order and duplicate keys" do
    props = MQTT::Protocol::ConnectProperties.new(user_properties: [{"k", "1"}, {"k", "2"}, {"j", "3"}])
    roundtrip(props).user_properties.should eq [{"k", "1"}, {"k", "2"}, {"j", "3"}]
  end

  it "rejects an unknown property identifier" do
    mio = IO::Memory.new
    mio.write Bytes[0x02, 0x99, 0x00] # len=2, id 0x99 is not a CONNECT property
    mio.rewind
    io = MQTT::Protocol::IO::V3.new(mio)
    expect_raises(MQTT::Protocol::Error::ProtocolError) do
      MQTT::Protocol::ConnectProperties.from_io(io, mio.size.to_u32)
    end
  end

  it "rejects a duplicated non-repeatable property" do
    # Session Expiry Interval twice
    mio = IO::Memory.new
    mio.write Bytes[0x0A,
      0x11, 0x00, 0x00, 0x00, 0x01,
      0x11, 0x00, 0x00, 0x00, 0x02]
    mio.rewind
    io = MQTT::Protocol::IO::V3.new(mio)
    expect_raises(MQTT::Protocol::Error::ProtocolError) do
      MQTT::Protocol::ConnectProperties.from_io(io, mio.size.to_u32)
    end
  end
end

describe MQTT::Protocol::WillProperties do
  it "encodes Will Delay Interval (0x18, four byte int)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::WillProperties.new(will_delay_interval: 30u32).to_io(io)
    mio.to_slice.should eq Bytes[0x05, 0x18, 0x00, 0x00, 0x00, 0x1E]
  end

  it "round-trips the full field set" do
    props = MQTT::Protocol::WillProperties.new(
      will_delay_interval: 30u32,
      payload_format_indicator: true,
      message_expiry_interval: 60u32,
      content_type: "text/plain",
      response_topic: "responses/1",
      correlation_data: Bytes[9, 8, 7],
      user_properties: [{"x", "y"}],
    )
    roundtrip(props).should eq props
  end
end

describe MQTT::Protocol::ConnackProperties do
  it "encodes Maximum QoS (0x24, byte)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::ConnackProperties.new(maximum_qos: 1u8).to_io(io)
    mio.to_slice.should eq Bytes[0x02, 0x24, 0x01]
  end

  it "round-trips the full field set" do
    props = MQTT::Protocol::ConnackProperties.new(
      session_expiry_interval: 120u32,
      receive_maximum: 50u16,
      maximum_qos: 2u8,
      retain_available: true,
      maximum_packet_size: 1_048_576u32,
      assigned_client_identifier: "auto-123",
      topic_alias_maximum: 5u16,
      reason_string: "ok",
      user_properties: [{"a", "b"}],
      wildcard_subscription_available: true,
      subscription_identifier_available: true,
      shared_subscription_available: false,
      server_keep_alive: 30u16,
      response_information: "resp/",
      server_reference: "other.example.com",
      authentication_method: "SCRAM-SHA-1",
      authentication_data: Bytes[1, 2],
    )
    roundtrip(props).should eq props
  end
end

describe MQTT::Protocol::PublishProperties do
  it "encodes Topic Alias (0x23, two byte int)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::PublishProperties.new(topic_alias: 5u16).to_io(io)
    mio.to_slice.should eq Bytes[0x03, 0x23, 0x00, 0x05]
  end

  it "encodes a single Subscription Identifier (0x0B, variable byte int)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::PublishProperties.new(subscription_identifiers: [1u32]).to_io(io)
    mio.to_slice.should eq Bytes[0x02, 0x0B, 0x01]
  end

  it "encodes repeated Subscription Identifiers in order" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::PublishProperties.new(subscription_identifiers: [1u32, 2u32]).to_io(io)
    mio.to_slice.should eq Bytes[0x04, 0x0B, 0x01, 0x0B, 0x02]
  end

  it "round-trips the full field set" do
    props = MQTT::Protocol::PublishProperties.new(
      payload_format_indicator: true,
      message_expiry_interval: 120u32,
      topic_alias: 7u16,
      response_topic: "responses/1",
      correlation_data: Bytes[1, 2, 3],
      user_properties: [{"a", "b"}],
      subscription_identifiers: [10u32, 20u32],
      content_type: "application/json",
    )
    roundtrip(props).should eq props
  end
end

describe MQTT::Protocol::SubscribeProperties do
  it "encodes a single Subscription Identifier (0x0B, variable byte int)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::SubscribeProperties.new(subscription_identifier: 128u32).to_io(io)
    # VBI(128) = 0x80 0x01, so body = 0x0B 0x80 0x01 (3 bytes)
    mio.to_slice.should eq Bytes[0x03, 0x0B, 0x80, 0x01]
  end

  it "round-trips with user properties" do
    props = MQTT::Protocol::SubscribeProperties.new(
      subscription_identifier: 42u32,
      user_properties: [{"a", "b"}],
    )
    roundtrip(props).should eq props
  end
end

describe MQTT::Protocol::DisconnectProperties do
  it "encodes Reason String (0x1F, utf8 string)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::DisconnectProperties.new(reason_string: "bye").to_io(io)
    mio.to_slice.should eq Bytes[0x06, 0x1F, 0x00, 0x03, 'b'.ord, 'y'.ord, 'e'.ord]
  end

  it "round-trips the full field set" do
    props = MQTT::Protocol::DisconnectProperties.new(
      session_expiry_interval: 0u32,
      reason_string: "shutting down",
      user_properties: [{"a", "b"}],
      server_reference: "other.example.com",
    )
    roundtrip(props).should eq props
  end
end

describe MQTT::Protocol::AuthProperties do
  it "encodes Authentication Method (0x15, utf8 string)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::AuthProperties.new(authentication_method: "SCRAM-SHA-1").to_io(io)
    mio.to_slice.should eq Bytes[
      0x0E, 0x15, 0x00, 0x0B,
      'S'.ord, 'C'.ord, 'R'.ord, 'A'.ord, 'M'.ord, '-'.ord,
      'S'.ord, 'H'.ord, 'A'.ord, '-'.ord, '1'.ord,
    ]
  end

  it "round-trips the full field set" do
    props = MQTT::Protocol::AuthProperties.new(
      authentication_method: "SCRAM-SHA-1",
      authentication_data: Bytes[0xAA, 0xBB],
      reason_string: "continue",
      user_properties: [{"a", "b"}],
    )
    roundtrip(props).should eq props
  end
end
