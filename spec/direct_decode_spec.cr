require "./spec_helper"

# Direct codec decode entry points (FABLE_FINDINGS.md 5.3/5.4). The byte
# budget is normally started by Packet.read_body, but the per-packet
# `from_io(io, flags, remaining_length)` methods and `Properties.from_io`
# are public and take an explicit bound - calling them directly must honor
# that bound instead of silently misparsing with an inactive budget (empty
# payloads, zero reason codes, spurious empty-payload errors).
private def direct_io(bytes : Bytes, version = MQTT::Protocol::Version::V5)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  MQTT::Protocol::IO.for(version, mio)
end

describe "direct codec from_io calls" do
  it "decodes the full payload of a directly-decoded v3 PUBLISH" do
    # Body only (no fixed header): topic "a" + payload "hi".
    io = direct_io(Bytes[0x00, 0x01, 0x61, 0x68, 0x69], MQTT::Protocol::Version::V3_1_1)
    publish = MQTT::Protocol::Publish.from_io(io, 0u8, 5u32)
    publish.topic.should eq "a"
    publish.payload.should eq "hi".to_slice
  end

  it "decodes the reason codes of a directly-decoded v3 SUBACK" do
    # Body: packet id (00 01) + return code 0x01.
    io = direct_io(Bytes[0x00, 0x01, 0x01], MQTT::Protocol::Version::V3_1_1)
    suback = MQTT::Protocol::SubAck.from_io(io, 0u8, 3u32)
    suback.reason_codes.should eq [MQTT::Protocol::SubAck::ReasonCode::GrantedQos1]
  end

  it "decodes a valid directly-decoded v5 SUBSCRIBE instead of raising empty-payload" do
    # Body: packet id (00 01) + empty props (00) + topic "a" + options QoS1.
    io = direct_io(Bytes[0x00, 0x01, 0x00, 0x00, 0x01, 0x61, 0x01])
    subscribe = MQTT::Protocol::Subscribe.from_io(io, 2u8, 7u32)
    subscribe.topic_filters.size.should eq 1
    subscribe.topic_filters.first.topic.should eq "a"
  end

  it "accepts a valid empty properties section on a directly-decoded v5 PUBLISH" do
    # Body: topic "a" + empty props (00) + payload "x".
    io = direct_io(Bytes[0x00, 0x01, 0x61, 0x00, 0x78])
    publish = MQTT::Protocol::Publish.from_io(io, 0u8, 5u32)
    publish.payload.should eq "x".to_slice
  end

  # 5.4: a directly-decoded properties section must bound its fields by the
  # explicit `remaining` argument - a declared 0xFFFF string must fail as
  # malformed, not over-read (blocking a socket / EOF on a memory IO).
  it "bounds property fields when Properties.from_io is called directly" do
    io = direct_io(Bytes[0x03, 0x15, 0xFF, 0xFF])
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) do
      MQTT::Protocol::ConnectProperties.from_io(io, 4u32)
    end
    ex.reason_code.should eq 0x81u8
  end
end
