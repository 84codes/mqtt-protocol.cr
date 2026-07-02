require "./spec_helper"

# 2.7: every decode failure is answerable with a v5 reason code. PacketDecode
# carries 0x81 (Malformed Packet, spec 2.4) by default; ProtocolError remains
# for violations that need a more specific code. A v5 consumer rescues one
# type and reads .reason_code uniformly.
describe MQTT::Protocol::Error::PacketDecode do
  it "carries reason code 0x81 by default" do
    MQTT::Protocol::Error::PacketDecode.new("x").reason_code.should eq 0x81u8
  end

  it "is the ancestor of ProtocolError, which keeps its specific code" do
    ex = MQTT::Protocol::Error::ProtocolError.new(0x94u8, "topic alias invalid")
    ex.should be_a MQTT::Protocol::Error::PacketDecode
    ex.reason_code.should eq 0x94u8
  end

  it "exposes 0x81 for a plain malformed-packet decode failure" do
    # v3 SUBSCRIBE whose options byte carries QoS 3 - raises plain PacketDecode.
    bytes = Bytes[0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 0x61, 0x03]
    mio = IO::Memory.new(bytes.size)
    mio.write bytes
    mio.rewind
    ex = expect_raises(MQTT::Protocol::Error::PacketDecode) do
      MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO::V3.new(mio))
    end
    ex.reason_code.should eq 0x81u8
  end
end
