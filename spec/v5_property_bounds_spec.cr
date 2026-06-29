require "./spec_helper"

# Regression specs for property-section bounding (INDEPENDENT_REVIEW.md #1-#3).
#
# A v5 properties section carries its own Variable Byte Integer length. Before
# these fixes that length was trusted blindly: it was never checked against the
# bytes left in the enclosing packet, and the tail-based packets
# (ack/disconnect/auth/connack) never verified that the section consumed the
# whole packet. Both let a malformed peer drive the parser past the packet
# boundary or leave trailing bytes that desync the stream.
private def decode_v5(bytes : Bytes)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  io = MQTT::Protocol::IO::V5.new(mio)
  MQTT::Protocol::Packet.from_io(io)
end

describe "v5 property-section bounding" do
  # #1: the section length must not exceed the packet's remaining bytes.
  it "rejects a property section longer than the packet's remaining length" do
    # DISCONNECT, remaining_length 3: reason (0x00) + 2 bytes. The section then
    # declares a 10-byte body, which cannot fit in the 2 bytes that remain.
    bytes = Bytes[0xE0, 0x03, 0x00, 0x0A, 0x00]
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { decode_v5(bytes) }
    ex.reason_code.should eq 0x81u8
  end

  # #2: a tail-based packet must consume its declared remaining length exactly,
  # so trailing bytes after the section are caught rather than silently left in
  # the stream to be misread as the next packet.
  it "rejects trailing bytes after a DISCONNECT property section" do
    # remaining_length 4: reason (0x00) + empty section (0x00) + 2 junk bytes.
    bytes = Bytes[0xE0, 0x04, 0x00, 0x00, 0x00, 0x00]
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { decode_v5(bytes) }
    ex.reason_code.should eq 0x81u8
  end

  it "rejects trailing bytes after a PUBACK property section" do
    # remaining_length 5: packet id (0x0001) + reason (0x00) + empty section
    # (0x00) + 1 junk byte.
    bytes = Bytes[0x40, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00]
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { decode_v5(bytes) }
    ex.reason_code.should eq 0x81u8
  end

  # #3: an ack must have room for its 2-byte packet id before we read it.
  it "rejects an ack whose remaining length is too short for a packet id" do
    bytes = Bytes[0x40, 0x01, 0x00] # PUBACK, remaining_length 1
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end
end
