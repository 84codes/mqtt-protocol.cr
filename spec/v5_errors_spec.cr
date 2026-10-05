require "./spec_helper"

# Error::ProtocolError (MQTT5_FINDINGS.md 3.6): decode violations that a v5
# consumer must answer with a specific reason code carry that code on the
# exception. It subclasses PacketDecode so existing v3 consumers (which just
# close on PacketDecode) keep working unchanged; v5 consumers read
# ex.reason_code and send the matching DISCONNECT/CONNACK.

describe MQTT::Protocol::Error::ProtocolError do
  it "is a PacketDecode so existing rescues still catch it" do
    (MQTT::Protocol::Error::ProtocolError < MQTT::Protocol::Error::PacketDecode).should be_true
  end

  it "carries the reason code byte the consumer must respond with" do
    ex = MQTT::Protocol::Error::ProtocolError.new(0x82u8, "protocol error")
    ex.reason_code.should eq 0x82u8
  end

  it "maps PacketTooLarge to reason code 0x95" do
    ex = MQTT::Protocol::Error::PacketTooLarge.new(100u32, 200)
    ex.reason_code.should eq 0x95u8
  end

  it "rejects an unknown property id as Malformed Packet (0x81)" do
    mio = IO::Memory.new
    mio.write Bytes[0x02, 0x99, 0x00] # len 2, unknown property id 0x99
    mio.rewind
    io = MQTT::Protocol::IO.v3(mio)
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) do
      MQTT::Protocol::ConnectProperties.from_io(io, mio.size.to_u32)
    end
    ex.reason_code.should eq 0x81u8
  end

  it "rejects a duplicated non-repeatable property as Protocol Error (0x82)" do
    mio = IO::Memory.new
    mio.write Bytes[0x0A,
      0x11, 0x00, 0x00, 0x00, 0x01,
      0x11, 0x00, 0x00, 0x00, 0x02]
    mio.rewind
    io = MQTT::Protocol::IO.v3(mio)
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) do
      MQTT::Protocol::ConnectProperties.from_io(io, mio.size.to_u32)
    end
    ex.reason_code.should eq 0x82u8
  end
end

describe MQTT::Protocol::Error::Connect do
  it "carries the CONNACK reason code to answer with" do
    MQTT::Protocol::Error::UnacceptableProtocolVersion.new.reason_code
      .should eq MQTT::Protocol::Connack::ReasonCode::UnsupportedProtocolVersion
    MQTT::Protocol::Error::IdentifierRejected.new.reason_code
      .should eq MQTT::Protocol::Connack::ReasonCode::ClientIdentifierNotValid
    MQTT::Protocol::Error::ServerUnavailable.new.reason_code
      .should eq MQTT::Protocol::Connack::ReasonCode::ServerUnavailable
    MQTT::Protocol::Error::BadCredentials.new.reason_code
      .should eq MQTT::Protocol::Connack::ReasonCode::BadUserNameOrPassword
    MQTT::Protocol::Error::NotAuthorized.new.reason_code
      .should eq MQTT::Protocol::Connack::ReasonCode::NotAuthorized
  end

  it "rejects with any CONNACK reason code" do
    ex = MQTT::Protocol::Error::Connect.new(MQTT::Protocol::Connack::ReasonCode::Banned, "banned")
    ex.reason_code.should eq MQTT::Protocol::Connack::ReasonCode::Banned
    ex.message.should eq "banned"
  end

  it "carries Unsupported Protocol Version for an unknown protocol level" do
    # CONNECT "MQTT" level 6
    bytes = Bytes[0x10, 0x0A, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x06, 0x02, 0x00, 0x3C]
    mio = IO::Memory.new(bytes.size)
    mio.write bytes
    mio.rewind
    ex = expect_raises(MQTT::Protocol::Error::UnacceptableProtocolVersion) do
      MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO.v3(mio))
    end
    ex.reason_code.should eq MQTT::Protocol::Connack::ReasonCode::UnsupportedProtocolVersion
  end
end
