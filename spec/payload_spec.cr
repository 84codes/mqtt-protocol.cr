require "./spec_helper"

describe MQTT::Protocol::Payload do
  it ".new(Bytes) returns a BytesPayload" do
    obj = MQTT::Protocol::Payload.new("foo".to_slice)
    obj.should be_a(MQTT::Protocol::BytesPayload)
  end

  it ".new(IO) returns a IOPayload" do
    io = IO::Memory.new
    io.write "foo".to_slice
    obj = MQTT::Protocol::Payload.new(io, 3)
    obj.should be_a(MQTT::Protocol::IOPayload)
  end

  describe "#==" do
    it "should return true for two BytePayload with same bytes" do
      one = MQTT::Protocol::BytesPayload.new("foo".to_slice)
      two = MQTT::Protocol::BytesPayload.new("foo".to_slice)

      (one == two).should be_true
    end

    it "should return false for two BytePayload with different bytes" do
      one = MQTT::Protocol::BytesPayload.new("foo".to_slice)
      two = MQTT::Protocol::BytesPayload.new("bar".to_slice)

      (one == two).should be_false
    end

    it "should return true for two IOPayload with same content" do
      io_one = IO::Memory.new("foo".to_slice)
      io_two = IO::Memory.new("foo".to_slice)

      io_one.rewind
      io_two.rewind

      one = MQTT::Protocol::IOPayload.new(io_one, 3)
      two = MQTT::Protocol::IOPayload.new(io_two, 3)

      (one == two).should be_true
    end

    it "should return false for two IOPayload with different content" do
      io_one = IO::Memory.new("foo".to_slice)
      io_two = IO::Memory.new("bar".to_slice)

      io_one.rewind
      io_two.rewind

      one = MQTT::Protocol::IOPayload.new(io_one, 3)
      two = MQTT::Protocol::IOPayload.new(io_two, 3)

      (one == two).should be_false
    end

    it "should return true for one BytesPayload and one IOPayload with same content" do
      io_two = IO::Memory.new("foo".to_slice)
      io_two.rewind

      one = MQTT::Protocol::BytesPayload.new("foo".to_slice)
      two = MQTT::Protocol::IOPayload.new(io_two, 3)

      (one == two).should be_true
    end

    it "should return false for one BytesPayload and one IOPayload with different content" do
      io_two = IO::Memory.new("bar".to_slice)
      io_two.rewind

      one = MQTT::Protocol::BytesPayload.new("foo".to_slice)
      two = MQTT::Protocol::IOPayload.new(io_two, 3)

      (one == two).should be_false
    end
  end
end
