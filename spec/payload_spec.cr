require "./spec_helper"

class NonPositionIO < ::IO
  def initialize(@data : Bytes)
  end

  def read(slice : Bytes)
    slice.size.times { |i| slice[i] = @data[i] }
    slice.size
  end

  def write(slice : Bytes) : Nil
    raise NotImplementedError.new("write")
  end
end

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

  describe "IOPayload" do
    describe "#to_slice" do
      it "should peek if possible" do
        io = IO::Memory.new("foo".to_slice)
        io.rewind

        obj = MQTT::Protocol::IOPayload.new(io, 3)
        data = obj.to_slice

        obj.@data.should be_nil
      end

      it "should copy data if peek isn't possible" do
        io = NonPositionIO.new("foo".to_slice)

        obj = MQTT::Protocol::IOPayload.new(io, 3)
        data = obj.to_slice

        obj.@data.should eq "foo".to_slice
      end
    end

    describe "#to_io" do
      it "should not affect position if io support pos/pos=" do
        io = IO::Memory.new("foo".to_slice)
        io.rewind

        obj = MQTT::Protocol::IOPayload.new(io, 3)

        dst = IO::Memory.new
        obj.to_io(dst)

        obj.@data.should be_nil
        obj.@io.pos.should eq 0
      end

      it "should copy data if io doesn't support pos/pos=" do
        io = NonPositionIO.new("foo".to_slice)

        obj = MQTT::Protocol::IOPayload.new(io, 3)

        dst = IO::Memory.new
        obj.to_io(dst)

        obj.@data.should eq "foo".to_slice
      end
    end
  end
end
