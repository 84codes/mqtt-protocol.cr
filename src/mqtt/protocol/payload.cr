require "./io"

module MQTT
  module Protocol
    abstract struct Payload
      def self.new(bytes : Bytes)
        BytesPayload.new(bytes)
      end

      def self.new(io : ::IO, bytesize : Int32)
        IOPayload.new(MQTT::Protocol::IO.new(io), bytesize)
      end

      def self.new(io : MQTT::Protocol::IO, bytesize : Int32)
        IOPayload.new(io, bytesize)
      end

      def size
        bytesize
      end

      abstract def bytesize : Int32
      abstract def to_slice : Bytes
      abstract def to_io(io, format : ::IO::ByteFormat = ::IO::ByteFormat::SystemEndian)

      def ==(other)
        return false unless other.is_a?(Payload)
        to_slice == other.to_slice
      end
    end

    struct BytesPayload < Payload
      def initialize(@bytes : Bytes)
      end

      def bytesize : Int32
        @bytes.bytesize
      end

      def to_slice : Bytes
        @bytes
      end

      def to_io(io, format : ::IO::ByteFormat = ::IO::ByteFormat::SystemEndian)
        io.write @bytes
      end
    end

    struct IOPayload < Payload
      getter bytesize : Int32

      @data : Bytes? = nil

      def initialize(@io : MQTT::Protocol::IO, @bytesize : Int32)
      end

      def initialize(io : ::IO, @bytesize : Int32)
        @io = MQTT::Protocol::IO.new(io)
      end

      def to_slice : Bytes
        if peeked = @io.peek.try &.[0, bytesize]?
          return peeked
        end
        @data ||= begin
          data = Bytes.new(bytesize)
          @io.read(data)
          data
        end
      end

      def to_io(io, format : ::IO::ByteFormat = ::IO::ByteFormat::SystemEndian)
        # Use data that has already been copied to memory
        if data = @data
          io.write data
        else
          if io_mem = @io.io.as?(::IO::Memory)
            io.write io_mem.to_slice
          elsif @io.io.is_a?(::IO::FileDescriptor)
            pos = @io.pos
            copied = ::IO.copy(@io, io, bytesize)
            raise "Failed to copy payload" if copied != bytesize
            @io.pos = pos
          else
            io.write to_slice
          end
        end
      end
    end
  end
end
