require "../io"

macro decode_assert(condition, err, *args)
  {% if (err.class_name == "StringLiteral" || err.class_name == "StringInterpolation") %}
    # err is a string
    ({{condition}} || raise Error::PacketDecode.new {{err}})
  {% elsif (err.class_name == "Call") %}
    # err is a call that we assume returns a string e.g. sprintf()
    ({{condition}} || raise Error::PacketDecode.new {{err}})
  {% else %}
    # here we just assume it's a class name
    ({{condition}} || raise {{err}}.new({{args.splat}}))
  {% end %}
end

module MQTT
  module Protocol
    alias Flags = UInt8

    abstract struct Packet
      abstract def to_io(io : MQTT::Protocol::IO)

      @remaining_length : UInt32 = 2

      def remaining_length : UInt32
        @remaining_length
      end

      def bytesize : UInt32
        # remaining_length + bytesize of remaining_length + bytesize of packet type
        if remaining_length < 127
          remaining_length + 1 + 1
        elsif remaining_length < 16_383
          remaining_length + 2 + 1
        elsif remaining_length < 2_097_151
          remaining_length + 3 + 1
        else
          remaining_length + 4 + 1
        end
      end

      def self.from_io(io : ::IO) : Packet
        from_io MQTT::Protocol::IO.new(io)
      end

      # ameba:disable Metrics/CyclomaticComplexity
      def self.from_io(io : MQTT::Protocol::IO) : Packet
        first_byte = io.read_byte || raise(::IO::EOFError.new)
        type = first_byte >> 4
        flags = first_byte & 0b00001111
        remaining_length = io.read_remaining_length
        packet =
          case type
          when Connect::TYPE     then Connect.from_io(io, flags, remaining_length)
          when Connack::TYPE     then Connack.from_io(io, flags, remaining_length)
          when Publish::TYPE     then Publish.from_io(io, flags, remaining_length)
          when PubAck::TYPE      then PubAck.from_io(io, flags, remaining_length)
          when PubRec::TYPE      then PubRec.from_io(io, flags, remaining_length)
          when PubRel::TYPE      then PubRel.from_io(io, flags, remaining_length)
          when PubComp::TYPE     then PubComp.from_io(io, flags, remaining_length)
          when Subscribe::TYPE   then Subscribe.from_io(io, flags, remaining_length)
          when SubAck::TYPE      then SubAck.from_io(io, flags, remaining_length)
          when Unsubscribe::TYPE then Unsubscribe.from_io(io, flags, remaining_length)
          when UnsubAck::TYPE    then UnsubAck.from_io(io, flags, remaining_length)
          when PingReq::TYPE     then PingReq.from_io(io, flags, remaining_length)
          when PingResp::TYPE    then PingResp.from_io(io, flags, remaining_length)
          when Disconnect::TYPE  then Disconnect.from_io(io, flags, remaining_length)
          else
            raise Error::PacketDecode.new "invalid packet type #{type.to_u8}"
          end
        packet
      end
    end

    abstract struct SimplePacket < Packet
      private abstract def type

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length.zero?, "invalid length"
        self.new
      end

      def to_io(io)
        io.write_byte(type << 4)
        io.write_remaining_length remaining_length
      end

      def initialize
        @remaining_length = 0
      end
    end
  end
end
