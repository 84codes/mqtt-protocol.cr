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

      # Wire size of the packet's remaining bytes when framed for `version`.
      # Computed arithmetically (no serialise-then-measure) and version-aware so
      # the reported size always matches what `to_io` writes.
      abstract def remaining_length(version : Version) : UInt32

      # Shared body for the QoS-ack packets (PUBACK/PUBREC/PUBREL/PUBCOMP).
      # Defined here on the base so subclasses inherit it as a macro. The
      # enclosing struct supplies its own `TYPE` and `ReasonCode` enum (which
      # must have a `Success` member); `wire_flags` is the fixed-header lower
      # nibble (0 for all but PUBREL, which is 0b0010).
      #
      # All version-dependent framing (the v5 omission rules 3.4.2.1, the v3
      # remaining-length-2 gate) lives on the IO via read_ack_tail/write_ack.
      macro ack_packet_body(wire_flags)
        getter packet_id, reason_code, properties

        def initialize(@packet_id : UInt16, @reason_code : ReasonCode = ReasonCode::Success,
                       @properties : PubAckProperties = PubAckProperties.new)
        end

        def remaining_length(version : MQTT::Protocol::Version) : UInt32
          return 2u32 unless version.v5?
          2u32 + MQTT::Protocol::IO.tail_bytesize(@reason_code.value, @properties)
        end

        def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
          decode_assert flags == {{wire_flags}}, MQTT::Protocol::Error::InvalidFlags, flags
          # The packet id is always present (2 bytes); reject a short header
          # before reading it so a truncated ack can't over-read the next packet.
          decode_assert remaining_length >= 2, "invalid length #{remaining_length} for ack"
          io.ensure_packet_budget(remaining_length)
          packet_id = io.read_int
          reason_byte, properties = io.read_ack_tail(remaining_length, PubAckProperties)
          if reason_byte.nil?
            new(packet_id, ReasonCode::Success, properties)
          else
            reason = ReasonCode.from_value?(reason_byte) ||
                     raise MQTT::Protocol::Error::ProtocolError.new(0x81u8, "invalid reason code")
            new(packet_id, reason, properties)
          end
        end

        def to_io(io)
          io.write_ack((TYPE << 4) | {{wire_flags}}, packet_id, reason_code.value, properties)
        end
      end

      def bytesize(version : Version) : UInt32
        rl = remaining_length(version)
        rl + MQTT::Protocol::IO.variable_byte_int_size(rl) + 1
      end

      def self.from_io(io : MQTT::Protocol::IO) : Packet
        # A clean end-of-stream before any byte is a closed connection, not a
        # malformed packet, so it propagates as EOFError. Once we are committed
        # to a packet (below), a short read is a decode error, not an EOF.
        first_byte = io.read_byte? || raise(::IO::EOFError.new)
        read_body(io, first_byte)
      end

      # ameba:disable Metrics/CyclomaticComplexity
      protected def self.read_body(io : MQTT::Protocol::IO, first_byte : UInt8) : Packet
        type = first_byte >> 4
        flags = first_byte & 0b00001111
        io.validate_packet_type(type)
        remaining_length = io.read_remaining_length
        # Every read primitive charges against this budget, so no codec can
        # read past the packet boundary; finish_packet then rejects a codec
        # that consumed too little. Together they enforce [MQTT-2.1.4] framing
        # integrity centrally instead of per packet type.
        io.start_packet(remaining_length)
        packet = case type
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
                 when Auth::TYPE        then Auth.from_io(io, flags, remaining_length)
                 else
                   raise Error::PacketDecode.new "invalid packet type #{type.to_u8}"
                 end
        io.finish_packet
        packet
      rescue ex : ::IO::EOFError
        raise Error::PacketDecode.new "truncated packet"
      ensure
        # Also on error paths, so a stale budget never charges the next
        # packet's header on a reused IO.
        io.abort_packet
      end
    end

    abstract struct SimplePacket < Packet
      private abstract def type

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length.zero?, "invalid length"
        self.new
      end

      def remaining_length(version : Version) : UInt32
        0u32
      end

      def to_io(io)
        io.write_byte(type << 4)
        io.write_remaining_length 0
      end
    end
  end
end
