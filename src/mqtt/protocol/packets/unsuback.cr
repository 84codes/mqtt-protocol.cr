module MQTT
  module Protocol
    struct UnsubAck < Packet
      TYPE = 11u8

      # Per-entry reason code (3.11.3). New in v5: v3 UNSUBACK has no payload.
      enum ReasonCode : UInt8
        Success                     = 0x00
        NoSubscriptionExisted       = 0x11
        UnspecifiedError            = 0x80
        ImplementationSpecificError = 0x83
        NotAuthorized               = 0x87
        TopicFilterInvalid          = 0x8F
        PacketIdentifierInUse       = 0x91
      end

      getter packet_id, properties

      # Nil-backed: a v3 UNSUBACK (no payload) allocates no array. Empty
      # normalises to nil so value equality holds. The getter does not
      # memoize (reads never mutate); appending to its result is not
      # supported - pass the full array to the constructor.
      @reason_codes : Array(ReasonCode)?

      def reason_codes : Array(ReasonCode)
        @reason_codes || [] of ReasonCode
      end

      def reason_codes? : Array(ReasonCode)?
        @reason_codes
      end

      # One reason code per topic filter of the UNSUBSCRIBE, in order
      # [MQTT-3.11.3-1]. A v3 IO writes none, since v3 UNSUBACK has no payload.
      def initialize(reason_codes : Array(ReasonCode), @packet_id : UInt16,
                     @properties : UnsubAckProperties = UnsubAckProperties.new)
        @reason_codes = reason_codes.empty? ? nil : reason_codes
      end

      @[Deprecated("Use `UnsubAck.new(reason_codes, packet_id)` with one reason code per topic filter")]
      def self.new(packet_id : UInt16)
        new(packet_id, UnsubAckProperties.new)
      end

      # A v3 UNSUBACK carries no reason codes; decoding one allocates no array.
      private def initialize(@packet_id : UInt16, @properties : UnsubAckProperties)
      end

      def remaining_length(version : MQTT::Protocol::Version) : UInt32
        # v3 UNSUBACK has no payload, just the packet id.
        return 2u32 unless version.v5?
        (2 + properties.bytesize + (@reason_codes.try(&.size) || 0)).to_u32
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        io.ensure_packet_budget(remaining_length)
        packet_id = io.read_int
        # v3 UNSUBACK is a bare packet id with no payload at all; any v3
        # payload bytes are rejected by the byte budget + finish_packet.
        return new(packet_id, UnsubAckProperties.new) unless io.unsuback_payload?
        properties = io.read_properties(UnsubAckProperties)
        reason_codes = Array(ReasonCode).new
        while io.remaining_in_packet > 0
          byte = io.read_byte
          reason_codes << (ReasonCode.from_value?(byte) ||
                           raise Error::ProtocolError.new(0x81u8, "invalid unsuback reason code #{byte}"))
        end
        new(reason_codes, packet_id, properties)
      end

      def to_io(io)
        io.validate_outbound_packet_type(TYPE)
        # Checked before the header goes out, so the packet is never half
        # written. Every UNSUBSCRIBE has a topic filter, so v5 needs a code.
        if io.unsuback_payload? && @reason_codes.nil?
          raise MQTT::Protocol::Error::PacketEncode.new("v5 UnsubAck needs a reason code per topic filter")
        end
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length(io.version)
        io.write_int(packet_id)
        return unless io.unsuback_payload?
        io.write_properties(properties)
        @reason_codes.try &.each { |reason_code| io.write_byte(reason_code.value) }
      end
    end
  end
end
