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

      getter packet_id, reason_codes, properties

      def initialize(@packet_id : UInt16, @reason_codes : Array(ReasonCode) = [] of ReasonCode,
                     @properties : UnsubAckProperties = UnsubAckProperties.new)
      end

      def remaining_length(version : MQTT::Protocol::Version) : UInt32
        # v3 UNSUBACK has no payload, just the packet id.
        return 2u32 unless version.v5?
        (2 + properties.bytesize + reason_codes.size).to_u32
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        # The one genuine v3/v5 structural difference: v3 UNSUBACK is a bare
        # packet id with no payload at all (not just a missing section), so a
        # reason-code payload is rejected outright rather than parsed.
        unless io.version.v5?
          decode_assert remaining_length == 2, "invalid length"
          return self.new(io.read_int)
        end
        packet_id = io.read_int
        properties = io.read_properties(UnsubAckProperties)
        reason_codes = Array(ReasonCode).new
        while io.remaining_in_packet > 0
          byte = io.read_byte
          reason_codes << (ReasonCode.from_value?(byte) ||
                           raise Error::ProtocolError.new(0x81u8, "invalid unsuback reason code #{byte}"))
        end
        self.new(packet_id, reason_codes, properties)
      end

      def to_io(io)
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length(io.version)
        io.write_int(packet_id)
        return unless io.version.v5?
        io.write_properties(properties)
        reason_codes.each { |reason_code| io.write_byte(reason_code.value) }
      end
    end
  end
end
