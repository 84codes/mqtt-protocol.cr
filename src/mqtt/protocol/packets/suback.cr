module MQTT
  module Protocol
    struct SubAck < Packet
      TYPE = 9u8

      # Per-entry reason code (3.9.3). The granted-QoS values match the v3 wire
      # bytes, so the same enum encodes both versions; only the v5 properties
      # section differs.
      enum ReasonCode : UInt8
        GrantedQoS0                         = 0x00
        GrantedQoS1                         = 0x01
        GrantedQoS2                         = 0x02
        UnspecifiedError                    = 0x80
        ImplementationSpecificError         = 0x83
        NotAuthorized                       = 0x87
        TopicFilterInvalid                  = 0x8F
        PacketIdentifierInUse               = 0x91
        QuotaExceeded                       = 0x97
        SharedSubscriptionsNotSupported     = 0x9E
        SubscriptionIdentifiersNotSupported = 0xA1
        WildcardSubscriptionsNotSupported   = 0xA2
      end

      getter reason_codes, packet_id, properties

      def initialize(@reason_codes : Array(ReasonCode), @packet_id : UInt16,
                     @properties : SubAckProperties = SubAckProperties.new)
      end

      def remaining_length(version : MQTT::Protocol::Version) : UInt32
        len = 2 + @reason_codes.size
        len += version.properties_bytesize(properties)
        len.to_u32
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : UInt8, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length > 2, "protocol violation"
        io.ensure_packet_budget(remaining_length)
        packet_id = io.read_int
        properties = io.read_properties(SubAckProperties)
        reason_codes = Array(ReasonCode).new
        while io.remaining_in_packet > 0
          # Version-gated: v3 allows only 0-2 / 0x80 ([MQTT-3.9.3-2]).
          reason_codes << io.read_suback_reason(io.read_byte)
        end
        self.new(reason_codes, packet_id, properties)
      end

      def to_io(io)
        # Reject codes the version cannot express before the header goes out,
        # so an unencodable SUBACK never leaves a truncated packet behind.
        @reason_codes.each { |reason_code| io.validate_suback_reason(reason_code) }
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length(io.version)
        io.write_int(@packet_id)
        io.write_properties(properties)
        @reason_codes.each do |reason_code|
          io.write_byte(reason_code.value)
        end
      end
    end
  end
end
