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
        packet_id = io.read_int
        bytes_to_read = io.consume(remaining_length, 2)
        properties, consumed = io.read_properties(SubAckProperties, bytes_to_read)
        bytes_to_read = io.consume(bytes_to_read, consumed)
        reason_codes = Array(ReasonCode).new
        while bytes_to_read > 0
          byte = io.read_byte
          reason_codes << (ReasonCode.from_value?(byte) ||
                           raise Error::ProtocolError.new(0x81u8, "invalid suback reason code #{byte}"))
          bytes_to_read = io.consume(bytes_to_read, 1)
        end
        self.new(reason_codes, packet_id, properties)
      end

      def to_io(io)
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
