module MQTT
  module Protocol
    struct SubAck < Packet
      TYPE = 9u8

      # Per-entry reason code (3.9.3). The granted-QoS values match the v3 wire
      # bytes, so the same enum encodes both versions; only the v5 properties
      # section differs.
      enum ReasonCode : UInt8
        GrantedQos0                         = 0x00
        GrantedQos1                         = 0x01
        GrantedQos2                         = 0x02
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

      # The v3 return codes, kept for source compatibility: use `ReasonCode`,
      # whose granted-QoS values and 0x80 are the same bytes. Crystal cannot
      # deprecate an enum, so the methods taking or returning it warn instead.
      enum ReturnCode : UInt8
        QoS0    =   0
        QoS1    =   1
        QoS2    =   2
        Failure = 128

        @[Deprecated("Use `SubAck::ReasonCode`")]
        def self.from_int(value)
          case value
          when 0
            QoS0
          when 1
            QoS1
          when 2
            QoS2
          when 128
            Failure
          else
            raise Error::PacketDecode.new "invalid return code #{value}"
          end
        end
      end

      getter reason_codes, packet_id, properties

      def initialize(@reason_codes : Array(ReasonCode), @packet_id : UInt16,
                     @properties : SubAckProperties = SubAckProperties.new)
      end

      @[Deprecated("Use `SubAck.new(reason_codes, packet_id)` with `SubAck::ReasonCode`")]
      def self.new(return_codes : Array(ReturnCode), packet_id : UInt16)
        new(return_codes.map { |code| ReasonCode.new(code.value) }, packet_id)
      end

      # v3 has a single failure code, so every v5 failure reads as `Failure`.
      @[Deprecated("Use `#reason_codes`")]
      def return_codes : Array(ReturnCode)
        @reason_codes.map do |code|
          code.value <= 2 ? ReturnCode.new(code.value) : ReturnCode::Failure
        end
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
        packet_id = io.read_packet_id
        properties = io.read_properties(SubAckProperties)
        reason_codes = Array(ReasonCode).new
        while io.remaining_in_packet > 0
          # Version-gated: v3 allows only 0-2 / 0x80 ([MQTT-3.9.3-2 v3.1.1]).
          reason_codes << io.read_suback_reason(io.read_byte)
        end
        new(reason_codes, packet_id, properties)
      end

      def to_io(io)
        io.validate_outbound_packet_type(TYPE)
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length(io.version)
        io.write_int(@packet_id)
        io.write_properties(properties)
        @reason_codes.each do |reason_code|
          io.write_byte(io.suback_code_byte(reason_code))
        end
      end
    end
  end
end
