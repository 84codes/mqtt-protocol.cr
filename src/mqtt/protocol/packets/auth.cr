require "./packets"

module MQTT
  module Protocol
    # AUTH (0x0F), new in v5. Wire-level only: the consumer decides whether to
    # honour extended authentication. An empty payload means Success.
    struct Auth < Packet
      TYPE = 15u8

      enum ReasonCode : UInt8
        Success                = 0x00
        ContinueAuthentication = 0x18
        ReAuthenticate         = 0x19
      end

      getter reason_code, properties

      def initialize(@reason_code : ReasonCode = ReasonCode::Success,
                     @properties : AuthProperties = AuthProperties.new)
      end

      # AUTH is v5-only, so its framing does not vary by version.
      def remaining_length(version : Version) : UInt32
        if @reason_code.success? && @properties.empty?
          0u32
        elsif @properties.empty?
          1u32
        else
          (1 + @properties.bytesize).to_u32
        end
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        reason_byte, properties = io.read_reason_tail(remaining_length, AuthProperties)
        if reason_byte.nil?
          new(ReasonCode::Success, properties)
        else
          reason = ReasonCode.from_value?(reason_byte) ||
                   raise Error::ProtocolError.new(0x81u8, "invalid auth reason code")
          new(reason, properties)
        end
      end

      def to_io(io)
        io.write_reason_tail(TYPE << 4, reason_code.value, properties)
      end
    end
  end
end
