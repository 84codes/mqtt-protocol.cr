require "./packets"

module MQTT
  module Protocol
    struct Connack < Packet
      # MQTT 3.1.1 return codes (kept as the v3 wire format).
      enum ReturnCode : UInt8
        Accepted                    = 0
        UnacceptableProtocolVersion = 1
        IdentifierRejected          = 2
        ServerUnavailable           = 3
        BadCredentials              = 4
        NotAuthorized               = 5
      end

      # MQTT 5.0 reason codes valid in CONNACK. This is the model; v3
      # connections encode the down-mapped ReturnCode instead.
      enum ReasonCode : UInt8
        Success                     = 0x00
        UnspecifiedError            = 0x80
        MalformedPacket             = 0x81
        ProtocolError               = 0x82
        ImplementationSpecificError = 0x83
        UnsupportedProtocolVersion  = 0x84
        ClientIdentifierNotValid    = 0x85
        BadUserNameOrPassword       = 0x86
        NotAuthorized               = 0x87
        ServerUnavailable           = 0x88
        ServerBusy                  = 0x89
        Banned                      = 0x8A
        BadAuthenticationMethod     = 0x8C
        TopicNameInvalid            = 0x90
        PacketTooLarge              = 0x95
        QuotaExceeded               = 0x97
        PayloadFormatInvalid        = 0x99
        RetainNotSupported          = 0x9A
        QoSNotSupported             = 0x9B
        UseAnotherServer            = 0x9C
        ServerMoved                 = 0x9D
        ConnectionRateExceeded      = 0x9F

        # The v3 ReturnCode for this reason, or nil if there is no equivalent
        # (the consumer should then close the connection without a CONNACK).
        def to_v3_return_code : ReturnCode?
          case self
          when Success                    then ReturnCode::Accepted
          when UnsupportedProtocolVersion then ReturnCode::UnacceptableProtocolVersion
          when ClientIdentifierNotValid   then ReturnCode::IdentifierRejected
          when ServerUnavailable          then ReturnCode::ServerUnavailable
          when BadUserNameOrPassword      then ReturnCode::BadCredentials
          when NotAuthorized              then ReturnCode::NotAuthorized
          end
        end

        def self.from_v3_return_code(rc : ReturnCode) : ReasonCode
          case rc
          in ReturnCode::Accepted                    then Success
          in ReturnCode::UnacceptableProtocolVersion then UnsupportedProtocolVersion
          in ReturnCode::IdentifierRejected          then ClientIdentifierNotValid
          in ReturnCode::ServerUnavailable           then ServerUnavailable
          in ReturnCode::BadCredentials              then BadUserNameOrPassword
          in ReturnCode::NotAuthorized               then NotAuthorized
          end
        end
      end

      TYPE = 2u8

      getter reason_code, properties
      getter? session_present

      def initialize(@session_present : Bool, @reason_code : ReasonCode,
                     @properties : ConnackProperties = ConnackProperties.new)
      end

      def remaining_length(version : Version) : UInt32
        # v3 CONNACK is flags + return code; v5 adds the properties section.
        return 2u32 unless version.v5?
        (2 + @properties.bytesize).to_u32
      end

      @[Deprecated("Use `Connack.new(session_present, reason_code)` with a `ReasonCode`")]
      def initialize(session_present : Bool, return_code : ReturnCode)
        initialize(session_present, ReasonCode.from_v3_return_code(return_code))
      end

      # The down-mapped v3 ReturnCode (raises if the reason has no v3 equivalent).
      @[Deprecated("Use `#reason_code`")]
      def return_code : ReturnCode
        @reason_code.to_v3_return_code ||
          raise Error::PacketEncode.new("no v3 return code for #{@reason_code}")
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags

        decode_assert remaining_length >= 2, "invalid length #{remaining_length} for connack"
        io.ensure_packet_budget(remaining_length)
        connack_flags = io.read_byte
        decode_assert (connack_flags & 0b11111110).zero?, MQTT::Protocol::Error::InvalidConnackFlags, connack_flags
        session_present = (connack_flags & 1u8) > 0

        reason = io.read_connack_reason(io.read_byte)
        # v3 has no property section and v5 must consume the rest of the packet
        # exactly; both are enforced by the byte budget + finish_packet.
        properties = io.read_properties(ConnackProperties)
        new(session_present, reason, properties)
      end

      def to_io(io)
        io.validate_outbound_packet_type(TYPE)
        # Resolve the code byte first: an unmappable v5 reason on a v3 IO must
        # raise before any byte goes on the wire.
        code = io.connack_code_byte(reason_code)
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length(io.version)
        io.write_byte(session_present? ? 1u8 : 0u8)
        io.write_byte(code)
        io.write_properties(properties)
      end
    end
  end
end
