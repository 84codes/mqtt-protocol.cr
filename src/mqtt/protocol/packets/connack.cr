require "./packets"

module MQTT
  module Protocol
    struct Connack < Packet
      enum ReturnCode : UInt8
        Accepted                    = 0
        UnacceptableProtocolVersion = 1
        IdentifierRejected          = 2
        ServerUnavailable           = 3
        BadCredentials              = 4
        NotAuthorized               = 5
      end

      TYPE = 2u8

      getter return_code
      getter? session_present

      def initialize(@session_present : Bool, @return_code : ReturnCode)
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags

        connack_flags = io.read_byte
        decode_assert (connack_flags & 0b11111110).zero?, MQTT::Protocol::Error::InvalidConnackFlags, connack_flags
        session_present = (connack_flags & 1u8) > 0

        return_code = io.read_byte
        decode_assert return_code < 6, "invalid return code: #{return_code}"

        self.new(session_present, ReturnCode.new(return_code))
      end

      def to_io(io)
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length
        io.write_byte session_present? ? 1u8 : 0u8
        io.write_byte return_code.to_u8
      end
    end
  end
end
