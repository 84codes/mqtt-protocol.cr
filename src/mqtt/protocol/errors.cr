module MQTT
  module Protocol
    class Error < Exception
      class PacketDecode < Error
      end

      class PacketEncode < Error
      end

      class InvalidFlags < PacketDecode
        def initialize(flags : UInt8)
          super sprintf("invalid flags: %04b", flags)
        end
      end

      class InvalidConnackFlags < PacketDecode
        def initialize(flags : UInt8)
          super sprintf("invalid connack flags: %08b", flags)
        end
      end

      abstract class Connect < Error
        abstract def return_code : UInt8
      end

      class UnacceptableProtocolVersion < Connect
        def initialize(msg = "unacceptable protocol version")
          super(msg)
        end

        def return_code : UInt8
          1u8
        end
      end

      class IdentifierRejected < Connect
        def initialize(msg = "identifier rejected")
          super(msg)
        end

        def return_code : UInt8
          2u8
        end
      end

      class ServerUnavailable < Connect
        def initialize(msg = "server unavailable")
          super(msg)
        end

        def return_code : UInt8
          3u8
        end
      end

      class BadCredentials < Connect
        def initialize(msg = "bad credentials, invalid format")
          super(msg)
        end

        def return_code : UInt8
          4u8
        end
      end

      class NotAuthorized < Connect
        def initialize(msg = "not authorized")
          super(msg)
        end

        def return_code : UInt8
          5u8
        end
      end
    end
  end
end
