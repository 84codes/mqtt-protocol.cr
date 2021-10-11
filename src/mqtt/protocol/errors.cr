module MQTT
  module Protocol
    class Error < Exception
      class PacketDecode < Error
      end

      class PacketEncode < Error
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

      class InvalidCredentials < Connect
        def initialize(msg = "invalid credentials")
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
