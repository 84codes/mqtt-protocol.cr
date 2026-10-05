module MQTT
  module Protocol
    class Error < Exception
      # Any decode failure carries the v5 reason code a consumer should
      # answer with (in a CONNACK or DISCONNECT, then close). Defaults to
      # 0x81 Malformed Packet (spec 2.4), which covers every plain parse
      # failure; use ProtocolError for violations that need a more specific
      # code. A v5 consumer rescues this one type and reads reason_code
      # uniformly; v3 consumers just close, ignoring the code. A rejected
      # CONNECT is an `Error::Connect` instead.
      class PacketDecode < Error
        getter reason_code : UInt8

        def initialize(message = nil, @reason_code : UInt8 = 0x81u8)
          super(message)
        end
      end

      class PacketEncode < Error
      end

      # A decode violation answered with a specific (non-0x81) reason code.
      # Subclasses PacketDecode so existing v3 consumers, which just close
      # on PacketDecode, keep working unchanged.
      class ProtocolError < PacketDecode
        def initialize(reason_code : UInt8, message = "protocol error")
          super(message, reason_code)
        end
      end

      class PacketTooLarge < ProtocolError
        def initialize(max_packet_size : UInt32, packet_size)
          super(0x95u8, "packet_max_size=#{max_packet_size} got=#{packet_size}")
        end
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

      # A CONNECT the server rejects, whether the decoder found it unacceptable
      # or the consumer did (authentication, limits). `reason_code` is what to
      # answer in the CONNACK; a v3 IO writes the matching v3 return code.
      #
      # Not a `PacketDecode`: a rejection need not mean malformed bytes. Rescue
      # it before `PacketDecode` around a CONNECT read.
      class Connect < Error
        getter reason_code : Connack::ReasonCode

        def initialize(@reason_code : Connack::ReasonCode, message = nil)
          super(message)
        end

        @[Deprecated("Use `#reason_code`")]
        def return_code : UInt8
          return_code = @reason_code.to_v3_return_code ||
                        raise PacketEncode.new("no v3 return code for #{@reason_code}")
          return_code.value
        end
      end

      class UnacceptableProtocolVersion < Connect
        def initialize(msg = "unacceptable protocol version")
          super(Connack::ReasonCode::UnsupportedProtocolVersion, msg)
        end
      end

      class IdentifierRejected < Connect
        def initialize(msg = "identifier rejected")
          super(Connack::ReasonCode::ClientIdentifierNotValid, msg)
        end
      end

      class ServerUnavailable < Connect
        def initialize(msg = "server unavailable")
          super(Connack::ReasonCode::ServerUnavailable, msg)
        end
      end

      class BadCredentials < Connect
        def initialize(msg = "bad credentials, invalid format")
          super(Connack::ReasonCode::BadUserNameOrPassword, msg)
        end
      end

      class NotAuthorized < Connect
        def initialize(msg = "not authorized")
          super(Connack::ReasonCode::NotAuthorized, msg)
        end
      end
    end
  end
end
