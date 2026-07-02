require "./packets"

module MQTT
  module Protocol
    # Promoted out of SimplePacket for v5: bidirectional, with an optional
    # reason code + properties. v3 DISCONNECT stays an empty packet.
    struct Disconnect < Packet
      TYPE = 14u8

      enum ReasonCode : UInt8
        NormalDisconnection                 = 0x00
        DisconnectWithWillMessage           = 0x04
        UnspecifiedError                    = 0x80
        MalformedPacket                     = 0x81
        ProtocolError                       = 0x82
        ImplementationSpecificError         = 0x83
        NotAuthorized                       = 0x87
        ServerBusy                          = 0x89
        ServerShuttingDown                  = 0x8B
        KeepAliveTimeout                    = 0x8D
        SessionTakenOver                    = 0x8E
        TopicFilterInvalid                  = 0x8F
        TopicNameInvalid                    = 0x90
        ReceiveMaximumExceeded              = 0x93
        TopicAliasInvalid                   = 0x94
        PacketTooLarge                      = 0x95
        MessageRateTooHigh                  = 0x96
        QuotaExceeded                       = 0x97
        AdministrativeAction                = 0x98
        PayloadFormatInvalid                = 0x99
        RetainNotSupported                  = 0x9A
        QoSNotSupported                     = 0x9B
        UseAnotherServer                    = 0x9C
        ServerMoved                         = 0x9D
        SharedSubscriptionsNotSupported     = 0x9E
        ConnectionRateExceeded              = 0x9F
        MaximumConnectTime                  = 0xA0
        SubscriptionIdentifiersNotSupported = 0xA1
        WildcardSubscriptionsNotSupported   = 0xA2
      end

      getter reason_code, properties

      def initialize(@reason_code : ReasonCode = ReasonCode::NormalDisconnection,
                     @properties : DisconnectProperties = DisconnectProperties.new)
      end

      def remaining_length(version : Version) : UInt32
        # v3 DISCONNECT is always an empty packet.
        return 0u32 unless version.v5?
        IO.tail_bytesize(@reason_code.value, @properties)
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        reason_byte, properties = io.read_reason_tail(remaining_length, DisconnectProperties)
        if reason_byte.nil?
          new(ReasonCode::NormalDisconnection, properties)
        else
          reason = ReasonCode.from_value?(reason_byte) ||
                   raise Error::ProtocolError.new(0x81u8, "invalid disconnect reason code")
          new(reason, properties)
        end
      end

      def to_io(io)
        io.write_reason_tail(TYPE << 4, reason_code.value, properties)
      end
    end
  end
end
