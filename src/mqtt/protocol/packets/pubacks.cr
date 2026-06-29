require "./packets"

# The four QoS-acknowledgement packets. Each is just a TYPE, a per-packet
# ReasonCode enum, and the shared `ack_packet_body` (defined on Packet), which
# routes all version-dependent framing through the IO's read_ack_tail/write_ack.
module MQTT
  module Protocol
    struct PubAck < Packet
      TYPE = 4u8

      enum ReasonCode : UInt8
        Success                     = 0x00
        NoMatchingSubscribers       = 0x10
        UnspecifiedError            = 0x80
        ImplementationSpecificError = 0x83
        NotAuthorized               = 0x87
        TopicNameInvalid            = 0x90
        PacketIdentifierInUse       = 0x91
        QuotaExceeded               = 0x97
        PayloadFormatInvalid        = 0x99
      end

      ack_packet_body(0u8)
    end

    struct PubRec < Packet
      TYPE = 5u8

      enum ReasonCode : UInt8
        Success                     = 0x00
        NoMatchingSubscribers       = 0x10
        UnspecifiedError            = 0x80
        ImplementationSpecificError = 0x83
        NotAuthorized               = 0x87
        TopicNameInvalid            = 0x90
        PacketIdentifierInUse       = 0x91
        QuotaExceeded               = 0x97
        PayloadFormatInvalid        = 0x99
      end

      ack_packet_body(0u8)
    end

    struct PubRel < Packet
      TYPE = 6u8

      enum ReasonCode : UInt8
        Success                  = 0x00
        PacketIdentifierNotFound = 0x92
      end

      # PUBREL carries fixed-header flags 0b0010.
      ack_packet_body(2u8)
    end

    struct PubComp < Packet
      TYPE = 7u8

      enum ReasonCode : UInt8
        Success                  = 0x00
        PacketIdentifierNotFound = 0x92
      end

      ack_packet_body(0u8)
    end
  end
end
