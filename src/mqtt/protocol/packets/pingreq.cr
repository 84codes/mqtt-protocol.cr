module MQTT
  module Protocol
    struct PingReq < SimplePacket
      TYPE = 12u8

      private def type
        TYPE
      end
    end
  end
end
