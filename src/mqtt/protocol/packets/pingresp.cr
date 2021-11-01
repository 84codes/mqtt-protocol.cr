module MQTT
  module Protocol
    struct PingResp < SimplePacket
      TYPE = 13u8

      private def type
        TYPE
      end
    end
  end
end
