module MQTT
  module Protocol
    struct Disconnect < SimplePacket
      TYPE = 14u8

      private def type
        TYPE
      end
    end
  end
end
