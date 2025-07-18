require "./protocol/errors"
require "./protocol/io"
require "./protocol/packets"

module MQTT
  module Protocol
    PROTOCOL_VERSION = UInt8.static_array('M', 'Q', 'T', 'T')

    # Protocol version constants
    MQTT_3_1_VERSION   = 0x03_u8
    MQTT_3_1_1_VERSION = 0x04_u8

    # Protocol name constants
    MQTT_3_1_PROTOCOL_NAME   = "MQIsdp"
    MQTT_3_1_1_PROTOCOL_NAME = "MQTT"
  end
end
