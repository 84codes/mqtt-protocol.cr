require "./protocol/errors"
require "./protocol/io"
require "./protocol/packets"

module MQTT
  module Protocol
    PROTOCOL_VERSION = UInt8.static_array('M', 'Q', 'T', 'T')
  end
end
