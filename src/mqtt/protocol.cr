require "./protocol/errors"
require "./protocol/version"
require "./protocol/io"
require "./protocol/properties"
require "./protocol/packets"

module MQTT
  module Protocol
    PROTOCOL_VERSION = UInt8.static_array('M', 'Q', 'T', 'T')
  end
end
