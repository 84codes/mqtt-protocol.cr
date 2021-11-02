# mqtt-protocol.cr

mqtt-protocol.cr is a MQTT 3.1.1 serialization library for Crystal

### Parts of [ MQTT specification Appendix B](http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718134) that are covered
<details>
<summary>List normative statements</summary>

- [x] MQTT-1.5.3-1
  > The character data in a UTF-8 encoded
   string MUST be well-formed UTF-8 as defined by the Unicode specification [Unicode] and restated in RFC 3629 [RFC3629]. In particular this data MUST NOT include encodings of code points between U+D800 and U+DFFF. If a Server or Client receives a Control Packet containing ill-formed UTF-8 it MUST close the Network Connection.

  Covered in @1b2b523e by utilizing https://devdocs.io/crystal/api/1.1.1/string#valid_encoding?:Bool-instance-method

- [x] MQTT-1.5.3-2
  > A UTF-8 encoded string MUST NOT include an encoding of the null character U+0000. If a receiver (Server or Client) receives a Control Packet containing U+0000 it MUST close the Network Connection.

  Covered in @1b2b523e

- [x] MQTT-1.5.3-3
  > A UTF-8 encoded sequence 0xEF 0xBB 0xBF is always to be interpreted to mean U+FEFF ("ZERO WIDTH NO-BREAK SPACE") wherever it appears in a string and MUST NOT be skipped over or stripped off by a packet receiver.

  Covered by Crystal:
  ```crystal
  io = IO::Memory.new(Bytes[0xEF, 0xBB, 0xBF])
  s = io.read_char.not_nil!
  puts s == '\uFEFF' # => true
  ```
- [x] MQTT-2.2.2-1
  > Where a flag bit is marked as “Reserved” in Table 2.2 - Flag Bits, it is reserved for future use and MUST be set to the value listed in that table.

  Covered in the serializing of each packet.

- [x] MQTT-2.2.2-2
  >If invalid flags are received, the receiver MUST close the Network Connection.

  Covered in the deserializing of each packet.

- [x] MQTT-2.3.1-1
  >SUBSCRIBE, UNSUBSCRIBE, and PUBLISH (in cases where QoS > 0) Control Packets MUST contain a non-zero 16-bit Packet Identifier.

  Covered in the serializing of each packet.

- [x] MQTT-2.3.1-5
  >A PUBLISH Packet MUST NOT contain a Packet Identifier if its QoS value is set to 0.

  Covered in the serialization of the packet.

- [x] MQTT-3.1.2-1

  > If the protocol name is incorrect the Server MAY disconnect the Client, or it MAY continue processing the CONNECT packet in accordance with some other specification. In the latter case, the Server MUST NOT continue to process the CONNECT packet in line with this specification.

  This protocol implementation WILL Raise an error and NOT continue to process the CONNECT packet.

- [x] MQTT-3.1.2-3

  > The Server MUST validate that the reserved flag in the CONNECT Control Packet is set to zero and disconnect the Client if it is not zero.

  The protocol will raise an error if the flags are not zero.

- [x] MQTT-3.1.2-11

  > If the Will Flag is set to 0 the Will QoS and Will Retain fields in the Connect Flags MUST be set to zero and the Will Topic and Will Message fields MUST NOT be present in the payload.

  The protocol will raise an error if the Will QoS or Will Retain fields are set. It will not validate whether the payload contains a Will Topic or and Will Message.


- [x] MQTT-3.1.2-13

  > If the Will Flag is set to 0, then the Will QoS MUST be set to 0 (0x00).

  The protocol will raise and error if the Will QoS is not 0 when the Will Flag is 0.

- [x] MQTT-3.1.2-14

  > If the Will Flag is set to 1, the value of Will QoS can be 0 (0x00), 1 (0x01), or 2 (0x02). It MUST NOT be 3 (0x03).

  The protocol will raise an error if Will QoS i 3 when Will Flag is 1.

- [x] MQTT-3.1.2-15

  > If the Will Flag is set to 0, then the Will Retain Flag MUST be set to 0.

  The protocol will raise an error if Will Retain is set to 1 while Will Flag is  1.

- [x] MQTT-3.1.2-18

  > If the User Name Flag is set to 0, a user name MUST NOT be present in the payload.

  The protocol will not validate whether the payload contains a username or not.

- [x] MQTT-3.1.2-19

  > If the User Name Flag is set to 1, a user name MUST be present in the payload.

  The protocol will not validate whether the payload contains a username, however, it will try to read the username

- [x] MQTT-3.1.2-20

  > If the Password Flag is set to 0, a password MUST NOT be present in the payload.

  The protocol will not validate whether the payload contains a password or not.

- [x] MQTT-3.1.2-21

  > If the Password Flag is set to 1, a password MUST be present in the payload.

  The protocol will not validate whether the payload contains a password, however, it will try to read the password

- [x] MQTT-3.1.2-22

  > If the User Name Flag is set to 0, the Password Flag MUST be set to 0.

  The protocol will raise an error if the password flag is set but not the username flag. It will not add any password payload if the username is not set.

- [x] MQTT-3.1.3-1

  > These fields, if present, MUST appear in the order Client Identifier, Will Topic, Will Message, User Name, Password.

  The protocol follows this rule.

- [x] MQTT-3.1.3-3

  > The Client Identifier (ClientId) MUST be present and MUST be the first field in the CONNECT packet payload.

  The protocol allows empty string for clean_sessions.

- [x] MQTT-3.1.3-4

  > The ClientId MUST be a UTF-8 encoded string as defined in Section 1.5.3.

  Covered by MQTT-1.5.3-1

- [x] MQTT-3.1.3-7

  > If the Client supplies a zero-byte ClientId, the Client MUST also set CleanSession to 1.

  The protocol follows this rule.

- [x] MQTT-3.1.3-8

  > If the Client supplies a zero-byte ClientId with CleanSession set to 0, the Server MUST respond to the CONNECT Packet with a CONNACK return code 0x02 (Identifier rejected) and then close the Network Connection.

  The protocol will raise an IdentifierRejected error that the server can handle accordingly.

- [x] MQTT-3.1.3-10

  > The Will Topic MUST be a UTF-8 encoded string as defined in Section ‎1.5.3.

  Covered by MQTT-1.5.3-1

- [x] MQTT-3.1.3-11

  > The User Name MUST be a UTF-8 encoded string as defined in Section 1.5.3.

  Covered by MQTT-1.5.3-1

- [x] MQTT-3.3.1-2

  > The DUP flag MUST be set to 0 for all QoS 0 messages.

  The protocol will raise an error if it encounters a set DUP flag for a QoS 0 message.

- [x] MQTT-3.3.1-4

  > A PUBLISH Packet MUST NOT have both QoS bits set to 1. If a Server or Client receives a PUBLISH Packet which has both QoS bits set to 1 it MUST close the Network Connection.

  The protocol ensures that QoS is 0, 1 or 2.

- [x] MQTT-3.3.2-1

  > The Topic Name MUST be present as the first field in the PUBLISH Packet Variable header. It MUST be a UTF-8 encoded string.

  Covered by the protocol in combination with MQTT-1.5.3-1

- [x] MQTT-3.3.2-2

  > The Topic Name in the PUBLISH Packet MUST NOT contain wildcard characters.

  The protocol raises ArgumentError if creating a Publish Packet with wildcards in topic.

- [x] MQTT-3.6.1-1

  > Bits 3,2,1 and 0 of the fixed header in the PUBREL Control Packet are reserved and MUST be set to 0,0,1 and 0 respectively. The Server MUST treat any other value as malformed and close the Network Connection.

  The protocol will raise an error if these values are not correct.

- [x] MQTT-3.8.1-1

  > Bits 3,2,1 and 0 of the fixed header of the SUBSCRIBE Control Packet are reserved and MUST be set to 0,0,1 and 0 respectively. The Server MUST treat any other value as malformed and close the Network Connection.

   The protocol will raise an error if these values are not correct.

- [x] MQTT-3.8.3-1

  > The Topic Filters in a SUBSCRIBE packet payload MUST be UTF-8 encoded strings as defined in Section 1.5.3.

  Covered by MQTT-1.5.3-1

- [x] MQTT-3.8.3-3

  > The payload of a SUBSCRIBE packet MUST contain at least one Topic Filter / QoS pair. A SUBSCRIBE packet with no payload is a protocol violation.

  Covered by the protocol by ensuring that the remaining length of the fixed header is larger than 2.

- [x] MQTT-3-8.3-4

  > The Server MUST treat a SUBSCRIBE packet as malformed and close the Network Connection if any of Reserved bits in the payload are non-zero, or QoS is not 0,1 or 2.

  Covered by the protocol, it will raise errors if any of these cases are violated.

- [x] MQTT-3.9.3-2

  > SUBACK return codes other than 0x00, 0x01, 0x02 and 0x80 are reserved and MUST NOT be used.

  Covered by the protocol, it will raise an error if any other return codes are used.

- [x] MQTT-3.10.1-1

  > Bits 3,2,1 and 0 of the fixed header of the UNSUBSCRIBE Control Packet are reserved and MUST be set to 0,0,1 and 0 respectively. The Server MUST treat any other value as malformed and close the Network Connection.

  The protocol will raise an error if these values are not correct.

- [x] MQTT-3.10.3-1

  > The Topic Filters in an UNSUBSCRIBE packet MUST be UTF-8 encoded strings as defined in Section 1.5.3, packed contiguously.

  Covered by MQTT-1.5.3-1

- [x] MQTT-3.10.3-2

  > The Payload of an UNSUBSCRIBE packet MUST contain at least one Topic Filter. An UNSUBSCRIBE packet with no payload is a protocol violation.

  Covered by the protocol by ensuring that the remaining length of the fixed header is larger than 2.

- [x] MQTT-3.14.1-1

  > The Server MUST validate that reserved bits are set to zero and disconnect the Client if they are not zero.

  Covered by the protocol, it will raise an error if these values are not correct.

- [x] MQTT-4.7.1-1

  > The wildcard characters can be used in Topic Filters, but MUST NOT be used within a Topic Name.

  Covered by the protocol.

- [x] MQTT-4.7.1-2

  > The multi-level wildcard character MUST be specified either on its own or following a topic level separator. In either case it MUST be the last character specified in the Topic Filter.

  Covered by the protocol.

- [x] MQTT-4.7.1-3

  > The single-level wildcard can be used at any level in the Topic Filter, including first and last levels. Where it is used it MUST occupy an entire level of the filter.

  Covered by the protocol.

- [x] MQTT-4.7.3-1

  > All Topic Names and Topic Filters MUST be at least one character long.

  Covered by the protocol.

- [x] MQTT-4.7.3-2

  > Topic Names and Topic Filters MUST NOT include the null character (Unicode U+0000).

  Covered by the protocol.

- [x] MQTT-4.7.3-3

  > Topic Names and Topic Filters are UTF-8 encoded strings, they MUST NOT encode to more than 65535 bytes.

  Covered by the protocol.

</details>
