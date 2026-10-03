require "./spec_helper"

# Unit specs for the packet byte budget - the counter that makes "no codec can
# read past the packet boundary" (section 2.1.4 framing integrity) a property
# of the type instead of a convention each codec has to remember.
#
# The tricky part is that `Budget` has three states and only two are visible
# through `#remaining`: inactive (nil - charges nothing, so the fixed header
# can be read before a packet is committed), active-with-bytes-left, and
# active-but-exhausted. The last two both report 0 while behaving differently
# under `#charge`, so most of these specs exist to pin that distinction.
private alias Budget = MQTT::Protocol::IO::Budget

private def exhausted_budget : Budget
  budget = Budget.new
  budget.start(1u32)
  budget.charge(1)
  budget
end

describe MQTT::Protocol::IO::Budget do
  describe "inactive (outside a packet read)" do
    it "reports no bytes remaining" do
      Budget.new.remaining.should eq 0u32
    end

    it "charges nothing, so the fixed header can be read uncommitted" do
      budget = Budget.new
      budget.charge(4)
      budget.remaining.should eq 0u32
    end

    it "accepts a finish, so a dispatcher teardown outside a packet is a no-op" do
      Budget.new.finish
    end
  end

  describe "#charge" do
    it "deducts from an active budget" do
      budget = Budget.new
      budget.start(10u32)
      budget.charge(2)
      budget.remaining.should eq 8u32
    end

    it "allows a field that exactly fills the packet" do
      budget = Budget.new
      budget.start(4u32)
      budget.charge(4)
      budget.remaining.should eq 0u32
    end

    it "rejects a field one byte past the packet" do
      budget = Budget.new
      budget.start(2u32)
      ex = expect_raises(MQTT::Protocol::Error::ProtocolError,
        "field of 3 bytes exceeds 2 bytes left in packet") { budget.charge(3) }
      ex.reason_code.should eq 0x81u8
    end

    it "leaves the count untouched when it rejects" do
      budget = Budget.new
      budget.start(2u32)
      expect_raises(MQTT::Protocol::Error::ProtocolError) { budget.charge(5) }
      budget.remaining.should eq 2u32
    end

    # The distinction inactive-vs-exhausted: both report 0 remaining, but an
    # exhausted budget must reject the next byte rather than wave it through.
    it "rejects any byte once the packet is exhausted" do
      ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { exhausted_budget.charge(1) }
      ex.reason_code.should eq 0x81u8
    end

    it "accepts a zero-byte field on an exhausted packet" do
      budget = exhausted_budget
      budget.charge(0)
      budget.remaining.should eq 0u32
    end
  end

  describe "#finish" do
    it "accepts a fully consumed packet" do
      exhausted_budget.finish
    end

    it "rejects trailing bytes the codec did not consume" do
      budget = Budget.new
      budget.start(5u32)
      budget.charge(2)
      ex = expect_raises(MQTT::Protocol::Error::ProtocolError,
        "packet has 3 trailing bytes") { budget.finish }
      ex.reason_code.should eq 0x81u8
    end
  end

  describe "#deactivate" do
    it "reopens the budget so the next packet's header reads uncharged" do
      budget = Budget.new
      budget.start(2u32)
      budget.deactivate
      budget.charge(9)
      budget.remaining.should eq 0u32
    end

    # The dispatcher's `ensure` deactivates after `finish` raised, so a
    # rejected packet must not leave leftovers that fail the *next* finish.
    it "drops leftover bytes, so an aborted packet cannot poison the next one" do
      budget = Budget.new
      budget.start(5u32)
      budget.deactivate
      budget.finish
    end
  end

  describe "#ensure_started" do
    it "arms an inactive budget from the explicit bound" do
      budget = Budget.new
      budget.ensure_started(7u32)
      budget.remaining.should eq 7u32
    end

    it "arms an exhausted budget, so a direct from_io after a packet is bounded" do
      budget = exhausted_budget
      budget.ensure_started(7u32)
      budget.remaining.should eq 7u32
    end

    it "leaves a packet read in progress alone" do
      budget = Budget.new
      budget.start(4u32)
      budget.charge(1)
      budget.ensure_started(99u32)
      budget.remaining.should eq 3u32
    end
  end

  # CONNECT reveals the version mid-packet, so the IO switches framing while a
  # packet read is in flight. The budget must survive that switch: every field
  # after the protocol level byte is read by the *new* framing but still belongs
  # to the packet the *old* one started, so a reset budget would let the tail of
  # a CONNECT run off the end of the packet.
  describe "survives the framing switch mid-CONNECT" do
    # A v5 CONNECT whose declared remaining_length is one byte short of its
    # fields, followed by bytes an unbounded read would happily consume. Every
    # read after the level byte happens under the negotiated v5 framing, so this
    # only raises if the budget carried over.
    it "bounds the CONNECT tail at the declared remaining length" do
      mio = IO::Memory.new
      w = MQTT::Protocol::IO.v5(mio)
      w.write_byte 0b0001_0000u8 # CONNECT
      # MQTT(2+4) + level(1) + flags(1) + keepalive(2) + props(1) + id(2+2) = 15
      w.write_remaining_length 14 # one short
      w.write_string "MQTT"
      w.write_byte 0x05u8        # protocol level 5 -> framing switches here
      w.write_byte 0b0000_0010u8 # clean start
      w.write_int 60u16
      w.write_byte 0x00u8 # properties length 0
      w.write_string "ab"
      mio.write Bytes[0xFF, 0xFF, 0xFF] # would-be next packet
      mio.rewind

      ex = expect_raises(MQTT::Protocol::Error::ProtocolError) do
        MQTT::Protocol::IO.new(mio).read_connect
      end
      ex.reason_code.should eq 0x81u8
    end

    it "accepts the same CONNECT when the remaining length is honest" do
      mio = IO::Memory.new
      w = MQTT::Protocol::IO.v5(mio)
      w.write_byte 0b0001_0000u8
      w.write_remaining_length 15
      w.write_string "MQTT"
      w.write_byte 0x05u8
      w.write_byte 0b0000_0010u8
      w.write_int 60u16
      w.write_byte 0x00u8
      w.write_string "ab"
      mio.write Bytes[0xFF, 0xFF, 0xFF]
      mio.rewind

      io = MQTT::Protocol::IO.new(mio)
      connect = io.read_connect
      connect.client_id.should eq "ab"
      connect.version.should eq MQTT::Protocol::Version::V5
      io.version.should eq MQTT::Protocol::Version::V5
      # The trailing bytes are left for the next read, not swallowed.
      io.remaining_in_packet.should eq 0u32
    end
  end
end
