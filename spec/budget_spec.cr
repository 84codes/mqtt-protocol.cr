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

  # Why Budget is a shared box and not a plain ivar: CONNECT reveals the
  # version mid-packet, so `IO#reframe` hands the same budget to the new IO
  # and the dispatcher's final check sees every byte both IOs consumed.
  describe "shared across a reframe" do
    it "carries charges from the old IO to the reframed one" do
      mio = IO::Memory.new
      mio.write Bytes[0xAA, 0xBB, 0xCC, 0xDD]
      mio.rewind

      budget = Budget.new
      budget.start(4u32)
      v3 = MQTT::Protocol::IO::V3.new(mio, budget: budget)
      v3.read_byte

      v5 = v3.reframe(MQTT::Protocol::Version::V5)
      v5.should be_a MQTT::Protocol::IO::V5
      v5.remaining_in_packet.should eq 3u32

      v5.read_int
      v3.remaining_in_packet.should eq 1u32
      budget.remaining.should eq 1u32
    end

    it "bounds the reframed IO at the original packet's boundary" do
      mio = IO::Memory.new
      mio.write Bytes[0xAA, 0xBB, 0xCC, 0xDD]
      mio.rewind

      budget = Budget.new
      budget.start(1u32)
      io = MQTT::Protocol::IO::V3.new(mio, budget: budget).reframe(MQTT::Protocol::Version::V5)

      ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { io.read_int }
      ex.reason_code.should eq 0x81u8
      mio.pos.should eq 0
    end
  end
end
