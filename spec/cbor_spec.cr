require "./spec_helper"

private alias Key = WebAuthn::CBOR::Key

describe WebAuthn::CBOR do
  describe "integers" do
    it "decodes small unsigned integers inline" do
      WebAuthn::CBOR.decode(Bytes[0x00]).as_i.should eq(0_i64)
      WebAuthn::CBOR.decode(Bytes[0x17]).as_i.should eq(23_i64)
    end

    it "decodes unsigned integers of each argument width" do
      WebAuthn::CBOR.decode(Bytes[0x18, 0x18]).as_i.should eq(24_i64)
      WebAuthn::CBOR.decode(Bytes[0x19, 0x01, 0x00]).as_i.should eq(256_i64)
      WebAuthn::CBOR.decode(Bytes[0x1a, 0x00, 0x01, 0x00, 0x00]).as_i.should eq(65536_i64)
      WebAuthn::CBOR.decode(Bytes[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]).as_i.should eq(4294967296_i64)
    end

    it "decodes negative integers as -1 - n" do
      WebAuthn::CBOR.decode(Bytes[0x20]).as_i.should eq(-1_i64)
      # COSE labels live here: -1 is kty-specific, -2 and -3 are x and y.
      WebAuthn::CBOR.decode(Bytes[0x21]).as_i.should eq(-2_i64)
      WebAuthn::CBOR.decode(Bytes[0x38, 0x18]).as_i.should eq(-25_i64)
    end
  end

  describe "strings" do
    it "decodes byte strings" do
      WebAuthn::CBOR.decode(Bytes[0x43, 0x01, 0x02, 0x03]).as_bytes.should eq(Bytes[1, 2, 3])
    end

    it "decodes an empty byte string" do
      WebAuthn::CBOR.decode(Bytes[0x40]).as_bytes.should eq(Bytes.empty)
    end

    it "decodes text strings" do
      WebAuthn::CBOR.decode(cbor_bytes(0x64, "none")).as_s.should eq("none")
    end

    it "rejects text that is not valid UTF-8" do
      expect_raises(WebAuthn::CBOR::MalformedError, /UTF-8/) do
        WebAuthn::CBOR.decode(Bytes[0x62, 0xff, 0xfe])
      end
    end
  end

  describe "arrays and maps" do
    it "decodes an array" do
      WebAuthn::CBOR.decode(Bytes[0x83, 0x01, 0x02, 0x03]).as_a.map(&.as_i).should eq([1_i64, 2_i64, 3_i64])
    end

    it "decodes a map keyed by text" do
      # {"fmt": "none"}
      value = WebAuthn::CBOR.decode(cbor_bytes(0xa1, 0x63, "fmt", 0x64, "none"))
      value["fmt"].as_s.should eq("none")
      value.as_h.size.should eq(1)
    end

    it "decodes a map keyed by negative integers, as COSE keys are" do
      # {1: 2, -1: 1}
      value = WebAuthn::CBOR.decode(Bytes[0xa2, 0x01, 0x02, 0x20, 0x01])
      value[1_i64].as_i.should eq(2_i64)
      value[-1_i64].as_i.should eq(1_i64)
    end

    it "decodes nested structures" do
      # {"a": [1, {"b": 2}]}
      bytes = cbor_bytes(0xa1, 0x61, "a", 0x82, 0x01, 0xa1, 0x61, "b", 0x02)
      inner = WebAuthn::CBOR.decode(bytes)["a"].as_a
      inner.size.should eq(2)
      inner[0].as_i.should eq(1_i64)
      inner[1]["b"].as_i.should eq(2_i64)
    end
  end

  describe "simple values" do
    it "decodes false, true and null" do
      WebAuthn::CBOR.decode(Bytes[0xf4]).as_bool.should be_false
      WebAuthn::CBOR.decode(Bytes[0xf5]).as_bool.should be_true
      WebAuthn::CBOR.decode(Bytes[0xf6]).null?.should be_true
    end

    it "rejects floats" do
      expect_raises(WebAuthn::CBOR::UnsupportedError, /float/) do
        WebAuthn::CBOR.decode(Bytes[0xfa, 0x47, 0xc3, 0x50, 0x00])
      end
    end
  end

  describe "hostile input" do
    it "rejects trailing bytes after the item" do
      expect_raises(WebAuthn::CBOR::MalformedError, /trailing/) do
        WebAuthn::CBOR.decode(Bytes[0x01, 0x02])
      end
    end

    it "rejects truncated input" do
      # 0x19 announces a 2-byte argument, only 1 byte follows.
      expect_raises(WebAuthn::CBOR::MalformedError, /truncated/) do
        WebAuthn::CBOR.decode(Bytes[0x19, 0x01])
      end
    end

    it "rejects a byte string shorter than it claims" do
      expect_raises(WebAuthn::CBOR::MalformedError, /declares a length of 3/) do
        WebAuthn::CBOR.decode(Bytes[0x43, 0x01])
      end
    end

    # A byte string announcing 4 GB must not make us try to allocate it.
    it "rejects a length larger than the remaining input" do
      expect_raises(WebAuthn::CBOR::MalformedError, /declares a length/) do
        WebAuthn::CBOR.decode(Bytes[0x5a, 0xff, 0xff, 0xff, 0xff, 0x01])
      end
    end

    it "rejects indefinite-length items" do
      expect_raises(WebAuthn::CBOR::UnsupportedError, /indefinite/) do
        WebAuthn::CBOR.decode(Bytes[0x5f, 0x41, 0x01, 0xff])
      end
    end

    it "rejects tags" do
      expect_raises(WebAuthn::CBOR::UnsupportedError, /tags/) do
        WebAuthn::CBOR.decode(Bytes[0xc0, 0x01])
      end
    end

    # One value for us, another for the next parser: that is a vulnerability,
    # not a quirk.
    it "rejects duplicate map keys" do
      expect_raises(WebAuthn::CBOR::MalformedError, /duplicate/) do
        WebAuthn::CBOR.decode(Bytes[0xa2, 0x01, 0x02, 0x01, 0x03])
      end
    end

    it "rejects map keys that are neither integers nor text" do
      expect_raises(WebAuthn::CBOR::UnsupportedError, /map keys/) do
        WebAuthn::CBOR.decode(Bytes[0xa1, 0x41, 0x01, 0x02])
      end
    end

    it "rejects nesting deeper than the limit" do
      # 40 nested single-element arrays.
      bytes = Bytes.new(41) { |i| i < 40 ? 0x81_u8 : 0x01_u8 }
      expect_raises(WebAuthn::CBOR::MalformedError, /nesting/) do
        WebAuthn::CBOR.decode(bytes)
      end
    end

    it "rejects reserved additional information" do
      expect_raises(WebAuthn::CBOR::MalformedError, /reserved/) do
        WebAuthn::CBOR.decode(Bytes[0x1c])
      end
    end
  end

  describe ".decode_first" do
    it "reports how many bytes the item consumed" do
      result = WebAuthn::CBOR.decode_first(Bytes[0x43, 0x01, 0x02, 0x03, 0xff, 0xff])
      result[:value].as_bytes.should eq(Bytes[1, 2, 3])
      result[:size].should eq(4)
    end
  end

  describe ".decode_map" do
    it "returns the map" do
      map = WebAuthn::CBOR.decode_map(Bytes[0xa1, 0x01, 0x02])
      map.size.should eq(1)
      map[1_i64].as_i.should eq(2_i64)
    end

    it "refuses a top-level value that is not a map" do
      expect_raises(WebAuthn::CBOR::MalformedError, /expected a CBOR map/) do
        WebAuthn::CBOR.decode_map(Bytes[0x01])
      end
    end
  end
end

describe WebAuthn::CBOR::Any do
  it "reports a type mismatch instead of returning something plausible" do
    value = WebAuthn::CBOR.decode(Bytes[0x01])
    value.as_i?.should eq(1_i64)
    value.as_s?.should be_nil

    expect_raises(WebAuthn::CBOR::TypeError, /expected String/) do
      value.as_s
    end
  end

  it "raises on a missing map key, and stays quiet with []?" do
    map = WebAuthn::CBOR.decode(Bytes[0xa1, 0x01, 0x02])
    map[1_i64].as_i.should eq(2_i64)
    map[9_i64]?.should be_nil
    map.has_key?(1_i64).should be_true
    map.has_key?(9_i64).should be_false

    expect_raises(WebAuthn::CBOR::TypeError, /missing CBOR map key/) do
      map[9_i64]
    end
  end

  it "indexing a non-map yields nothing rather than an error" do
    WebAuthn::CBOR.decode(Bytes[0x01])["x"]?.should be_nil
  end

  # `value || raise` would treat a legitimate `false` as an absent value.
  it "treats a false entry as present" do
    # {1: false}
    map = WebAuthn::CBOR.decode(Bytes[0xa1, 0x01, 0xf4])
    map.has_key?(1_i64).should be_true
    map[1_i64].as_bool.should be_false
  end

  it "treats a null entry as present" do
    # {1: null}
    map = WebAuthn::CBOR.decode(Bytes[0xa1, 0x01, 0xf6])
    map.has_key?(1_i64).should be_true
    map[1_i64].null?.should be_true
  end
end
