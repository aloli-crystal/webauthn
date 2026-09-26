require "./spec_helper"

describe WebAuthn::AuthenticatorData do
  describe "parsing" do
    it "reads the fixed header" do
      bytes = build_authenticator_data(TEST_RP_ID, flags: FLAG_UP | FLAG_UV, sign_count: 42_u32)
      data = WebAuthn::AuthenticatorData.parse(bytes)

      data.rp_id_hash.should eq(sha256(TEST_RP_ID.to_slice))
      data.sign_count.should eq(42_u32)
      data.user_present?.should be_true
      data.user_verified?.should be_true
      data.attested_credential_data?.should be_false
      data.credential_id.should be_nil
    end

    it "reads a big-endian counter at the top of its range" do
      bytes = build_authenticator_data(TEST_RP_ID, flags: FLAG_UP, sign_count: 0xDEADBEEF_u32)
      WebAuthn::AuthenticatorData.parse(bytes).sign_count.should eq(0xDEADBEEF_u32)
    end

    it "decodes each flag independently" do
      bytes = build_authenticator_data(TEST_RP_ID, flags: FLAG_UP | FLAG_BE | FLAG_BS)
      data = WebAuthn::AuthenticatorData.parse(bytes)

      data.user_present?.should be_true
      data.user_verified?.should be_false
      data.backup_eligible?.should be_true
      data.backup_state?.should be_true
      data.extension_data?.should be_false
    end

    it "reads attested credential data, including the variable-length COSE key" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      credential_id = Random::Secure.random_bytes(48)
      aaguid = Random::Secure.random_bytes(16)

      bytes = build_authenticator_data(
        TEST_RP_ID, flags: FLAG_UP | FLAG_AT,
        credential_id: credential_id, cose_key: cose_ec2_key(key.public_key), aaguid: aaguid
      )
      data = WebAuthn::AuthenticatorData.parse(bytes)

      data.credential_id.should eq(credential_id)
      data.aaguid.should eq(aaguid)
      public_key = data.credential_public_key
      public_key.should_not be_nil
      public_key.try(&.algorithm).should eq(Jose::JWS::Algorithm::ES256)
    end

    # The COSE key does not announce its length; finding the end of it is what
    # makes extensions parseable at all.
    it "finds the extension block that follows the COSE key" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      bytes = build_authenticator_data(
        TEST_RP_ID, flags: FLAG_UP | FLAG_AT | FLAG_ED,
        credential_id: Random::Secure.random_bytes(16),
        cose_key: cose_ec2_key(key.public_key),
        extensions: cbor_map([{cbor_tstr("credProtect"), cbor_int(2)}])
      )

      data = WebAuthn::AuthenticatorData.parse(bytes)
      data.extension_data?.should be_true
      data.credential_public_key.should_not be_nil
    end
  end

  describe "malformed input" do
    it "refuses a record shorter than the fixed header" do
      expect_raises(WebAuthn::AuthenticatorData::MalformedError, /needs at least 37/) do
        WebAuthn::AuthenticatorData.parse(Bytes.new(36))
      end
    end

    it "refuses trailing bytes nobody accounts for" do
      bytes = build_authenticator_data(TEST_RP_ID, flags: FLAG_UP)
      padded = Bytes.new(bytes.size + 3)
      bytes.copy_to(padded[0, bytes.size])

      expect_raises(WebAuthn::AuthenticatorData::MalformedError, /unaccounted/) do
        WebAuthn::AuthenticatorData.parse(padded)
      end
    end

    it "refuses truncated attested credential data" do
      bytes = build_authenticator_data(TEST_RP_ID, flags: FLAG_UP | FLAG_AT)
      expect_raises(WebAuthn::AuthenticatorData::MalformedError, /truncated attested/) do
        WebAuthn::AuthenticatorData.parse(bytes)
      end
    end

    it "refuses a credential id beyond the 1023-byte limit" do
      io = IO::Memory.new
      io.write(sha256(TEST_RP_ID.to_slice))
      io.write_byte(FLAG_UP | FLAG_AT)
      4.times { io.write_byte(0_u8) }
      io.write(Bytes.new(16))
      io.write_byte(0xff_u8)
      io.write_byte(0xff_u8)

      expect_raises(WebAuthn::AuthenticatorData::MalformedError, /1023-byte limit/) do
        WebAuthn::AuthenticatorData.parse(io.to_slice)
      end
    end

    it "refuses a credential id that runs past the end" do
      io = IO::Memory.new
      io.write(sha256(TEST_RP_ID.to_slice))
      io.write_byte(FLAG_UP | FLAG_AT)
      4.times { io.write_byte(0_u8) }
      io.write(Bytes.new(16))
      io.write_byte(0x01_u8)
      io.write_byte(0x00_u8) # announces 256 bytes
      io.write(Bytes.new(4))

      expect_raises(WebAuthn::AuthenticatorData::MalformedError, /runs past the end/) do
        WebAuthn::AuthenticatorData.parse(io.to_slice)
      end
    end

    it "refuses attested credential data with no public key" do
      io = IO::Memory.new
      io.write(sha256(TEST_RP_ID.to_slice))
      io.write_byte(FLAG_UP | FLAG_AT)
      4.times { io.write_byte(0_u8) }
      io.write(Bytes.new(16))
      io.write_byte(0x00_u8)
      io.write_byte(0x04_u8)
      io.write(Bytes[1, 2, 3, 4])

      expect_raises(WebAuthn::AuthenticatorData::MalformedError, /no credential public key/) do
        WebAuthn::AuthenticatorData.parse(io.to_slice)
      end
    end
  end
end

describe WebAuthn::ClientData do
  it "parses the fields a ceremony checks" do
    challenge = WebAuthn.generate_challenge
    data = WebAuthn::ClientData.parse(
      build_client_data(WebAuthn::ClientData::TYPE_GET, challenge, TEST_ORIGIN)
    )

    data.type.should eq("webauthn.get")
    data.origin.should eq(TEST_ORIGIN)
    data.cross_origin?.should be_false
    data.challenge_matches?(challenge).should be_true
    data.challenge_matches?(WebAuthn.generate_challenge).should be_false
  end

  # Re-serialising the JSON would change key order or escaping, and the hash
  # would no longer match what the authenticator signed.
  it "hashes the bytes as received, not a re-encoding" do
    raw = %({"type":"webauthn.get","challenge":"AAAA","origin":"#{TEST_ORIGIN}"}).to_slice
    WebAuthn::ClientData.parse(raw).hash.should eq(sha256(raw))
  end

  it "accepts an unpadded base64url challenge" do
    # 3 bytes encode to 4 base64 characters with no padding needed.
    WebAuthn::ClientData.parse(
      %({"type":"webauthn.get","challenge":"AQID","origin":"x"}).to_slice
    ).challenge_matches?(Bytes[1, 2, 3]).should be_true
  end

  it "treats an unparseable challenge as a mismatch rather than an error" do
    WebAuthn::ClientData.parse(
      %({"type":"webauthn.get","challenge":"!!!not base64!!!","origin":"x"}).to_slice
    ).challenge_matches?(Bytes[1, 2, 3]).should be_false
  end

  it "refuses input that is not JSON" do
    expect_raises(WebAuthn::ClientData::MalformedError, /not valid JSON/) do
      WebAuthn::ClientData.parse("nonsense".to_slice)
    end
  end

  it "refuses a JSON value that is not an object" do
    expect_raises(WebAuthn::ClientData::MalformedError, /not a JSON object/) do
      WebAuthn::ClientData.parse("[1,2,3]".to_slice)
    end
  end

  it "refuses client data missing a required field" do
    expect_raises(WebAuthn::ClientData::MalformedError, /missing "origin"/) do
      WebAuthn::ClientData.parse(%({"type":"webauthn.get","challenge":"AQID"}).to_slice)
    end
  end
end
