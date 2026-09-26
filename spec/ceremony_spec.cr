require "./spec_helper"

describe WebAuthn::RelyingParty do
  describe "configuration" do
    it "refuses an empty id, origin list or algorithm list" do
      expect_raises(ArgumentError, /needs an id/) do
        WebAuthn::RelyingParty.new(id: "", origins: [TEST_ORIGIN])
      end
      expect_raises(ArgumentError, /at least one origin/) do
        WebAuthn::RelyingParty.new(id: TEST_RP_ID, origins: [] of String)
      end
      expect_raises(ArgumentError, /at least one algorithm/) do
        WebAuthn::RelyingParty.new(id: TEST_RP_ID, origins: [TEST_ORIGIN], algorithms: [] of Int64)
      end
    end

    it "hashes its id the way authenticator data does" do
      test_relying_party.id_hash.should eq(sha256(TEST_RP_ID.to_slice))
    end
  end

  describe "registration" do
    it "accepts a well-formed registration and returns the credential to store" do
      rp = test_relying_party
      reg = fake_registration(rp)

      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      credential.id.should eq(reg.credential_id)
      credential.sign_count.should eq(0_u32)
      credential.user_verified?.should be_true
      credential.public_key.algorithm.should eq(Jose::JWS::Algorithm::ES256)
      credential.aaguid.size.should eq(16)
    end

    it "accepts an RS256 credential, as Windows Hello enrols" do
      rp = test_relying_party
      reg = fake_registration(rp, key: Jose::JWK::RSAKey.generate(2048))

      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)
      credential.public_key.algorithm.should eq(Jose::JWS::Algorithm::RS256)
    end

    it "records backup eligibility and state" do
      rp = test_relying_party
      reg = fake_registration(rp, flags: FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE | FLAG_BS)

      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)
      credential.backup_eligible?.should be_true
      credential.backup_state?.should be_true
    end

    it "refuses a challenge that does not match" do
      rp = test_relying_party
      reg = fake_registration(rp)

      expect_raises(WebAuthn::VerificationError, /challenge mismatch/) do
        rp.verify_registration(reg.attestation_object, reg.client_data_json, WebAuthn.generate_challenge)
      end
    end

    # The check that makes a passkey phishing-resistant.
    it "refuses an origin that was not allowed" do
      rp = test_relying_party
      reg = fake_registration(rp, origin: "https://noalyss.example.attacker.test")

      expect_raises(WebAuthn::VerificationError, /is not allowed/) do
        rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)
      end
    end

    it "refuses authenticator data addressed to another relying party" do
      rp = test_relying_party
      reg = fake_registration(rp, rp_id_hash: sha256("other.example".to_slice))

      expect_raises(WebAuthn::VerificationError, /different relying party/) do
        rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)
      end
    end

    it "refuses a ceremony where the user was not present" do
      rp = test_relying_party
      reg = fake_registration(rp, flags: FLAG_UV | FLAG_AT)

      expect_raises(WebAuthn::VerificationError, /was not present/) do
        rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)
      end
    end

    it "refuses an unverified user when verification is required" do
      rp = test_relying_party
      reg = fake_registration(rp, flags: FLAG_UP | FLAG_AT)

      expect_raises(WebAuthn::VerificationError, /user verification was required/) do
        rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)
      end
    end

    it "accepts an unverified user when verification is only preferred" do
      rp = test_relying_party
      reg = fake_registration(rp, flags: FLAG_UP | FLAG_AT)

      credential = rp.verify_registration(
        reg.attestation_object, reg.client_data_json, reg.challenge,
        user_verification: WebAuthn::UserVerification::Preferred
      )
      credential.user_verified?.should be_false
    end

    it "refuses the get ceremony's client data" do
      rp = test_relying_party
      reg = fake_registration(rp)
      wrong = build_client_data(WebAuthn::ClientData::TYPE_GET, reg.challenge, TEST_ORIGIN)

      expect_raises(WebAuthn::VerificationError, /client data type/) do
        rp.verify_registration(reg.attestation_object, wrong, reg.challenge)
      end
    end

    it "refuses an attestation format other than none" do
      rp = test_relying_party
      reg = fake_registration(rp, fmt: "packed")

      expect_raises(WebAuthn::VerificationError, /is not supported/) do
        rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)
      end
    end

    it "refuses fmt none carrying a non-empty statement" do
      rp = test_relying_party
      reg = fake_registration(rp, att_stmt: cbor_map([{cbor_tstr("x"), cbor_int(1)}]))

      expect_raises(WebAuthn::VerificationError, /attStmt is not empty/) do
        rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)
      end
    end

    it "refuses a registration with no attested credential data" do
      rp = test_relying_party
      auth_data = build_authenticator_data(rp.id, flags: FLAG_UP | FLAG_UV)
      challenge = WebAuthn.generate_challenge

      expect_raises(WebAuthn::VerificationError, /no attested credential data/) do
        rp.verify_registration(
          build_attestation_object(auth_data),
          build_client_data(WebAuthn::ClientData::TYPE_CREATE, challenge, TEST_ORIGIN),
          challenge
        )
      end
    end

    # A credential cannot be backed up without being eligible for it.
    it "refuses a backed-up credential that is not backup eligible" do
      rp = test_relying_party
      reg = fake_registration(rp, flags: FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BS)

      expect_raises(WebAuthn::VerificationError, /not backup eligible/) do
        rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)
      end
    end
  end

  describe "authentication" do
    it "accepts a well-formed assertion" do
      rp = test_relying_party
      reg = fake_registration(rp)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      assertion = fake_assertion(rp, reg.signing_key, sign_count: 1_u32)
      result = rp.verify_authentication(
        credential, assertion.authenticator_data, assertion.client_data_json,
        assertion.signature, assertion.challenge
      )

      result.credential_id.should eq(credential.id)
      result.sign_count.should eq(1_u32)
      result.user_verified?.should be_true
    end

    it "accepts an RS256 assertion" do
      rp = test_relying_party
      reg = fake_registration(rp, key: Jose::JWK::RSAKey.generate(2048))
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      assertion = fake_assertion(rp, reg.signing_key, sign_count: 1_u32)
      rp.verify_authentication(
        credential, assertion.authenticator_data, assertion.client_data_json,
        assertion.signature, assertion.challenge
      ).sign_count.should eq(1_u32)
    end

    it "refuses a signature that does not cover the data" do
      rp = test_relying_party
      reg = fake_registration(rp)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      assertion = fake_assertion(rp, reg.signing_key, tamper_signature: true)
      expect_raises(WebAuthn::VerificationError, /signature verification failed/) do
        rp.verify_authentication(
          credential, assertion.authenticator_data, assertion.client_data_json,
          assertion.signature, assertion.challenge
        )
      end
    end

    it "refuses a signature from another key" do
      rp = test_relying_party
      reg = fake_registration(rp)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      impostor = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      assertion = fake_assertion(rp, impostor)

      expect_raises(WebAuthn::VerificationError, /signature verification failed/) do
        rp.verify_authentication(
          credential, assertion.authenticator_data, assertion.client_data_json,
          assertion.signature, assertion.challenge
        )
      end
    end

    it "refuses a replayed challenge" do
      rp = test_relying_party
      reg = fake_registration(rp)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      assertion = fake_assertion(rp, reg.signing_key)
      expect_raises(WebAuthn::VerificationError, /challenge mismatch/) do
        rp.verify_authentication(
          credential, assertion.authenticator_data, assertion.client_data_json,
          assertion.signature, WebAuthn.generate_challenge
        )
      end
    end

    it "refuses an assertion for a different credential id" do
      rp = test_relying_party
      reg = fake_registration(rp)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      assertion = fake_assertion(rp, reg.signing_key)
      expect_raises(WebAuthn::VerificationError, /different credential/) do
        rp.verify_authentication(
          credential, assertion.authenticator_data, assertion.client_data_json,
          assertion.signature, assertion.challenge,
          credential_id: Random::Secure.random_bytes(32)
        )
      end
    end

    it "refuses the create ceremony's client data" do
      rp = test_relying_party
      reg = fake_registration(rp)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      challenge = WebAuthn.generate_challenge
      auth_data = build_authenticator_data(rp.id, flags: FLAG_UP | FLAG_UV, sign_count: 1_u32)
      client_data = build_client_data(WebAuthn::ClientData::TYPE_CREATE, challenge, TEST_ORIGIN)
      signed = IO::Memory.new
      signed.write(auth_data)
      signed.write(sha256(client_data))

      expect_raises(WebAuthn::VerificationError, /client data type/) do
        rp.verify_authentication(
          credential, auth_data, client_data,
          authenticator_sign(reg.signing_key, signed.to_slice), challenge
        )
      end
    end

    it "refuses an assertion that smuggles in attested credential data" do
      rp = test_relying_party
      reg = fake_registration(rp)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      challenge = WebAuthn.generate_challenge
      other = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      auth_data = build_authenticator_data(
        rp.id, flags: FLAG_UP | FLAG_UV | FLAG_AT, sign_count: 1_u32,
        credential_id: Random::Secure.random_bytes(16), cose_key: cose_ec2_key(other.public_key)
      )
      client_data = build_client_data(WebAuthn::ClientData::TYPE_GET, challenge, TEST_ORIGIN)
      signed = IO::Memory.new
      signed.write(auth_data)
      signed.write(sha256(client_data))

      expect_raises(WebAuthn::VerificationError, /must not carry attested credential data/) do
        rp.verify_authentication(
          credential, auth_data, client_data,
          authenticator_sign(reg.signing_key, signed.to_slice), challenge
        )
      end
    end
  end

  describe "signature counter" do
    it "accepts a counter that moved forward" do
      rp = test_relying_party
      reg = fake_registration(rp, sign_count: 5_u32)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      assertion = fake_assertion(rp, reg.signing_key, sign_count: 6_u32)
      rp.verify_authentication(
        credential, assertion.authenticator_data, assertion.client_data_json,
        assertion.signature, assertion.challenge
      ).sign_count.should eq(6_u32)
    end

    # Apple's authenticators always report zero. Enforcing a strictly
    # increasing counter would lock out every macOS and iOS user.
    it "accepts a counter that stays at zero" do
      rp = test_relying_party
      reg = fake_registration(rp, sign_count: 0_u32)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      assertion = fake_assertion(rp, reg.signing_key, sign_count: 0_u32)
      rp.verify_authentication(
        credential, assertion.authenticator_data, assertion.client_data_json,
        assertion.signature, assertion.challenge
      ).sign_count.should eq(0_u32)
    end

    it "flags a counter that went backwards as a possible clone" do
      rp = test_relying_party
      reg = fake_registration(rp, sign_count: 10_u32)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      assertion = fake_assertion(rp, reg.signing_key, sign_count: 3_u32)
      expect_raises(WebAuthn::ClonedAuthenticatorError, /may have been cloned/) do
        rp.verify_authentication(
          credential, assertion.authenticator_data, assertion.client_data_json,
          assertion.signature, assertion.challenge
        )
      end
    end

    it "flags a repeated counter as a possible clone" do
      rp = test_relying_party
      reg = fake_registration(rp, sign_count: 4_u32)
      credential = rp.verify_registration(reg.attestation_object, reg.client_data_json, reg.challenge)

      assertion = fake_assertion(rp, reg.signing_key, sign_count: 4_u32)
      expect_raises(WebAuthn::ClonedAuthenticatorError) do
        rp.verify_authentication(
          credential, assertion.authenticator_data, assertion.client_data_json,
          assertion.signature, assertion.challenge
        )
      end
    end

    # Distinct from a forgery: the signature was valid, so the response is to
    # warn the user, not to treat it as an attack in progress.
    it "raises a distinguishable error for a suspected clone" do
      WebAuthn::ClonedAuthenticatorError.new("x").should be_a(WebAuthn::VerificationError)
    end
  end

  describe "challenges" do
    it "generates 32 unpredictable bytes by default" do
      a = WebAuthn.generate_challenge
      b = WebAuthn.generate_challenge
      a.size.should eq(32)
      a.should_not eq(b)
    end

    it "refuses a challenge too short to be worth generating" do
      expect_raises(ArgumentError, /below 16 bytes/) do
        WebAuthn.generate_challenge(8)
      end
    end
  end
end
