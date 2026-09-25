require "./spec_helper"

describe WebAuthn::COSE do
  describe "EC2 keys" do
    it "decodes a P-256 key and verifies a signature made with it" do
      ec = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      key = WebAuthn::COSE.decode_key(cose_ec2_key(ec.public_key))

      key.algorithm.should eq(Jose::JWS::Algorithm::ES256)
      key.cose_algorithm.should eq(WebAuthn::COSE::ALG_ES256)

      data = "authenticator data || client data hash".to_slice
      key.verify(data, authenticator_sign(ec, data)).should be_true
    end

    it "rejects a signature over different data" do
      ec = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      key = WebAuthn::COSE.decode_key(cose_ec2_key(ec.public_key))

      signature = authenticator_sign(ec, "one".to_slice)
      key.verify("two".to_slice, signature).should be_false
    end

    it "rejects a signature from another key" do
      ec = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      impostor = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      key = WebAuthn::COSE.decode_key(cose_ec2_key(ec.public_key))

      data = "payload".to_slice
      key.verify(data, authenticator_sign(impostor, data)).should be_false
    end

    it "refuses a curve that contradicts the algorithm" do
      ec = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      # ES256 with crv = 2 (P-384)
      expect_raises(WebAuthn::COSE::MalformedKeyError, /declares curve 2/) do
        WebAuthn::COSE.decode_key(cose_ec2_key(ec.public_key, crv: 2_i64))
      end
    end

    it "refuses coordinates of the wrong length" do
      ec = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      bad = cbor_map([
        {cbor_int(WebAuthn::COSE::LABEL_KTY), cbor_int(WebAuthn::COSE::KTY_EC2)},
        {cbor_int(WebAuthn::COSE::LABEL_ALG), cbor_int(WebAuthn::COSE::ALG_ES256)},
        {cbor_int(WebAuthn::COSE::LABEL_EC2_CRV), cbor_int(1)},
        {cbor_int(WebAuthn::COSE::LABEL_EC2_X), cbor_bstr(ec.x[0, 16])},
        {cbor_int(WebAuthn::COSE::LABEL_EC2_Y), cbor_bstr(ec.y)},
      ])
      expect_raises(WebAuthn::COSE::MalformedKeyError, /rejected/) do
        WebAuthn::COSE.decode_key(bad)
      end
    end
  end

  describe "RSA keys" do
    it "decodes an RSA key and verifies a signature made with it" do
      rsa = Jose::JWK::RSAKey.generate(2048)
      key = WebAuthn::COSE.decode_key(cose_rsa_key(rsa.public_key))

      key.algorithm.should eq(Jose::JWS::Algorithm::RS256)

      data = "authenticator data || client data hash".to_slice
      key.verify(data, authenticator_sign(rsa, data)).should be_true
    end

    it "refuses a modulus below 2048 bits" do
      rsa = Jose::JWK::RSAKey.generate(2048)
      short = Jose::JWK::RSAKey.new(rsa.n[0, 64], rsa.e)
      expect_raises(WebAuthn::COSE::MalformedKeyError, /bits/) do
        WebAuthn::COSE.decode_key(cose_rsa_key(short))
      end
    end
  end

  describe "algorithm negotiation" do
    # Accepting an algorithm we never offered would let the caller pick one
    # for us — a downgrade we have no reason to allow.
    it "refuses an algorithm the relying party did not offer" do
      ec = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      expect_raises(WebAuthn::COSE::UnsupportedKeyError, /was not offered/) do
        WebAuthn::COSE.decode_key(cose_ec2_key(ec.public_key), [WebAuthn::COSE::ALG_RS256])
      end
    end

    it "offers ES256 and RS256 by default" do
      # ES256 covers Apple and Android, RS256 covers Windows Hello.
      WebAuthn::COSE::DEFAULT_ALGORITHMS.should eq(
        [WebAuthn::COSE::ALG_ES256, WebAuthn::COSE::ALG_RS256]
      )
    end

    it "accepts RS256 when it is offered" do
      rsa = Jose::JWK::RSAKey.generate(2048)
      key = WebAuthn::COSE.decode_key(cose_rsa_key(rsa.public_key), [WebAuthn::COSE::ALG_RS256])
      key.algorithm.should eq(Jose::JWS::Algorithm::RS256)
    end
  end

  describe "malformed input" do
    it "refuses a key that is not a map" do
      expect_raises(WebAuthn::COSE::MalformedKeyError, /not a CBOR map/) do
        WebAuthn::COSE.decode_key(Bytes[0x01])
      end
    end

    it "refuses an unknown key type" do
      bad = cbor_map([
        {cbor_int(WebAuthn::COSE::LABEL_KTY), cbor_int(9)},
        {cbor_int(WebAuthn::COSE::LABEL_ALG), cbor_int(WebAuthn::COSE::ALG_ES256)},
      ])
      expect_raises(WebAuthn::COSE::UnsupportedKeyError, /key type 9/) do
        WebAuthn::COSE.decode_key(bad)
      end
    end

    it "refuses a key missing its algorithm" do
      bad = cbor_map([{cbor_int(WebAuthn::COSE::LABEL_KTY), cbor_int(WebAuthn::COSE::KTY_EC2)}])
      expect_raises(WebAuthn::COSE::MalformedKeyError, /missing alg/) do
        WebAuthn::COSE.decode_key(bad)
      end
    end

    it "refuses an EC2 key whose type and algorithm disagree" do
      rsa = Jose::JWK::RSAKey.generate(2048)
      bad = cbor_map([
        {cbor_int(WebAuthn::COSE::LABEL_KTY), cbor_int(WebAuthn::COSE::KTY_EC2)},
        {cbor_int(WebAuthn::COSE::LABEL_ALG), cbor_int(WebAuthn::COSE::ALG_RS256)},
        {cbor_int(WebAuthn::COSE::LABEL_RSA_N), cbor_bstr(rsa.n)},
      ])
      expect_raises(WebAuthn::COSE::UnsupportedKeyError, /not an EC2 algorithm/) do
        WebAuthn::COSE.decode_key(bad)
      end
    end

    it "refuses a coordinate that is not a byte string" do
      bad = cbor_map([
        {cbor_int(WebAuthn::COSE::LABEL_KTY), cbor_int(WebAuthn::COSE::KTY_EC2)},
        {cbor_int(WebAuthn::COSE::LABEL_ALG), cbor_int(WebAuthn::COSE::ALG_ES256)},
        {cbor_int(WebAuthn::COSE::LABEL_EC2_CRV), cbor_int(1)},
        {cbor_int(WebAuthn::COSE::LABEL_EC2_X), cbor_int(42)},
        {cbor_int(WebAuthn::COSE::LABEL_EC2_Y), cbor_int(43)},
      ])
      expect_raises(WebAuthn::COSE::MalformedKeyError, /x is not a byte string/) do
        WebAuthn::COSE.decode_key(bad)
      end
    end
  end
end
