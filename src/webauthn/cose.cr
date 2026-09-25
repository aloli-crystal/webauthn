require "jose"
require "./cbor"

module WebAuthn
  # COSE keys (RFC 8152 §7), as carried inside WebAuthn credential data.
  #
  # An authenticator hands over its public key as a CBOR map labelled by
  # integers. This turns that map into a `jose` key, which knows how to verify
  # a signature with it.
  module COSE
    class Error < WebAuthn::Error
    end

    class UnsupportedKeyError < Error
    end

    class MalformedKeyError < Error
    end

    # Common COSE key parameters (RFC 8152 §7.1).
    LABEL_KTY = 1_i64
    LABEL_ALG = 3_i64

    # Type-specific parameters (RFC 8152 §13). The labels collide across key
    # types on purpose: -1 is the curve for EC2 and the modulus for RSA.
    LABEL_EC2_CRV = -1_i64
    LABEL_EC2_X   = -2_i64
    LABEL_EC2_Y   = -3_i64
    LABEL_RSA_N   = -1_i64
    LABEL_RSA_E   = -2_i64

    KTY_EC2 = 2_i64
    KTY_RSA = 3_i64

    # COSE algorithm identifiers (IANA COSE Algorithms registry).
    ALG_ES256 =   -7_i64
    ALG_ES384 =  -35_i64
    ALG_ES512 =  -36_i64
    ALG_RS256 = -257_i64
    ALG_RS384 = -258_i64
    ALG_RS512 = -259_i64

    # Algorithms a relying party should offer, best first.
    #
    # ES256 covers Apple and Android platform authenticators and most security
    # keys; RS256 covers Windows Hello, which commonly enrols with it. Offering
    # only one of the two shuts out an entire population of users.
    DEFAULT_ALGORITHMS = [ALG_ES256, ALG_RS256]

    # A credential public key, paired with the algorithm it signs with.
    struct Key
      getter algorithm : Jose::JWS::Algorithm
      getter cose_algorithm : Int64
      getter jose_key : Jose::JWK::ECKey | Jose::JWK::RSAKey

      def initialize(@algorithm : Jose::JWS::Algorithm, @cose_algorithm : Int64,
                     @jose_key : Jose::JWK::ECKey | Jose::JWK::RSAKey)
      end

      # Verify a signature the authenticator produced.
      #
      # ECDSA signatures arrive ASN.1 DER-encoded, which is what `jose` wants
      # — CTAP authenticators emit DER, not the fixed-width `r || s` pair that
      # JWS itself uses.
      def verify(data : Bytes, signature : Bytes) : Bool
        Jose::JWS.verify_signature(data, signature, @algorithm, @jose_key)
      end
    end

    # Decode a COSE_Key from its CBOR encoding.
    #
    # `allowed_algorithms` is the list the relying party announced at
    # registration. An authenticator that answers with something else is
    # refused: accepting an algorithm we never offered would let a caller
    # downgrade us to whatever it likes.
    def self.decode_key(bytes : Bytes, allowed_algorithms : Enumerable(Int64) = DEFAULT_ALGORITHMS) : Key
      decode_key(CBOR.decode(bytes), allowed_algorithms)
    end

    def self.decode_key(value : CBOR::Any, allowed_algorithms : Enumerable(Int64) = DEFAULT_ALGORITHMS) : Key
      map = value.as_h? || raise MalformedKeyError.new("COSE key is not a CBOR map")

      kty = integer(map, LABEL_KTY, "kty")
      cose_alg = integer(map, LABEL_ALG, "alg")

      unless allowed_algorithms.includes?(cose_alg)
        raise UnsupportedKeyError.new(
          "COSE algorithm #{cose_alg} was not offered by the relying party " \
          "(offered: #{allowed_algorithms.join(", ")})"
        )
      end

      case kty
      when KTY_EC2
        decode_ec2(map, cose_alg)
      when KTY_RSA
        decode_rsa(map, cose_alg)
      else
        raise UnsupportedKeyError.new("unsupported COSE key type #{kty}")
      end
    end

    private def self.decode_ec2(map : Hash(CBOR::Key, CBOR::Any), cose_alg : Int64) : Key
      algorithm, curve = case cose_alg
                         when ALG_ES256 then {Jose::JWS::Algorithm::ES256, Jose::JWK::Curve::P256}
                         when ALG_ES384 then {Jose::JWS::Algorithm::ES384, Jose::JWK::Curve::P384}
                         when ALG_ES512 then {Jose::JWS::Algorithm::ES512, Jose::JWK::Curve::P521}
                         else
                           raise UnsupportedKeyError.new("COSE algorithm #{cose_alg} is not an EC2 algorithm")
                         end

      crv = integer(map, LABEL_EC2_CRV, "crv")
      expected_crv = case curve
                     in Jose::JWK::Curve::P256 then 1_i64
                     in Jose::JWK::Curve::P384 then 2_i64
                     in Jose::JWK::Curve::P521 then 3_i64
                     end
      unless crv == expected_crv
        raise MalformedKeyError.new(
          "COSE key declares curve #{crv} but algorithm #{cose_alg} requires #{expected_crv}"
        )
      end

      x = byte_string(map, LABEL_EC2_X, "x")
      y = byte_string(map, LABEL_EC2_Y, "y")

      begin
        Key.new(algorithm, cose_alg, Jose::JWK::ECKey.new(curve, x, y))
      rescue ex : Jose::JWK::InvalidKeyError
        raise MalformedKeyError.new("COSE EC2 key rejected: #{ex.message}")
      end
    end

    private def self.decode_rsa(map : Hash(CBOR::Key, CBOR::Any), cose_alg : Int64) : Key
      algorithm = case cose_alg
                  when ALG_RS256 then Jose::JWS::Algorithm::RS256
                  when ALG_RS384 then Jose::JWS::Algorithm::RS384
                  when ALG_RS512 then Jose::JWS::Algorithm::RS512
                  else
                    raise UnsupportedKeyError.new("COSE algorithm #{cose_alg} is not an RSA algorithm")
                  end

      n = byte_string(map, LABEL_RSA_N, "n")
      e = byte_string(map, LABEL_RSA_E, "e")

      key = begin
        Jose::JWK::RSAKey.new(n, e)
      rescue ex : Jose::JWK::InvalidKeyError
        raise MalformedKeyError.new("COSE RSA key rejected: #{ex.message}")
      end

      if key.modulus_bits < 2048
        raise MalformedKeyError.new("COSE RSA key is only #{key.modulus_bits} bits")
      end

      Key.new(algorithm, cose_alg, key)
    end

    private def self.integer(map : Hash(CBOR::Key, CBOR::Any), label : Int64, name : String) : Int64
      entry = map[label]? || raise MalformedKeyError.new("COSE key is missing #{name} (label #{label})")
      entry.as_i? || raise MalformedKeyError.new("COSE key #{name} is not an integer")
    end

    private def self.byte_string(map : Hash(CBOR::Key, CBOR::Any), label : Int64, name : String) : Bytes
      entry = map[label]? || raise MalformedKeyError.new("COSE key is missing #{name} (label #{label})")
      bytes = entry.as_bytes? || raise MalformedKeyError.new("COSE key #{name} is not a byte string")
      raise MalformedKeyError.new("COSE key #{name} is empty") if bytes.empty?
      bytes
    end
  end
end
