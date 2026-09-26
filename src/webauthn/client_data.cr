require "base64"
require "json"
require "openssl"
require "crypto/subtle"
require "./errors"

module WebAuthn
  # The client data (WebAuthn §5.8.1), as the browser assembled it.
  #
  # This is the half of a ceremony the *browser* vouches for: which ceremony
  # ran, against which challenge, and — the part that defeats phishing — for
  # which origin. The authenticator never sees it in the clear; it signs a
  # hash of it, which is what binds the signature to this origin and this
  # challenge.
  class ClientData
    class MalformedError < WebAuthn::Error
    end

    TYPE_CREATE = "webauthn.create"
    TYPE_GET    = "webauthn.get"

    getter raw : Bytes
    getter type : String
    getter challenge : String
    getter origin : String
    getter? cross_origin : Bool

    def initialize(@raw : Bytes, @type : String, @challenge : String, @origin : String,
                   @cross_origin : Bool)
    end

    def self.parse(bytes : Bytes) : ClientData
      json = begin
        JSON.parse(String.new(bytes))
      rescue ex : JSON::ParseException
        raise MalformedError.new("client data is not valid JSON: #{ex.message}")
      end

      object = json.as_h? || raise MalformedError.new("client data is not a JSON object")

      ClientData.new(
        bytes.dup,
        string(object, "type"),
        string(object, "challenge"),
        string(object, "origin"),
        object["crossOrigin"]?.try(&.as_bool?) || false
      )
    end

    # SHA-256 of the raw bytes — what the authenticator actually signed over.
    #
    # Computed from the bytes as received, never from a re-serialisation: two
    # JSON encoders do not agree on key order or escaping, and the hash would
    # not match.
    def hash : Bytes
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(@raw)
      digest.final
    end

    def challenge_matches?(expected : Bytes) : Bool
      decoded = begin
        Base64.decode(base64url_to_base64(@challenge))
      rescue
        return false
      end
      Crypto::Subtle.constant_time_compare(decoded, expected)
    end

    private def base64url_to_base64(value : String) : String
      padded = value.tr("-_", "+/")
      remainder = padded.size % 4
      remainder.zero? ? padded : padded + "=" * (4 - remainder)
    end

    private def self.string(object : Hash(String, JSON::Any), key : String) : String
      value = object[key]? || raise MalformedError.new("client data is missing #{key.inspect}")
      value.as_s? || raise MalformedError.new("client data #{key.inspect} is not a string")
    end
  end
end
