require "openssl"
require "crypto/subtle"
require "./errors"
require "./cbor"
require "./cose"
require "./authenticator_data"
require "./client_data"
require "./credential"

module WebAuthn
  # Raised when a ceremony does not verify.
  #
  # Failure is an exception rather than a false return value on purpose: a
  # caller cannot forget to check it, and there is no path where a partly
  # verified ceremony quietly counts as a success.
  class VerificationError < Error
  end

  # Raised when the signature counter suggests the authenticator was cloned.
  #
  # Kept distinct because it warrants a different response: the signature was
  # valid, so this is not a forgery — it is a sign that the credential exists
  # in two places, and the user should be told.
  class ClonedAuthenticatorError < VerificationError
  end

  # Generate a challenge.
  #
  # 32 bytes from the system CSPRNG. The challenge is what makes each ceremony
  # single-use; it must be stored server-side and compared with what comes
  # back, never trusted from the client.
  def self.generate_challenge(size : Int32 = 32) : Bytes
    raise ArgumentError.new("a challenge below 16 bytes is not worth generating") if size < 16
    Random::Secure.random_bytes(size)
  end

  # The relying party — the site credentials are registered against.
  class RelyingParty
    getter id : String
    getter origins : Array(String)
    getter algorithms : Array(Int64)

    # `id` is the WebAuthn RP ID, and it is effectively permanent: change it
    # and every passkey already registered stops being offered. It may be any
    # registrable domain suffix of the origins, so instances served at
    # `a.example.com` and `b.example.com` can share `example.com` and, with
    # it, one key per user across both.
    #
    # `origins` is an exact allowlist — scheme, host and port. Nothing is
    # inferred from `id`: an origin the relying party did not name is not one
    # it accepts.
    def initialize(@id : String, origins : Array(String),
                   @algorithms : Array(Int64) = COSE::DEFAULT_ALGORITHMS)
      raise ArgumentError.new("a relying party needs an id") if @id.empty?
      raise ArgumentError.new("a relying party needs at least one origin") if origins.empty?
      raise ArgumentError.new("a relying party needs at least one algorithm") if @algorithms.empty?
      @origins = origins.dup
    end

    # SHA-256 of the RP ID, as it appears in authenticator data.
    def id_hash : Bytes
      digest = OpenSSL::Digest.new("SHA256")
      digest.update(@id.to_slice)
      digest.final
    end

    # Verify a registration (WebAuthn §7.1) and return the credential to store.
    def verify_registration(attestation_object : Bytes, client_data_json : Bytes,
                            challenge : Bytes,
                            user_verification : UserVerification = UserVerification::Required) : Credential
      # Verified for its own sake: it raises on any mismatch, and registration
      # has no later use for the parsed value.
      parse_client_data(client_data_json, ClientData::TYPE_CREATE, challenge)

      attestation = begin
        CBOR.decode_map(attestation_object)
      rescue ex : CBOR::Error
        raise VerificationError.new("attestation object is not valid CBOR: #{ex.message}")
      end

      verify_attestation_format(attestation)

      auth_data_bytes = attestation["authData"]?.try(&.as_bytes?) ||
                        raise VerificationError.new("attestation object has no authData")

      authenticator_data = parse_authenticator_data(auth_data_bytes)
      verify_authenticator_data(authenticator_data, user_verification)

      unless authenticator_data.attested_credential_data?
        raise VerificationError.new("registration carries no attested credential data")
      end

      credential_id = authenticator_data.credential_id ||
                      raise VerificationError.new("registration carries no credential id")
      public_key = authenticator_data.credential_public_key ||
                   raise VerificationError.new("registration carries no credential public key")

      Credential.new(
        id: credential_id,
        public_key: public_key,
        sign_count: authenticator_data.sign_count,
        aaguid: authenticator_data.aaguid || Bytes.new(AuthenticatorData::AAGUID_SIZE),
        backup_eligible: authenticator_data.backup_eligible?,
        backup_state: authenticator_data.backup_state?,
        user_verified: authenticator_data.user_verified?
      )
    end

    # Verify an authentication (WebAuthn §7.2).
    #
    # `credential` is the stored record. On success the caller must persist
    # the returned `sign_count`: skipping that turns the cloned-authenticator
    # check into a no-op.
    def verify_authentication(credential : Credential, authenticator_data : Bytes,
                              client_data_json : Bytes, signature : Bytes, challenge : Bytes,
                              user_verification : UserVerification = UserVerification::Required,
                              credential_id : Bytes? = nil) : Assertion
      if credential_id && !Crypto::Subtle.constant_time_compare(credential_id, credential.id)
        raise VerificationError.new("the assertion is for a different credential")
      end

      client_data = parse_client_data(client_data_json, ClientData::TYPE_GET, challenge)
      parsed = parse_authenticator_data(authenticator_data)
      verify_authenticator_data(parsed, user_verification)

      # An assertion has no business carrying a new credential.
      if parsed.attested_credential_data?
        raise VerificationError.new("an assertion must not carry attested credential data")
      end

      # The authenticator signs authData concatenated with the hash of the
      # client data — which is what ties the signature to this origin and this
      # challenge rather than some other site's.
      signed = Bytes.new(parsed.raw.size + 32)
      parsed.raw.copy_to(signed[0, parsed.raw.size])
      client_data.hash.copy_to(signed[parsed.raw.size, 32])

      unless credential.public_key.verify(signed, signature)
        raise VerificationError.new("signature verification failed")
      end

      verify_sign_count(credential.sign_count, parsed.sign_count)
      verify_backup_consistency(credential, parsed)

      Assertion.new(
        credential_id: credential.id,
        sign_count: parsed.sign_count,
        user_verified: parsed.user_verified?,
        backup_state: parsed.backup_state?
      )
    end

    private def parse_client_data(bytes : Bytes, expected_type : String, challenge : Bytes) : ClientData
      client_data = begin
        ClientData.parse(bytes)
      rescue ex : ClientData::MalformedError
        raise VerificationError.new(ex.message)
      end

      unless client_data.type == expected_type
        raise VerificationError.new(
          "client data type is #{client_data.type.inspect}, expected #{expected_type.inspect}"
        )
      end

      unless client_data.challenge_matches?(challenge)
        raise VerificationError.new("challenge mismatch")
      end

      # Exact match against the allowlist. This is the check that makes a
      # passkey phishing-resistant: a signature made for another origin will
      # not pass here, however convincing the site that collected it looked.
      unless @origins.includes?(client_data.origin)
        raise VerificationError.new("origin #{client_data.origin.inspect} is not allowed")
      end

      client_data
    end

    private def parse_authenticator_data(bytes : Bytes) : AuthenticatorData
      AuthenticatorData.parse(bytes, @algorithms)
    rescue ex : AuthenticatorData::MalformedError | CBOR::Error | COSE::Error
      raise VerificationError.new("authenticator data rejected: #{ex.message}")
    end

    private def verify_authenticator_data(data : AuthenticatorData,
                                          user_verification : UserVerification) : Nil
      unless Crypto::Subtle.constant_time_compare(data.rp_id_hash, id_hash)
        raise VerificationError.new("authenticator data is for a different relying party")
      end

      raise VerificationError.new("the user was not present") unless data.user_present?

      if user_verification.required? && !data.user_verified?
        raise VerificationError.new("user verification was required but the authenticator did not perform it")
      end

      # A credential cannot be backed up without being eligible for backup.
      if data.backup_state? && !data.backup_eligible?
        raise VerificationError.new("authenticator reports a backed-up credential that is not backup eligible")
      end
    end

    # Only `none` is accepted.
    #
    # The other formats prove which make and model of authenticator was used.
    # That is rarely what a relying party needs, it ties a user's hardware to
    # their account, and getting it wrong is worse than not doing it.
    private def verify_attestation_format(attestation : Hash(CBOR::Key, CBOR::Any)) : Nil
      fmt = attestation["fmt"]?.try(&.as_s?) ||
            raise VerificationError.new("attestation object has no fmt")

      unless fmt == "none"
        raise VerificationError.new(
          "attestation format #{fmt.inspect} is not supported; request attestation: \"none\""
        )
      end

      statement = attestation["attStmt"]?.try(&.as_h?)
      if statement && !statement.empty?
        raise VerificationError.new("attestation format is \"none\" but attStmt is not empty")
      end
    end

    # WebAuthn §7.2, step 21.
    #
    # Many authenticators — every Apple one, notably — always report zero.
    # Treating a zero counter as an error would lock out every macOS and iOS
    # user, so the check only applies once a non-zero counter has been seen.
    private def verify_sign_count(stored : UInt32, received : UInt32) : Nil
      return if stored.zero? && received.zero?
      return if received > stored

      raise ClonedAuthenticatorError.new(
        "signature counter went from #{stored} to #{received}; the credential may have been cloned"
      )
    end

    private def verify_backup_consistency(credential : Credential, data : AuthenticatorData) : Nil
      # Backup eligibility is a property of the credential, fixed when it was
      # created. Backup *state* may change — a key syncing for the first time
      # is normal — but eligibility flipping is not.
      if credential.backup_eligible? != data.backup_eligible?
        raise VerificationError.new(
          "backup eligibility changed since registration, which a credential cannot do"
        )
      end
    end
  end
end
