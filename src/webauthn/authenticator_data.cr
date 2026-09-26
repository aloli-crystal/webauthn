require "./errors"
require "./cbor"
require "./cose"

module WebAuthn
  # The authenticator data structure (WebAuthn §6.1).
  #
  # A flat binary record the authenticator signs over, and the only part of a
  # ceremony whose integrity the signature actually covers:
  #
  #   rpIdHash   32 bytes
  #   flags       1 byte
  #   signCount   4 bytes, big-endian
  #   attestedCredentialData   only when the AT flag is set
  #   extensions               only when the ED flag is set
  class AuthenticatorData
    class MalformedError < WebAuthn::Error
    end

    RP_ID_HASH_SIZE = 32
    AAGUID_SIZE     = 16
    FIXED_SIZE      = RP_ID_HASH_SIZE + 1 + 4

    # Flag bits (WebAuthn §6.1).
    FLAG_USER_PRESENT             = 0x01_u8
    FLAG_USER_VERIFIED            = 0x04_u8
    FLAG_BACKUP_ELIGIBLE          = 0x08_u8
    FLAG_BACKUP_STATE             = 0x10_u8
    FLAG_ATTESTED_CREDENTIAL_DATA = 0x40_u8
    FLAG_EXTENSION_DATA           = 0x80_u8

    getter raw : Bytes
    getter rp_id_hash : Bytes
    getter flags : UInt8
    getter sign_count : UInt32
    getter aaguid : Bytes?
    getter credential_id : Bytes?
    getter credential_public_key : COSE::Key?

    def initialize(@raw : Bytes, @rp_id_hash : Bytes, @flags : UInt8, @sign_count : UInt32,
                   @aaguid : Bytes? = nil, @credential_id : Bytes? = nil,
                   @credential_public_key : COSE::Key? = nil)
    end

    # The user was present — a physical gesture reached the authenticator.
    def user_present? : Bool
      flag?(FLAG_USER_PRESENT)
    end

    # The authenticator verified *who* the user is: biometrics, PIN, or the
    # machine's session password. This is the bit that makes a passkey
    # multi-factor on its own.
    def user_verified? : Bool
      flag?(FLAG_USER_VERIFIED)
    end

    # The credential may be backed up — synced to the user's other devices.
    def backup_eligible? : Bool
      flag?(FLAG_BACKUP_ELIGIBLE)
    end

    # The credential is currently backed up.
    def backup_state? : Bool
      flag?(FLAG_BACKUP_STATE)
    end

    def attested_credential_data? : Bool
      flag?(FLAG_ATTESTED_CREDENTIAL_DATA)
    end

    def extension_data? : Bool
      flag?(FLAG_EXTENSION_DATA)
    end

    private def flag?(bit : UInt8) : Bool
      (@flags & bit) != 0
    end

    # Parse authenticator data.
    #
    # `allowed_algorithms` bounds the COSE key that may appear in attested
    # credential data; it is unused when the AT flag is clear.
    def self.parse(bytes : Bytes,
                   allowed_algorithms : Enumerable(Int64) = COSE::DEFAULT_ALGORITHMS) : AuthenticatorData
      if bytes.size < FIXED_SIZE
        raise MalformedError.new("authenticator data is #{bytes.size} bytes, needs at least #{FIXED_SIZE}")
      end

      rp_id_hash = bytes[0, RP_ID_HASH_SIZE].dup
      flags = bytes[RP_ID_HASH_SIZE]
      sign_count = read_u32(bytes, RP_ID_HASH_SIZE + 1)

      data = new(bytes.dup, rp_id_hash, flags, sign_count)
      offset = FIXED_SIZE

      if data.attested_credential_data?
        aaguid, credential_id, public_key, offset = parse_attested_credential_data(
          bytes, offset, allowed_algorithms
        )
        data = new(bytes.dup, rp_id_hash, flags, sign_count, aaguid, credential_id, public_key)
      end

      if data.extension_data?
        # Extensions are not interpreted, but they must parse: trailing bytes
        # that no one accounts for are a sign the record is not what we think.
        offset += CBOR.decode_first(bytes[offset, bytes.size - offset])[:size]
      end

      unless offset == bytes.size
        raise MalformedError.new("#{bytes.size - offset} unaccounted byte(s) after authenticator data")
      end

      data
    end

    private def self.parse_attested_credential_data(bytes : Bytes, offset : Int32,
                                                    allowed_algorithms : Enumerable(Int64))
      unless bytes.size >= offset + AAGUID_SIZE + 2
        raise MalformedError.new("truncated attested credential data")
      end

      aaguid = bytes[offset, AAGUID_SIZE].dup
      offset += AAGUID_SIZE

      credential_id_length = (bytes[offset].to_u32 << 8) | bytes[offset + 1].to_u32
      offset += 2

      # WebAuthn §6.5.1 caps credential IDs at 1023 bytes.
      if credential_id_length > 1023
        raise MalformedError.new("credential id length #{credential_id_length} exceeds the 1023-byte limit")
      end
      unless bytes.size >= offset + credential_id_length
        raise MalformedError.new("credential id runs past the end of the authenticator data")
      end

      credential_id = bytes[offset, credential_id_length].dup
      offset += credential_id_length

      # The COSE key is variable-length and the record does not say how long
      # it is: the decoder reports what it consumed so the next field can be
      # found.
      remaining = bytes[offset, bytes.size - offset]
      raise MalformedError.new("no credential public key present") if remaining.empty?

      decoded = CBOR.decode_first(remaining)
      public_key = COSE.decode_key(decoded[:value], allowed_algorithms)
      offset += decoded[:size]

      {aaguid, credential_id, public_key, offset}
    end

    private def self.read_u32(bytes : Bytes, offset : Int32) : UInt32
      (bytes[offset].to_u32 << 24) |
        (bytes[offset + 1].to_u32 << 16) |
        (bytes[offset + 2].to_u32 << 8) |
        bytes[offset + 3].to_u32
    end
  end
end
