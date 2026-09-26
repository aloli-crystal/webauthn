require "./cose"

module WebAuthn
  # How thorough the authenticator had to be about *who* the user is.
  enum UserVerification
    # The UV flag must be set. What a passkey used as a single factor needs:
    # without it, possession of the device is all that was proved.
    Required
    # Accept either, and record what happened.
    Preferred
    # Do not require it.
    Discouraged
  end

  # A registered credential — what a relying party stores, and all it stores.
  #
  # There is no secret here. `public_key` verifies signatures and cannot
  # produce them, so a stolen credential table yields nothing an attacker can
  # authenticate with.
  struct Credential
    getter id : Bytes
    getter public_key : COSE::Key
    getter sign_count : UInt32
    getter aaguid : Bytes
    # Whether the credential may sync to the user's other devices. Worth
    # recording: a device-bound credential dies with its device, and the
    # recovery story differs.
    getter? backup_eligible : Bool
    getter? backup_state : Bool
    getter? user_verified : Bool

    def initialize(@id : Bytes, @public_key : COSE::Key, @sign_count : UInt32,
                   @aaguid : Bytes, @backup_eligible : Bool, @backup_state : Bool,
                   @user_verified : Bool)
    end
  end

  # The outcome of a successful authentication.
  struct Assertion
    getter credential_id : Bytes
    getter sign_count : UInt32
    getter? user_verified : Bool
    getter? backup_state : Bool

    def initialize(@credential_id : Bytes, @sign_count : UInt32, @user_verified : Bool,
                   @backup_state : Bool)
    end
  end
end
