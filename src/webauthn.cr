require "jose"

require "./webauthn/version"
require "./webauthn/errors"
require "./webauthn/cbor"
require "./webauthn/cose"

# WebAuthn (W3C Web Authentication, Level 3) for the relying party — the
# server side.
#
# A passkey leaves no shared secret on the server: the private key is held by
# the user's device and unlocked by it, and all the server ever stores is a
# public key. A leak of the credential table yields nothing usable, and a
# signature is bound to the origin it was made for, so it cannot be replayed
# against a phishing site.
module WebAuthn
end
