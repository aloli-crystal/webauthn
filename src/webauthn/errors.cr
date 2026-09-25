module WebAuthn
  # Base class for every error this shard raises.
  #
  # Ceremony failures are errors, not return values: a registration or an
  # authentication either verified or it did not, and a caller must not be
  # able to ignore the difference by forgetting to check a boolean.
  class Error < Exception
  end
end
