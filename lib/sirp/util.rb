module SIRP
  # Convert a hex string to an a array of Integer bytes by first converting
  # the String to hex, and then converting that hex to an Array of Integer bytes.
  #
  # @param str [String] a string to convert
  # @return [Array<Integer>] an Array of Integer bytes
  def hex_to_bytes(str)
    [str].pack('H*').unpack('C*')
  end
  typesig :hex_to_bytes, [String] => Array

  # Convert a number to a downcased hex string, prepending '0' to the
  # hex string if the hex conversion resulted in an odd length string.
  #
  # @param num [Integer] a number to convert to a hex string
  # @return [String] a hex string
  def num_to_hex(num)
    hex_str = num.to_s(16)
    even_hex_str = hex_str.length.odd? ? '0' + hex_str : hex_str
    even_hex_str.downcase
  end
  typesig :num_to_hex, [Integer] => String

  # Constant time string comparison.
  # Extracted from Rack::Utils
  # https://github.com/rack/rack/blob/master/lib/rack/utils.rb
  #
  # NOTE: the values compared should be of fixed length, such as strings
  # that have already been processed by HMAC. This should not be used
  # on variable length plaintext strings because it could leak length info
  # via timing attacks. The user provided value should always be passed
  # in as the second parameter so as not to leak info about the secret.
  #
  # @param a [String] the private value
  # @param b [String] the user provided value
  # @return [true, false] whether the strings match or not
  def secure_compare(a, b)
    # Do all comparisons on equal length hashes of the inputs
    a = Digest::SHA256.hexdigest(a)
    b = Digest::SHA256.hexdigest(b)
    return false unless a.bytesize == b.bytesize


    l = a.unpack('C*')

    r, i = 0, -1
    b.each_byte { |v| r |= v ^ l[i+=1] }
    r == 0
  end
  typesig :secure_compare, [String, String] => Boolean
end
