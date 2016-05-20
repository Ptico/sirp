# SiRP : Secure (interoperable) Remote Password Authentication

[![Gem Version](https://badge.fury.io/rb/sirp.svg)](https://badge.fury.io/rb/sirp)
[![Dependency Status](https://gemnasium.com/badges/github.com/grempe/sirp.svg)](https://gemnasium.com/github.com/grempe/sirp)
[![Build Status](https://travis-ci.org/grempe/sirp.svg?branch=master)](https://travis-ci.org/grempe/sirp)
[![Coverage Status](https://coveralls.io/repos/github/grempe/sirp/badge.svg?branch=master)](https://coveralls.io/github/grempe/sirp?branch=master)
[![Code Climate](https://codeclimate.com/github/grempe/sirp/badges/gpa.svg)](https://codeclimate.com/github/grempe/sirp)
[![Inline docs](http://inch-ci.org/github/grempe/sirp.svg?branch=master)](http://inch-ci.org/github/grempe/sirp)

Ruby Docs : [http://www.rubydoc.info/gems/sirp](http://www.rubydoc.info/gems/sirp)

This is a pure Ruby implementation of the
[Secure Remote Password](http://srp.stanford.edu/) protocol (SRP-6a),
which is a 'zero-knowledge' mutual authentication system.

SRP is an protocol that allows for mutual authentication of a client and
server over an insecure network connection without revealing the password to the
server or an evesdropper. If the client lacks the user's password, or the server
lacks the proper verification key, the authentication will fail. This approach
is much more secure than the vast majority of authentication systems in common use
since the password is never sent over the wire. The password is impossible to
intercept, or to be revealed in a server breach, unless the verifier can be
reversed. Since the verifier is derived from the password + salt through
cryptographic one-way hash functions and Modular Exponentiation. Attacking the
verifier to retrieve a password would be of similar difficulty
as deriving a private encryption key from its public key. Extremely difficult, if
not impossible.

Unlike other common challenge-response authentication protocols, such as
Kerberos and SSL, SRP does not rely on an external infrastructure of trusted
key servers or complex certificate management.

At the end of the authentication process both the client and the server will have
negotiated a shared strong encryption key suitable for encrypted session
communications. This key is negotiated through a modified Diffie-Hellman
key exchange and the key is never sent over the wire.

SiRP is designed to be interoperable with a Ruby client and server, or
with Ruby on the server side, and the [JSRP](https://github.com/alax/jsrp)
Javascript client running in a browser.

## Live Demo

You can try out an interactive demo at
[https://sirp-demo.herokuapp.com/index.html](https://sirp-demo.herokuapp.com/index.html).

[Demo Source Code @ grempe/sirp-demo](https://github.com/grempe/sirp-demo)

## Documentation

There is pretty extensive inline documentation. You can view the latest
API docs at [http://www.rubydoc.info/gems/sirp](http://www.rubydoc.info/gems/sirp)

You can check my documentation quality score at
[http://inch-ci.org/github/grempe/sirp](http://inch-ci.org/github/grempe/sirp?branch=master)

## Supported Platforms

SiRP is continuously integration tested on the following Ruby VMs:

* MRI 2.1
* MRI 2.2
* MRI 2.3

Ruby versions < 2.1 are not supported.

## Installation

Add this line to your application's `Gemfile`:

```ruby
gem 'sirp', '~> 2.0'
```

And then execute:
```sh
$ bundle
```

Or install it yourself as:

```sh
$ gem install sirp
```

### Installation Security : Signed Ruby Gem

The SiRP gem is cryptographically signed. To be sure the gem you install hasn’t
been tampered with you can install it using the following method:

Add my public key (if you haven’t already) as a trusted certificate

```
# Caveat: Gem certificates are trusted globally, such that adding a
# cert.pem for one gem automatically trusts all gems signed by that cert.
gem cert --add <(curl -Ls https://raw.github.com/grempe/sirp/master/certs/gem-public_cert_grempe.pem)
```

To install, it is possible to specify either `HighSecurity` or `MediumSecurity`
mode. Since the `sirp` gem depends on one or more gems that are not cryptographically
signed you will likely need to use `MediumSecurity`. You should receive a warning
if any signed gem does not match its signature.

```
# All dependent gems must be signed and verified.
gem install sirp -P HighSecurity
```

```
# All signed dependent gems must be verified.
gem install sirp -P MediumSecurity
```

```
# Same as above, except Bundler only recognizes
# the long --trust-policy flag, not the short -P
bundle --trust-policy MediumSecurity
```

You can [learn more about security and signed Ruby Gems](http://guides.rubygems.org/security/).

### Installation Security : Signed Git Commits

Most, if not all, of the commits and tags to the repository for this code are
signed with my PGP/GPG code signing key. I have uploaded my code signing public
keys to GitHub and you can now verify those signatures with the GitHub UI.
See [this list of commits](https://github.com/grempe/sirp/commits/master)
and look for the `Verified` tag next to each commit. You can click on that tag
for additional information.

You can also clone the repository and verify the signatures locally using your
own GnuPG installation. You can find my certificates and read about how to conduct
this verification at [https://www.rempe.us/keys/](https://www.rempe.us/keys/).

## Compatibility

This implementation has been tested for compatibility with the following SRP-6a
compliant third-party libraries:

[grempe/jsrp (JavaScript)](https://github.com/grempe/jsrp)

## SRP-6a Protocol Design

Extracted from [http://srp.stanford.edu/design.html](http://srp.stanford.edu/design.html)

```
SRP is the newest addition to a new class of strong authentication protocols
that resist all the well-known passive and active attacks over the network.
SRP borrows some elements from other key-exchange and identification protcols
and adds some subtle modifications and refinements. The result is a protocol
that preserves the strength and efficiency of the EKE family protocols while
fixing some of their shortcomings.

The following is a description of SRP-6 and 6a, the latest versions of SRP:

  N    A large safe prime (N = 2q+1, where q is prime)
       All arithmetic is done modulo N.
  g    A generator modulo N
  k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  s    User's salt
  I    Username
  p    Cleartext Password
  H()  One-way hash function
  ^    (Modular) Exponentiation
  u    Random scrambling parameter
  a,b  Secret ephemeral values
  A,B  Public ephemeral values
  x    Private key (derived from p and s)
  v    Password verifier

The host stores passwords using the following formula:

  x = H(s, p)               (s is chosen randomly)
  v = g^x                   (computes password verifier)

The host then keeps {I, s, v} in its password database. The authentication
protocol itself goes as follows:

User -> Host:  I, A = g^a                  (identifies self, a = random number)
Host -> User:  s, B = kv + g^b             (sends salt, b = random number)

        Both:  u = H(A, B)

        User:  x = H(s, p)                 (user enters password)
        User:  S = (B - kg^x) ^ (a + ux)   (computes session key)
        User:  K = H(S)

        Host:  S = (Av^u) ^ b              (computes session key)
        Host:  K = H(S)

Now the two parties have a shared, strong session key K. To complete
authentication, they need to prove to each other that their keys match.
One possible way:

User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
Host -> User:  H(A, M, K)

The two parties also employ the following safeguards:

* The user will abort if he receives B == 0 (mod N) or u == 0.
* The host will abort if it detects that A == 0 (mod N).
* The user must show his proof of K first. If the server detects that the
user's proof is incorrect, it must abort without showing its own proof of K.
```

### Implementation Decisions

The interoperability of different implementations of SRP is elusive. The spec
leaves a number of decisions up to the implementer. The choice of hashing
algorithm (H) is left open, the method of verifying shared keys (H_AMK) is
not clearly specified, and the generation of the Verifier (v) is not considered
very strong by modern standards.

It is also not specified how the client and server should exchange information
over the wire (binary, hex, protobuf, etc).

It is therefore no wonder that most implementations don't work together.

This library has also made its own choices. This implementation provides Ruby
code that makes a choice for strength where possible. This code is suitable for
use as both a Ruby client and Ruby SRP server. There is also a JavaScript
client based on the work of alax/jsrp which has been modified to be compatible.

It is unlikely that any other implementation will just work out of the box. No
support is provided for any other implementations not listed here.

#### Hashing Algorithm

The hashing algorithm used internally is either `SHA1` or `SHA256`. Only group sizes
`1024` and `1536` use `SHA1` for legacy support, and the rest will use `SHA256`.

This matches the choices made in the `jsrp` package.

#### Calculating `x`

The derivation of the private key `x` has been strengthened in this
implementation and makes use of SHA256, HMAC-SHA256, and Scrypt. Scrypt
is a modern memory and CPU hard key derivation function and is used
to protect against the possibility of a brute-force attack on the Verifier.
See the `calc_x` method in `lib/sirp/sirp.rb` for details.

#### Proof of `K`

According to the Wikipaedia page for Secure Remote Password implementations will
often choose different methods to prove that the client and server have both
negotiatied the same keys.

```
Carol → Steve: M1 = H[H(N) XOR H(g) | H(I) | s | A | B | KCarol]. Steve verifies M1.
Steve → Carol: M2 = H(A | M1 | KSteve). Carol verifies M2.
```

and

```
Carol → Steve: M1 = H(A | B | SCarol). Steve verifies M1.
Steve → Carol: M2 = H(A | M1 | SSteve). Carol verifies M2.
```

This implementation makes use of the second method. See `SIRP.calc_H_AMK`.

## Usage Example

In this example the client and server steps are interleaved for demonstration
purposes. See the [grempe/sirp-demo](https://github.com/grempe/sirp-demo)
repository for working sample code and a live demo. The phases of authentication
in this example are delineated by the HTTPS request/response between client and
server. The concept of 'phases' is something noted here for convenience. The
specification makes no mention of phases since it is implementation specific.

This example is useful for showing the ordering and arguments in the public
API and is not intended to be a 'copy & paste' code sample since the
client and server interaction is something left up to the implementer and likely
different in every case.

``` ruby
require 'sirp'

username     = 'user'
password     = 'password'
prime_length = 2048

# ~~~ Phase 0 : User Registration ~~~

# One time only! SRP is a form of TOFU (Trust On First Use) authentication
# where all is predicated on the client being able to register a verifier
# with the server upon initial registration. The server promises in turn to
# keep this verifier secret and never reveal it. If this first interaction
# is compromised then all is lost. If the verifier is revealed then there
# is a theoretical attack on the verifier which could reveal information
# about the password. It is likely cryptographically difficult though.
# It is important that the username and password combination be of
# high entropy.

# The salt and verifier should be persisted server-side, accessible by
# looking up via the username. The server must protect the verifier but
# will return the salt to any party requesting authentication who knows
# the username.

@auth = SIRP::Verifier.new(prime_length).generate_userauth(username, password)
# => {username: '...', verifier: '...', salt: '...'}

# ~~~ Phase 1 : Challenge/Response ~~~

client = SIRP::Client.new(prime_length)
A = client.start_authentication

# HTTPS POST Client => Server: request includes 'username' and  'A'

# Server retrieves user's verifier and salt from the database by
# looking up these values indexed by 'username'. Here simulated
# by using the @auth hash directly.
v    = @auth[:verifier]
salt = @auth[:salt]

# Server generates a challenge for the client and a proof it will require
# in Phase 2 of the auth process. The challenge is given to the client, the
# proof is temporarily persisted.
verifier = SIRP::Verifier.new(prime_length)
session = verifier.get_challenge_and_proof(username, v, salt, A)

# Server has to persist proof to authenticate the client response later.
@proof = session[:proof]

# Server sends the challenge containing salt and B to client.
response = session[:challenge]

# HTTPS Server => Client: response includes 'salt', and 'B'

# ~~~ Phase 2 : Continue Authentication ~~~

# Client calculates M as a response to the challenge using the
# username and password and the server provided 'salt' and 'B'.
client_M = client.process_challenge(username, password, salt, B)

# HTTPS POST Client => Server: request includes 'username', and 'M'

# Instantiate a new verifier on the server.
verifier = SIRP::Verifier.new(prime_length)

# Verify challenge response M against the Verifier proof stored earlier.
# server_H_AMK returned will be 'false' if verification failed.
server_H_AMK = verifier.verify_session(@proof, client_M)

# At this point, the client and server should have a common session key (K)
# that is secure and unknown to any outside party. Before they can safely use
# it though they must prove to each other that their keys are identical by
# exchanging a hash H(A,M,K). This step allows both client and server to be
# certain they arrived at the same values independently.

# The server sends a response based on the results of verify_session.

if server_H_AMK
  # HTTPS Server => Client: response includes server_H_AMK
else
  # Do NOT include the server_H_AMK in the response.
  # HTTPS Server => Client: 401 Unauthorized
end

# The client compares server_H_AMK response to its own calculated H(A,M,K).

if client.verify(server_H_AMK)
  ####  SUCCESS ####
  # Client and server have mutually authenticated.
  # Optional : Use this secret key to derive shared encryption keys for some
  # other application specific use.
  secret_key = client.K
else
  # FAIL, THROW IT ALL AWAY AND START OVER!
end

```

## History

This gem is a fork of the [lamikae/srp-rb](https://github.com/lamikae/srp-rb)
repository created by Mikael Lammentausta [@lamikae](https://github.com/lamikae).
Significant changes were needed for my use-case which demanded breaking changes
for the sake of greater interoperability. With these factors in mind, a hard
fork seemed the most appropriate path to take. Much credit is due to Mikael for
his original implementation.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then,
run `bundle exec rake test` to run the tests. You can also run `bin/console` for an
interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.

The formal release process can be found in [RELEASE.md](https://github.com/grempe/sirp/blob/master/RELEASE.md)

### Contributing

Bug reports and pull requests are welcome on GitHub
at [https://github.com/grempe/sirp](https://github.com/grempe/sirp). This
project is intended to be a safe, welcoming space for collaboration, and
contributors are expected to adhere to the
[Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Legal

### Copyright

(c) 2016 Glenn Rempe <[glenn@rempe.us](mailto:glenn@rempe.us)> ([https://www.rempe.us/](https://www.rempe.us/))

(c) 2012 Mikael Lammentausta

### License

The gem is available as open source under the terms of
the [BSD 3-clause "New" or "Revised" License](https://spdx.org/licenses/BSD-3-Clause.html).

### Warranty

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. See the LICENSE.txt file for the
specific language governing permissions and limitations under
the License.
