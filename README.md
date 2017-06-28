tarantool-jwt
===========

JSON Web Tokens for Tarantool application server based on [luajwt](https://github.com/x25/luajwt)

```bash
$ sudo luarocks install --server=http://rocks.moonscript.org tarantool-jwt
```

## Usage

Basic usage:

```lua
local jwt = require('jwt')

local key = 'example_key'

local payload = {
    iss = '12345678',
    nbf = os.time(),
    exp = os.time() + 3600,
}

-- encode
local alg = 'HS256' -- (default)
local state, token = pcall(jwt.encode, payload, key, alg)

-- token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIx(cutted)...

-- decode and validate
local validate = true -- validate signature, exp and nbf (default: true)
local state, decoded = pcall(jwt.decode, token, key, validate)

-- decoded: { ["iss"] = 12345678, ["nbf"] = 1405108000, ["exp"] = 1405181916 }

-- only decode
local state, unsafe = pcall(jwt.decode, token)

-- unsafe:  { ["iss"] = 12345678, ["nbf"] = 1405108000, ["exp"] = 1405181916 }

-- decode with callbacks

local state, decoded = pcall(jwt.decode, key, value, {['exp'] = function(value) return false end})
-- state: false
-- decoded: error
```

Generate token and try:

## Algorithms

**HMAC**

* HS256    - HMAC using SHA-256 hash algorithm (default)
* HS384    - HMAC using SHA-384 hash algorithm
* HS512    - HMAC using SHA-512 hash algorithm

## License
MIT
