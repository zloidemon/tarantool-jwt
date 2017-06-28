#!/usr/bin/env tarantool

local fiber = require('fiber')

local function t2s(o)
        if type(o) == 'table' then
                local s = '{ '
                for k,v in pairs(o) do
                        if type(k) ~= 'number' then k = '"' .. k ..'"' end
                        s = ('%s[%s] = %s,'):format(s, k, t2s(v))
                end

                return s .. '} '
        else
                return tostring(o)
        end
end

-- 
local jwt = require 'jwt'

local key = 'example_key'

local claim = {
    iss = '12345678',
    nbf = fiber.time() - 1,
    exp = fiber.time() + 3600,
}

local alg = 'HS256' -- default alg
local token, err = jwt.encode(claim, key, alg)

print('Token:', token)

local validate = true -- validate exp and nbf (default: true)
local decoded, err = jwt.decode(token, key, validate)

print('Claim:', t2s(decoded))
