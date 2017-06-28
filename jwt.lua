local strict = require('strict').on()
local json   = require('json')
local digest = require('digest')
local crypto = require('crypto')
local fiber  = require('fiber')

-- FIXME: Remove trim_newline everywhere after fix issue:
-- https://github.com/tarantool/tarantool/issues/2478

local function trim_newline(str)
    return string.gsub(str, '\n', '')
end

local alg_sign = {
    ['none']  = function(data, key) return '' end,
    ['HS256'] = function(data, key) return crypto.hmac.sha256(key, data) end,
    ['HS384'] = function(data, key) return crypto.hmac.sha384(key, data) end,
    ['HS512'] = function(data, key) return crypto.hmac.sha512(key, data) end,
}

local function sigcheck(alg, data, signature, key)
    return signature == alg_sign[alg](data, key)
end

local function b64_encode(input)
    local result = digest.base64_encode(input)

    result = result:gsub('+', '-')
        :gsub('/', '_')
        :gsub('=', '')

    local ret, _ = trim_newline(result)

    return ret
end

local function b64_decode(input)
    local reminder = #input % 4

    if reminder > 0 then
            local padlen = 4 - reminder
            input = input .. string.rep('=', padlen)
    end

    input = input:gsub('-', '+')
        :gsub('_', '/')

    return digest.base64_decode(input)
end

local function tokenize(str, div, len)
    local result, pos = {}, 0

    for st, sp in function() return str:find(div, pos, true) end do

        result[#result + 1] = str:sub(pos, st - 1)
        pos = sp + 1

        len = len - 1

        if len <= 1 then
            break
        end
    end

    result[#result + 1] = str:sub(pos)

    return result
end

local function encode(data, key, alg)
    if type(data) ~= 'table' then
        error('Data must be table')
    end

    if type(key) ~= 'string' then
        error('Secret key must be string')
    end

    alg = alg or 'HS256'

    if not alg_sign[alg] then
        error('Algorithm not supported')
    end

    local header = { typ='JWT', alg=alg }

    local segments = {
        b64_encode(json.encode(header)),
        b64_encode(json.encode(data))
    }

    local signing_input = table.concat(segments, '.')
    local signature = alg_sign[alg](signing_input, key)

    segments[#segments + 1] = b64_encode(signature)

    return table.concat(segments, '.')
end

local function decode(data, key, verify, callbacks)
    if callbacks == nil then
        callbacks = {
            ['nbf'] = function(value) return fiber.time() > value end,
            ['exp'] = function(value) return fiber.time() <= value end,
        }
    end
    if not data or type(data) ~= 'string' then
        error('Data must be string')
    end

    if key and type(key) ~= 'string' then
        error('Secret key must be string')
    end

    if key and verify == nil then
        verify = true
    end

    local token = tokenize(data, '.', 3)

    if #token ~= 3 then
        error('Invalid token parts')
    end

    local header_b64, payload_b64, sig_b64 = token[1], token[2], token[3]

    local header    = json.decode(b64_decode(header_b64))
    local payload   = json.decode(b64_decode(payload_b64))
    local signature = b64_decode(sig_b64)

    if verify then
        if not header.typ or header.typ ~= 'JWT' then
            error('Invalid typ')
        end

        if not header.alg or type(header.alg) ~= 'string' then
            error('Invalid alg')
        end

        if not alg_sign[header.alg] then
            error('Algorithm not supported')
        end

        if not sigcheck(header.alg, header_b64 .. '.' .. payload_b64, signature, key) then
            error('Invalid signature')
        end

        if payload.iss and type(payload.iss) ~= 'string' then
            error('iss must be string')
        end

        if payload.aud and type(payload.aud) ~= 'string' then
            error('aud must be string')
        end

        if payload.exp and type(payload.exp) ~= 'number' then
            error('exp must be number')
        end

        if payload.nbf and type(payload.nbf) ~= 'number' then
            error('nbf must be number')
        end

        if payload.iat and type(payload.iat) ~= 'number' then
            error('iat must be number')
        end

        if payload.jti and type(payload.jti) ~= 'string' then
            error('jti must be string')
        end

        for key, value in pairs(payload) do
            if callbacks[key] and type(callbacks[key]) == 'function' then
                if not callbacks[key](value) then
                    error(('%s has invalid value: %s'):format(value, key))
                end
            end
        end
    end

    return payload
end

return {
    encode = encode,
    decode = decode,
}
