package = 'tarantool-jwt'
version = 'scm-1'

source = {
    url = 'git://github.com/zloidemon/tarantool-jwt',
    branch = 'master'
}

description = {
    summary = 'JSON Web Tokens for Tarantool',
    detailed = 'Very fast and compatible with pyjwt, php-jwt, ruby-jwt, node-jwt-simple and others',
    homepage = 'https://github.com/zloidemon/tarantool-jwt',
    license = 'MIT <http://opensource.org/licenses/MIT>'
}

dependencies = {
    'lua >= 5.1',
}

build = {
    type = 'builtin',
    modules = {
        luajwt = 'jwt.lua'
    }
}
