module Api

include("Auth.jl")

using HTTP: Middleware, Cookies
using HTTP
using Oxygen
using OteraEngine
using Dates
using Umbrella
using URIs: URI, queryparams
using JSONWebTokens
using StructTypes

using .Init
using .Auth

const PROTECTED_URLS = [ "/", "/profiles" ]

const CORS_HEADERS = [
    "Access-Control-Allow-Origin" => SERVER_URL,
    "Access-Control-Allow-Headers" => "*",
    "Access-Control-Allow-Methods" => "POST, GET, OPTIONS"
]

mutable struct User
    name::String
    email::String
    password::String
end

mutable struct AuthUser
    user::User
    avatar::String
    jwt::String
end

const users = Dict{String, AuthUser}()

# https://juliaweb.github.io/HTTP.jl/stable/examples/#Cors-Server
function CorsMiddleware(handler)
    return function(req::HTTP.Request)
        # determine if this is a pre-flight request from the browser
        if HTTP.method(req) == "OPTIONS"
            return HTTP.Response(200, CORS_HEADERS)  
        else 
            return handler(req) # passes the request to the AuthMiddleware
        end
    end
end

function getCookieToken(req::HTTP.Request)
    for cookie in Cookies.cookies(req)
        if cookie.name == "token"
            println("found token=$(cookie.value)")
            return cookie.value
        end
    end
    return nothing
end

function getCurrentUser(req::HTTP.Request)
    token = getCookieToken(req)
    if !isnothing(token)
        for user in values(users)
            if token == user.jwt
                println("current user = $(user)")
                return user
            end
        end
    end
    return nothing
end

function getAvatar()
    return rand(String["/img/default-blue.png",
                       "/img/default-red.png",
                       "/img/default-slate.png",
                       "/img/default-green.png"])
end

function AuthMiddleware(handler)
    return function(req::HTTP.Request)
        # ** NOT an actual security check ** #
        path = URI(req.target).path
        if isnothing(getCookieToken(req)) && any(map(x -> x == path, PROTECTED_URLS))
            return HTTP.Response(302, [ "Location" => SERVER_URL * AUTH_URL ])
        else 
            return handler(req) # passes the request to your application
        end
    end
end

@get "/" function(req::HTTP.Request)
    current  = getCurrentUser(req)
    println("current = $(current)")
    if isnothing(current)
        return HTTP.Response(302, ["Location" => AUTH_URL])
    end
    tmp = Template("./src/templates/index.html")
    init = Dict("name" => current.user.name, "avatar" => current.avatar)
    return html(tmp(init))
end

@get "/auth" function(req::HTTP.Request)
    tmp = Template("./src/templates/auth.html")
    return html(tmp())
end

@get "/oauth2/google" function(req::HTTP.Request)
    println("redirect google auth")
    google_oauth2.redirect()
end

@get "/oauth2/github" function(req::HTTP.Request)
    println("redirect github auth")
    github_oauth2.redirect()
end

@get "/api/auth/callback/google" function(req::HTTP.Request)
    println("got google callback")
    query_params = queryparams(req)
    code = query_params["code"]

    google_oauth2.token_exchange(code,
        function (tokens::Google.Tokens, user::Google.User)
            println(tokens.access_token)
            println(tokens.refresh_token)
            println("email=$(user.email)")
            if haskey(users, user.email)
                users[user.email].avatar = user.picture
                users[user.email].jwt = tokens.access_token
            else
                println("avatar=$(user.picture)")
                users[user.email] = AuthUser(User(user.given_name, user.email, ""), user.picture, tokens.access_token)
            end
            return HTTP.Response(302, ["Set-Cookie" => "token=$(tokens.access_token); max-age=$(datetime2unix(now() + Day(3)))", "Location" => "/"])
        end
    )
end

@get "/api/auth/callback/github" function(req::HTTP.Request)
    println("got github callback")
    query_params = queryparams(req)
    code = query_params["code"]

    github_oauth2.token_exchange(code,
        function (tokens::GitHub.Tokens, user::GitHub.User)
            println(tokens.access_token)
            println("email=$(user.email)")
            if haskey(users, user.email)
                users[user.email].avatar = user.avatar
                users[user.email].jwt = tokens.access_token
            else
                println("avatar=$(user.avatar)")
                users[user.email] = AuthUser(User(user.name, user.email, ""), user.avatar, tokens.access_token)
            end
            return HTTP.Response(302, ["Set-Cookie" => "token=$(tokens.access_token); max-age=$(datetime2unix(now() + Day(3)))", "Location" => "/"])
        end
    )
end

@get "/profiles" function(req::HTTP.Request)
    current = getCurrentUser(req)
    if isnothing(current)
        return HTTP.Response(302, ["Location" => AUTH_URL])
    end
    tmp = Template("./src/templates/profiles.html")
    init = Dict("name" => current.user.name, "avatar" => current.avatar)
    return html(tmp(init))
end

@post "/logout" function(req::HTTP.Request)
    current = getCurrentUser(req)
    if isnothing(current)
        return HTTP.Response(302, ["Location" => AUTH_URL])
    end
    return HTTP.Response(302, ["Set-Cookie" => "token=deleted; max-age=$(datetime2unix(now() - Days(3)))", "Location" => AUTH_URL ])
end

function parseForm(req::HTTP.Request)
    return queryparams(String(HTTP.payload(req)))
#    form = Dict{String, String}()
#    payload = strip(String(HTTP.payload(req)))
#    for pair in split(payload, "&")
#        kv = split(pair, "=")
#        if length(kv) == 2
#            valpair = map(HTTP.unescapeuri, kv)
#            form[valpair[1]] = valpair[2]
#        end
#    end
#    return form
end

@post "/login" function(req::HTTP.Request)
    println("logging in now")
    form = parseForm(req)
    println("form=$(form)")
    #user = json(req, User)
    #if isnothing(user) || isempty(user.email) || isempty(user.password)
    if length(form) < 2 || !haskey(form, "email") || !haskey(form, "password")
        return HTTP.Response(302, ["Location" => AUTH_URL])
    end
    if haskey(users, form["email"])
        user = users[form["email"]]
        if user.user.password == form["password"]
            println("jwt = $(user.jwt)")
            #return Dict("token" => user.jwt)
            return HTTP.Response(302, ["Set-Cookie" => "token=$(user.jwt); max-age=$(datetime2unix(now() + Day(3)))", "Location" => "/"])
        end
    end
    return HTTP.Response(302, ["Location" => AUTH_URL])
end

@post "/register" function(req::HTTP.Request)
    println("registering now")
    form = parseForm(req)
    println("form=$(form)")
    #user = json(req, User)
    #if isnothing(user) || isempty(user.email) || isempty(user.password)
    if length(form) < 2 || !haskey(form, "email") || !haskey(form, "password")
        return HTTP.Response(302, ["Location" => AUTH_URL])
    end
    println("registering $(form["email"])")
    if haskey(users, form["email"])
        println("re-registering existing $(form["email"])")
        user = users[form["email"]]
        println("jwt = $(user.jwt)")
        #return Dict("token" => user.jwt)
        return HTTP.Response(302, ["Set-Cookie" => "token=$(user.jwt); max-age=$(datetime2unix(now() + Day(3)))", "Location" => "/"])
    end
    claims = Dict("sub" => form["email"], "email" => form["email"], "iat" => datetime2unix(now()))
    encoding = JSONWebTokens.HS256(ENV["AUTH_JWT_SECRET"])
    jwt = JSONWebTokens.encode(encoding, claims)
    name = get(form, "name", form["email"])
    current = User(name, form["email"], form["password"])
    users[form["email"]] = AuthUser(current, getAvatar(), jwt)
    println("jwt = $(jwt)")
    return HTTP.Response(302, ["Set-Cookie" => "token=$(jwt); max-age=$(datetime2unix(now() + Day(3)))", "Location" => "/"])
end

staticfiles("public", "/")

# set application level middleware
serve(port=PORT, middleware=[CorsMiddleware, AuthMiddleware])

end # module Api
