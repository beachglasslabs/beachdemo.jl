module Api

include("Auth.jl")

using HTTP: Middleware, Cookies
using HTTP
using Oxygen
using OteraEngine
using Dates
using Umbrella
import URIs
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
    jwt::String
end

users = Dict{String, AuthUser}()

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
    return Nothing
end

function AuthMiddleware(handler)
    return function(req::HTTP.Request)
        # ** NOT an actual security check ** #
        path = URIs.URI(req.target).path
        if getCookieToken(req) == Nothing && any(map(x -> x == path, PROTECTED_URLS))
            return HTTP.Response(302, [ "Location" => SERVER_URL * AUTH_URL ])
        else 
            return handler(req) # passes the request to your application
        end
    end
end

@get "/" function(req::HTTP.Request)
    tmp = Template("./src/templates/index.html")
    init = Dict("time" => now())
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
            println(user.email)
            if haskey(users, user.email)
                users[user.email].jwt = tokens.access_token
            else
                users[User(user.given_name, user.email, "")].jwt = tokens.access_token
            end
            return HTTP.Response(302, ["Set-Cookie" => "token=$(tokens.access_token)", "Location" => "/"])
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
            println(user.name)
            if haskey(users, user.email)
                users[user.email].jwt = tokens.access_token
            else
                users[User(user.name, user.email, "")].jwt = tokens.access_token
            end
        end
    )
end

@get "/profiles" function(req::HTTP.Request)
    image = rand(String["/img/default-blue.png", "/img/default-red.png", "/img/default-slate.png", "/img/default-green.png"])
    tmp = Template("./src/templates/profiles.html")
    init = Dict("name" => "test user", "img" => image)
    return html(tmp(init))
end

@post "/login" function(req::HTTP.Request)
    current = json(req, User)
    if isnothing(current) || isempty(current.email) || isempty(current.password)
        return HTTP.Response(302, ["Location" => AUTH_URL])
    end
    if haskey(users, current.email)
        user = users[current.email]
        if user.user.password == current.password
            println("jwt = $(user.jwt)")
            #return Dict("token" => user.jwt)
            return HTTP.Response(302, ["Set-Cookie" => "token=$(user.jwt)", "Location" => "/"])
        end
    end
    return HTTP.Response(302, ["Location" => AUTH_URL])
end

@post "/register" function(req::HTTP.Request)
    new = json(req, User)
    if isnothing(new) || isempty(new.email) || isempty(new.password)
        return HTTP.Response(302, ["Location" => AUTH_URL])
    end
    println("registering $(new)")
    if haskey(users, new.email)
        println("re-registering existing $(new)")
        user = users[new.email]
        println("jwt = $(user.jwt)")
        #return Dict("token" => user.jwt)
        return HTTP.Response(302, ["Set-Cookie" => "token=$(user.jwt)", "Location" => "/"])
    end
    claims = Dict("sub" => new.email, "email" => new.email, "iat" => datetime2unix(now()))
    encoding = JSONWebTokens.HS256(ENV["AUTH_JWT_SECRET"])
    jwt = JSONWebTokens.encode(encoding, claims)
    user = User(new.name, new.email, new.password)
    users[user.email] = AuthUser(user, jwt)
    println("jwt = $(jwt)")
    return HTTP.Response(302, ["Set-Cookie" => "token=$(jwt)", "Location" => "/"])
end

staticfiles("public", "/")

# set application level middleware
serve(port=PORT, middleware=[CorsMiddleware, AuthMiddleware])

end # module Api
