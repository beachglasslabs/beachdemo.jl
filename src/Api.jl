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

function redirect(location::String)
    return HTTP.Response(302, ["Location" => location])
end

function redirect(location::String, token::String, days::Integer = 3)
    return HTTP.Response(302, ["Set-Cookie" => "token=$(token); max-age=$(datetime2unix(now() + Day(days)))", "Location" => location])
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
        current = getCurrentUser(req)
        protected = any(map(x -> x == path, PROTECTED_URLS))
        if protected
            if isnothing(current)
                return redirect(AUTH_URL)
            else
                println("found session for $(current.user.email)")
                return handler(req) # passes the request to your application
            end
        else
            return handler(req) # passes the request to your application
        end
    end
end

@get "/" function(req::HTTP.Request)
    current  = getCurrentUser(req)
    println("current = $(current)")
    if isnothing(current)
        return redirect(AUTH_URL)
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
            println("google email=$(user.email)")
            if haskey(users, user.email)
                users[user.email].avatar = user.picture
                users[user.email].jwt = tokens.access_token
            else
                println("google avatar=$(user.picture)")
                users[user.email] = AuthUser(User(user.given_name, user.email, ""), user.picture, tokens.access_token)
            end
            return redirect("/", tokens.access_token)
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
            println("github email=$(user.email)")
            if haskey(users, user.email)
                users[user.email].avatar = user.avatar
                users[user.email].jwt = tokens.access_token
            else
                println("github avatar=$(user.avatar)")
                users[user.email] = AuthUser(User(user.name, user.email, ""), user.avatar, tokens.access_token)
            end
            return redirect("/", tokens.access_token)
        end
    )
end

@get "/profiles" function(req::HTTP.Request)
    current = getCurrentUser(req)
    if isnothing(current)
        return redirect(AUTH_URL)
    end
    tmp = Template("./src/templates/profiles.html")
    init = Dict("name" => current.user.name, "avatar" => current.avatar)
    return html(tmp(init))
end

@post "/logout" function(req::HTTP.Request)
    current = getCurrentUser(req)
    if isnothing(current)
        return redirect(AUTH_URL)
    end
    return redirect(AUTH_URL, "deleted", -3)
end

function parseForm(req::HTTP.Request)
    return queryparams(String(HTTP.payload(req)))
end

@post "/login" function(req::HTTP.Request)
    form = parseForm(req)
    println("form=$(form)")
    #user = json(req, User)
    #if isnothing(user) || isempty(user.email) || isempty(user.password)
    if length(form) < 2 || !haskey(form, "email") || !haskey(form, "password")
        return redirect(AUTH_URL)
    end
    if haskey(users, form["email"])
        user = users[form["email"]]
        if user.user.password == form["password"]
            println("logging in $(form["email"])")
            return redirect("/", user.jwt)
        end
    end
    return redirect(AUTH_URL)
end

@post "/register" function(req::HTTP.Request)
    form = parseForm(req)
    println("form=$(form)")
    #user = json(req, User)
    #if isnothing(user) || isempty(user.email) || isempty(user.password)
    if length(form) < 2 || !haskey(form, "email") || !haskey(form, "password")
        return redirect(AUTH_URL)
    end
    if haskey(users, form["email"])
        println("existing user $(form["email"]) found")
        current = getCurrentUser(req) 
        if !isnothing(current) && current.user.email != form["email"]
            println("already logged in $(form["email"])")
            return redirect("/")
        else
            return redirect(AUTH_URL)
        end
    end
    println("registering $(form["email"])")
    claims = Dict("sub" => form["email"], "email" => form["email"], "iat" => datetime2unix(now()))
    encoding = JSONWebTokens.HS256(ENV["AUTH_JWT_SECRET"])
    jwt = JSONWebTokens.encode(encoding, claims)
    println("jwt = $(jwt)")
    name = get(form, "name", form["email"])
    user = User(name, form["email"], form["password"])
    users[form["email"]] = AuthUser(user, getAvatar(), jwt)
    return redirect("/", jwt)
end

staticfiles("public", "/")

# set application level middleware
serve(port=PORT, middleware=[CorsMiddleware, AuthMiddleware])

end # module Api
