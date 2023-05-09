module Api

include("Auth.jl")

using HTTP: Middleware, Cookies
using HTTP
using Oxygen
using OteraEngine
using Umbrella
using URIs: URI, queryparams

using .Init
using .Auth

const PROTECTED_URLS = [ "/", "/profiles" ]

const CORS_HEADERS = [
    "Access-Control-Allow-Origin" => "*",
    "Access-Control-Allow-Headers" => "*",
    "Access-Control-Allow-Methods" => "POST, GET, OPTIONS"
]

mutable struct User
    name::String
    email::String
    password::Union{String, Nothing}
end

mutable struct Account
    user::User
    avatar::String
    jwt::String
end

# email -> account(user)
const accounts = Dict{String, Account}()
# sessionId -> email
const sessions = Dict{String, String}()
# sessionId -> provider
const oauth2 = Dict{String, OAuth2}()

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

function getSessionUser(req::HTTP.Request)
    token = getCookieToken(req)
    if !isnothing(token)
        if haskey(sessions, token)
            return sessions[token]
        end
    end
    return nothing
end

function removeSessionUser!(email::String)
    for (k, v) in sessions
        if v == email
            delete!(sessions, k)
            return k
        end
    end
    return nothing
end

function getCurrentUser(req::HTTP.Request)
    user = getSessionUser(req)
    if !isnothing(user)
        if haskey(accounts, user)
            return accounts[user]
        end
    end
    return nothing
end

function redirect(location::String)
    return HTTP.Response(302, ["Location" => location])
end

function redirect(location::String, token::String, days::Integer = 3)
    println("redirect token=$(token)")
    return HTTP.Response(302, ["Set-Cookie" => newCookie(token, days),
                               "Location" => location])
end

function getAvatar()
    return rand(String["/img/default-blue.png",
                       "/img/default-red.png",
                       "/img/default-slate.png",
                       "/img/default-green.png"])
end

function parseForm(req::HTTP.Request)
    return queryparams(String(HTTP.payload(req)))
end

function validateForm(form::Dict{String, String}, fields::Vector{String})
    if length(form) < length(fields)
        return false
    end
    for f in fields
        if !haskey(form, f)
            return false
        elseif isnothing(form[f]) || isempty(form[f])
            return false
        end
    end
    return true
end

function AuthMiddleware(handler)
    return function(req::HTTP.Request)
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
    if isnothing(current)
        return redirect(AUTH_URL)
    end
    tmp = Template("./src/templates/index.html")
    init = Dict("name" => current.user.name, "avatar" => current.avatar)
    return html(tmp(init))
end

@get "/auth" function(_::HTTP.Request)
    tmp = Template("./src/templates/auth.html")
    return html(tmp())
end

@get "/oauth2/google" function(_::HTTP.Request)
    println("redirect google auth")
    state = newSessionId()
    google = init(:google, googleOptions(state))
    oauth2[state] = google
    google.redirect()
end

@get "/oauth2/github" function(_::HTTP.Request)
    println("redirect github auth")
    state = newSessionId()
    github = init(:github, githubOptions(state))
    oauth2[state] = github
    github.redirect()
end

@get "/api/auth/callback/google" function(req::HTTP.Request)
    query_params = queryparams(req)
    code = query_params["code"]
    state = query_params["state"]
    println("google session=$(state)")
    if haskey(oauth2, state)
        google = oauth2[state]
        # generate a new session id for cookie
        token = newSessionId()
        google.token_exchange(code,
            function (tokens::Google.Tokens, user::Google.User)
                println(tokens.access_token)
                # offline access only
                #println(tokens.refresh_token)
                println("google email=$(user.email)")
                if !haskey(accounts, user.email)
                    jwt = newJwt(user.email)
                    accounts[user.email] = Account(User(user.given_name, user.email, nothing), user.picture, jwt)
                end
                sessions[token] = user.email
            end
        )
        delete!(oauth2, state)
        return redirect("/profiles", token)
    else
        return redirect(AUTH_URL)
    end
end

@get "/api/auth/callback/github" function(req::HTTP.Request)
    query_params = queryparams(req)
    code = query_params["code"]
    state = query_params["state"]
    println("github session=$(state)")
    if haskey(oauth2, state)
        github = oauth2[state]
        # generate a new session id for cookie
        token = newSessionId()
        github.token_exchange(code,
            function (tokens::GitHub.Tokens, user::GitHub.User)
                println(tokens.access_token)
                println("github email=$(user.email)")
                if !haskey(accounts, user.email)
                    jwt = newJwt(user.email)
                    accounts[user.email] = Account(User(user.name, user.email, nothing), user.avatar_url, jwt)
                end
                sessions[token] = user.email
            end
        )
        delete!(oauth2, state)
        return redirect("/profiles", token)
    else
        return redirect(AUTH_URL)
    end
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
    else
        token = removeSessionUser!(current.user.email)
        println("removing session $(token)")
        return redirect(AUTH_URL, token, -3)
    end
end

@post "/login" function(req::HTTP.Request)
    form = parseForm(req)
    println("form=$(form)")
    if !validateForm(form, ["email", "password"])
        return redirect(AUTH_URL)
    end
    if haskey(accounts, form["email"])
        user = accounts[form["email"]]
        # if pssword is nothing then it was registered through oauth2
        if !isnothing(user.user.password) && user.user.password == form["password"]
            println("logging in $(form["email"])")
            token = newSessionId()
            sessions[token] = user.user.email
            return redirect("/profiles", token)
        end
    end
    return redirect(AUTH_URL)
end

@post "/register" function(req::HTTP.Request)
    form = parseForm(req)
    println("form=$(form)")
    if !validateForm(form, ["email", "password"])
        return redirect(AUTH_URL)
    elseif isnothing(form["name"]) || isempty(form["name"])
        form["name"] = form["email"]
    end
    if haskey(accounts, form["email"])
        println("existing user $(form["email"]) found")
        current = getCurrentUser(req) 
        if !isnothing(current) && current.user.email == form["email"]
            println("already logged in $(form["email"])")
            return redirect("/")
        else
            return redirect(AUTH_URL)
        end
    end
    println("registering $(form["email"])")
    jwt = newJwt(form["email"])
    println("jwt = $(jwt)")
    user = User(form["name"], form["email"], form["password"])
    accounts[form["email"]] = Account(user, getAvatar(), jwt)
    token = newSessionId()
    sessions[token] = form["email"]
    return redirect("/", token)
end

staticfiles("public", "/")

# set application level middleware
serve(port=PORT, middleware=[CorsMiddleware, AuthMiddleware])

end # module Api
