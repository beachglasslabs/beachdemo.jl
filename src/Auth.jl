using Umbrella
using Umbrella.Google
using Dates
using UUIDs
using JSONWebTokens

include("Init.jl")

readenv()

function newSessionId()
    string(uuid4().value, base=16)
end

function googleOptions(session::Union{String, Nothing} = nothing)
    Configuration.Options(;
        client_id = ENV["GOOGLE_ID"],
        client_secret = ENV["GOOGLE_SECRET"],
        redirect_uri = SERVER_URL * "/oauth2/google/callback",
        success_redirect = "/",
        failure_redirect = AUTH_URL,
        scopes = ["profile", "openid", "email"],
        state = session,
        providerOptions = GoogleOptions(access_type="online")
    )
end

function githubOptions(session::Union{String, Nothing} = nothing)
    Configuration.Options(;
        client_id = ENV["GITHUB_ID"],
        client_secret = ENV["GITHUB_SECRET"],
        redirect_uri = SERVER_URL * "/oauth2/github/callback",
        success_redirect = "/",
        failure_redirect = AUTH_URL,
        scopes = ["user", "email", "profile"],
        state = session
    )
end

function newJwt(sub::String)
    claims = Dict("iss" => "beachglasslabs", "sub" => sub, "aud" => "beachglass.tv",  "iat" => datetime2unix(now()), "exp" => datetime2unix(now() + Day(3)))
    encoding = JSONWebTokens.HS256(ENV["AUTH_JWT_SECRET"])
    JSONWebTokens.encode(encoding, claims)
end

function newCookie(token::String, days::Integer = 3)
    "token=$(token); Max-Age=$(datetime2unix(now() + Day(days))); Path=/; SameSize=None;"
end

