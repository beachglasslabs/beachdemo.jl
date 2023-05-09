module Auth

using Umbrella
using Umbrella.Google
using UUIDs

include("Init.jl")

using .Init

export google_oauth2, github_oauth2, newSessionId, newGoogleState
export Init

readenv()

function newSessionId()
    string(uuid1().value, base=16)
end

const google_options = Configuration.Options(;
    client_id = ENV["GOOGLE_ID"],
    client_secret = ENV["GOOGLE_SECRET"],
    redirect_uri = SERVER_URL * "/api/auth/callback/google",
    success_redirect = "/",
    failure_redirect = AUTH_URL,
    scopes = ["profile", "openid", "email"],
    providerOptions = GoogleOptions(access_type="online")
)
const google_oauth2 = init(:google, google_options)

const github_options = Configuration.Options(;
    client_id = ENV["GITHUB_ID"],
    client_secret = ENV["GITHUB_SECRET"],
    redirect_uri = SERVER_URL * "/api/auth/callback/github",
    success_redirect = "/",
    failure_redirect = AUTH_URL,
    scopes = ["user", "email", "profile"],
)
const github_oauth2 = init(:github, github_options)

function newGoogleState()
    Configuration.Options(;
        client_id = ENV["GOOGLE_ID"],
        client_secret = ENV["GOOGLE_SECRET"],
        redirect_uri = SERVER_URL * "/api/auth/callback/google",
        success_redirect = "/",
        failure_redirect = AUTH_URL,
        scopes = ["profile", "openid", "email"],
        state = newSessionId(),
        providerOptions = GoogleOptions(access_type="online")
    )
end

end # module Auth

using .Auth
export google_oauth2, github_oauth2, newSessionId, newGoogleState
