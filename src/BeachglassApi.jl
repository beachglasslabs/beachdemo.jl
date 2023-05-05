module BeachglassApi

using HTTP
using Oxygen
using OteraEngine
using Dates
using Umbrella

function readenv(env=".env")
    open(env, "r") do f
        while !eof(f)
            line = strip(readline(f))
            if isempty(line)
                continue
            end
            name, value = split(line, "=") 
            if isempty(name) || isempty(value)
                continue
            end
            ENV[strip(name)] = strip(value)
        end
    end
    println("Loaded env from $(pwd() * "/" * env)")
end

readenv()

const google_options = Configuration.Options(;
    client_id = ENV["GOOGLE_ID"],
    client_secret = ENV["GOOGLE_SECRET"],
    redirect_uri = "http://localhost:3000/api/auth/callback/google",
    success_redirect = "/",
    failure_redirect = "/auth",
    scopes = ["profile", "openid", "email"],
)
const google_oauth2 = init(:google, google_options)

const github_options = Configuration.Options(;
    client_id = ENV["GITHUB_ID"],
    client_secret = ENV["GITHUB_SECRET"],
    redirect_uri = "http://localhost:3000/api/auth/callback/github",
    success_redirect = "/",
    failure_redirect = "/auth",
    scopes = ["user", "email", "profile"],
)
const github_oauth2 = init(:github, github_options)

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
    return google_oauth2.redirect()
    println("google auth redirected")
end

@get "/oauth2/github" function(req::HTTP.Request)
    println("redirect github auth")
    return github_oauth2.redirect()
    println("github auth redirected")
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
            println(user)
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
    println("login not implemented yet")
end

@post "/register" function(req::HTTP.Request)
    println("register not implemented yet")
end

staticfiles("public", "/")

serve(port=3000)

end # module BeachglassApi
