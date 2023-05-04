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

@get "/profile" function(req::HTTP.Request)
    image = rand(String["/img/default-blue.png", "/img/default-red.png", "/img/default-slate.png", "/img/default-green.png"])
    tmp = Template("./src/templates/profile.html")
    init = Dict("name" => "test user", "img" => image)
    return html(tmp(init))
end

@post "/login" function(req::HTTP.Request)
end

@post "/register" function(req::HTTP.Request)
end

readenv()
staticfiles("public", "/")

serve(port=3000)

end # module BeachglassApi
