module BeachglassApi

using HTTP
using Oxygen
using OteraEngine
using Dates

@get "/" function(req::HTTP.Request)
    tmp = Template("./templates/index.html")
    init = Dict("time" => now())
    return html(tmp(jl_init=init))
end

@get "/auth" function(req::HTTP.Request)
    tmp = Template("./templates/auth.html")
    return html(tmp())
end

@get "/profile" function(req::HTTP.Request)
    image = rand(String["/img/default-blue.png", "/img/default-red.png", "/img/default-slate.png", "/img/default-green.png"])
    tmp = Template("./templates/profile.html")
    init = Dict("name" => "test user", "img" => image)
    return html(tmp(jl_init=init))
end

@post "/login" function(req::HTTP.Request)
end

@post "/register" function(req::HTTP.Request)
end

staticfiles("../public", "/")

serve()

end # module BeachglassApi
