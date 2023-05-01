using Oxygen
using HTTP
using OteraEngine
using Dates

@get "/" function(req::HTTP.Request)
    tmp = Template("./templates/index.html")
    init = Dict("time" => now())
    return html(tmp(init))
end

@get "/auth" function(req::HTTP.Request)
    tmp = Template("./templates/auth.html")
    return html(tmp())
end

@post "/login" function(req::HTTP.Request)
end

@post "/register" function(req::HTTP.Request)
end

staticfiles("../public", "/")

serve()
