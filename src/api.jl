using Oxygen
using HTTP
using OteraEngine
using Dates

@get "/" function(req::HTTP.Request)
    tmp = Template("./templates/index.html")
    init = Dict("time" => now())
    return html(tmp(init))
end

staticfiles("../public", "/")

serve()
