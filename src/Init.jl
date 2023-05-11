const PORT = 3000
const SERVER_URL = "http://localhost:" * string(PORT)
const AUTH_URL = "/auth"


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

