module MovieBase

using JSON3
using StructTypes
using UUIDs

export Movie, movies

mutable struct Movie
    id::Union{String,Nothing}
    title::String
    description::String
    videoUrl::String
    thumbnailUrl::String
    genre::String
    duration::String
end
Movie() = Movie(nothing, "", "", "", "", "", "")

StructTypes.StructType(::Type{Movie}) = StructTypes.Mutable()

function importData(file="movies.json")
    json_string = read(file, String)
    movies = JSON3.read(json_string, Vector{Movie})
    for movie in movies
        movie.id = string(uuid1().value, base=16)
    end
    return movies
end

const movies = importData()

end # module MovieBase

using .MovieBase
export Movie, movies
