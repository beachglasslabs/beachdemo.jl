using JSON3
using StructTypes
using UUIDs

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
    movies = Dict{String, Movie}()
    json_string = read(file, String)
    all_movies = JSON3.read(json_string, Vector{Movie})
    for movie in all_movies
        movie.id = string(uuid4().value, base=16)
        println("movie id = $(movie.id)")
        movies[movie.id] = movie
    end
    return movies
end

const movies = importData()

