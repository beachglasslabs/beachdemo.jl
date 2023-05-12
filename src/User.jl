mutable struct User
    name::String
    email::String
    password::Union{String, Nothing}
end

mutable struct Account
    user::User
    avatar::String
    jwt::String
    favorites::Vector{String}
    Account(user, avatar, jwt) = new(user, avatar, jwt, [])
end

function addFavorite(user::Account, new::String)
    if ! (new in user.favorites)  
        push!(user.favorites, new)
    end
end

function removeFavorite(user::Account, old::String)
    if old in user.favorites
        deleteat!(user.favorites, findfirst(x->x==old, user.favorites))
    end
end

function getAvatar()
    rand(String["/img/default-blue.png",
                "/img/default-red.png",
                "/img/default-slate.png",
                "/img/default-green.png"])
end

