This is meant to test out some new technologies we were considering using for the demo front-end:
 * The UI is based on a great video tutorial I found on [Youtube](https://github.com/AntonioErdeljac/next-netflix-tutorial).
 * I rewrote the UI to be based on [HTMX](https://htmx.org) and [Alpinejs](https://alpinejs.dev).
 * The backend is completely rewritten in [Julia](https://julialang.org) and I intentionally chose some of the less well-known packages.
 * Special thanks to [Oxygen.jl](https://github.com/ndortega/Oxygen.jl), and [OteraEngine](https://github.com/MommaWatasu/OteraEngine.jl).
 * Due to the immaturity of Julia, I had to implement the authentication and session management using cookies.
 * I got rid of the Mongodb Atlas dependency by using in-memory data structures.
 * Github oauth2 doesn't work as [Umbrella](https://github.com/jiachengzhang1/Umbrella.jl) hasn't been updated.

To test it out:
 1. `git clone git@github.com:beachglasslabs/beachglass.tv.git`
 2. `npm install` to install npm packages
 3. instantiate the Julia packages (use `add Umbrella#main` for [Umbrella](https://github.com/jiachengzhang1/Umbrella.jl)) 
 4. `npm run dev` to start the server
