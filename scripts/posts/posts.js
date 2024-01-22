import Macros from "./post/Macros.js"

const posts = [
    Macros
    ];


for (let i = 0; i < posts.length; i++) {
    posts[i].id = i;
}

export default posts;
