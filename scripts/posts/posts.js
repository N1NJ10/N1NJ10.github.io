import Macros from "./post/Macros.js";
import Broker from "./post/Broker.js"
import Authority from "./post/Authority.js"

const posts = [
    Macros,
    Broker,
    Authority,
    
    ];


for (let i = 0; i < posts.length; i++) {
    posts[i].id = i;
}

export default posts;
