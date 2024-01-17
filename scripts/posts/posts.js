import Macros from "./post/Macros.js";
import Broker from "./post/Broker.js"
import Authority from "./post/Authority.js"
import Active from "./post/Active.js"
import ECPPT from "./post/Ecppt_The_honest.js"
import F5 from "./post/F5.js"
import SQL from "./post/SQL.js"
const posts = [
    Macros,
    Broker,
    Authority,
    Active,
    ECPPT,
    F5,
    SQL,
    ];


for (let i = 0; i < posts.length; i++) {
    posts[i].id = i;
}

export default posts;
