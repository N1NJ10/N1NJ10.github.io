import Macros from "./post/Macros.js";
import Broker from "./post/Broker.js"
import Authority from "./post/Authority.js"
import Active from "./post/Active.js"
import ECPPT from "./post/Ecppt_The_honest.js"
import auto from "./post/Auto_Login.js"
import F5 from "./post/F5.js"
import ntlm from "./post/ntlm.js"
import SQL from "./post/SQL.js"
import poison from "./post/poison.js"
import arp from "./post/arp.js"

const posts = [
    Macros,
    Broker,
    Authority,
    Active,
    ECPPT,
    auto,
    F5,
    ntlm,
    SQL,
    poison,
    arp,
    ];


for (let i = 0; i < posts.length; i++) {
    posts[i].id = i;
}

export default posts;
