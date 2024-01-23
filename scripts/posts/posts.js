import Macros from "./post/Macros.js"
import Authority from "./post/Authority.js"
import ECPPT from "./post/Ecppt_The_honest.js"
import F5 from "./post/F5.js"
import Broker from "./post/Broker.js"
import SQL from "./post/SQL.js"
import ntlm from "./post/ntlm.js"
import poison from "./post/poison.js"

const posts = [
Macros,
Authority,
ECPPT,
F5,
poison,
ntlm,
Broker,
SQL,
];

for (let i = 0; i < posts.length; i++) {
posts[i].id = i;
}

export default posts;
