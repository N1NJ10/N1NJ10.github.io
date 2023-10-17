import posts from "../posts/posts.js";

const tags = [];

posts.forEach(post => {
    post.tags.forEach(tag => {
        if (!tags.includes(tag)) {
            tags.push(tag);
        }
    });
});
export default tags;