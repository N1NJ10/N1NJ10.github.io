import posts from "../posts/posts.js";

const categories = [];
// get categories from posts and add them to the newCategories array
for (let i = 0; i < posts.length; i++) {
    if (categories.findIndex(category => category.toLowerCase() === posts[i].category.toLowerCase()) === -1) {
        categories.push(posts[i].category);
    }
}

export default categories;