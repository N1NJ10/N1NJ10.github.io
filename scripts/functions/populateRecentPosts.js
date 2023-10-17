export const populateRecentPosts = (posts) => {
    const recentPosts = document.querySelector(".sidebar-recent__ul");
    const postTemplate = document.getElementById("recentPostTemplate");

    for (let i = 0; i < Math.min(6, posts.length); i++) {
        const post = posts[i];
        const clone = postTemplate.content.cloneNode(true);

        clone.querySelector("a").textContent = post.title;
        clone.querySelector("a").href = `${post.link || "#"}`; // Set the link

        recentPosts.appendChild(clone);
    }
}