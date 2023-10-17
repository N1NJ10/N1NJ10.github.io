import mobileNavBarActive from "../../../../scripts/functions/mobileNavBarActivate.js";
import {populateCategories} from "../../../../scripts/functions/populateCategories.js";
import {populateRecentPosts} from "../../../../scripts/functions/populateRecentPosts.js";
import {populatePaginationWithCategories} from "../../../../scripts/functions/populatePagination.js";
import posts from "../../../../scripts/posts/posts.js";
import tags from "../../../../scripts/tags/tags.js";
import categories from "../../../../scripts/categories/categories.js";

const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const converter = new showdown.Converter();
const postTemplate = document.getElementById("postTemplate");
const categoryFilter = new URLSearchParams(window.location.search).get('category');

document.querySelector('.title-name').innerText = "Category: " + categoryFilter.toUpperCase();
const currentPage = parseInt(new URLSearchParams(window.location.search).get('page')) || 1;


const filteredPosts = posts.filter(post => {
    return post.category.toLowerCase() === categoryFilter.toLowerCase();
})

const populatePosts = () => {
    const postTemplate = document.getElementById("postTemplate");
    const postList = document.querySelector("#postList");
    for (let i = ((currentPage - 1) * 8); i < Math.min(((currentPage * 8)) + 8, filteredPosts.length); i++) {
        const post = filteredPosts[i];
        const clone = postTemplate.content.cloneNode(true);
        const title = clone.querySelector(".title a");
        const content = clone.querySelector(".content .text");
        const author = clone.querySelector(".date-author .author");
        const date = clone.querySelector('time');
        const tags = clone.querySelector(".tags");
        const imgContainer = clone.querySelector(".pic");


        post.tags.forEach(tag => {
            const tagElement = document.createElement("a");
            tagElement.className = "tag";
            tagElement.textContent = tag;
            tagElement.href = `/pages/tags/tag/?tag=${encodeURIComponent(tag.toLowerCase())}`;
            tags.appendChild(tagElement);
        })

        const postText = converter.makeHtml(post.description);

        title.textContent = post.title;
        title.href = `/pages/post/?title=${encodeURIComponent(post.title)}`;
        date.textContent += `${months[post.date.getMonth() - 1]} ${post.date.getDay()}, ${post.date.getFullYear()}`;
        author.textContent = "✍️ " + post.author;
        content.innerHTML = postText;
        imgContainer.innerHTML = `<img alt="" src="${post.previewPicture}">`;
        postList.appendChild(clone);
    }

}

if (filteredPosts.length > 0) {
    populatePosts();
    populatePaginationWithCategories(filteredPosts, currentPage, categoryFilter);
} else {
    const postList = document.querySelector("#postList");
    postList.innerHTML = "<h1 style='color: white;font-weight: 800'>No posts found</h1>";
}
mobileNavBarActive();
populateRecentPosts(posts);
populateCategories(categories, posts);
