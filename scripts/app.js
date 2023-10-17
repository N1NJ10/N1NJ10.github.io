import posts from "./posts/posts.js";
import categories from "./categories/categories.js";

import {populateCategories} from "./functions/populateCategories.js";
import {populateRecentPosts} from "./functions/populateRecentPosts.js";
import {populatePagination} from "./functions/populatePagination.js";
import mobileNavBarActive from "./functions/mobileNavBarActivate.js";

const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const urlParams = new URLSearchParams(window.location.search);
const currentPage = parseInt(urlParams.get('page')) || 1;


const populatePosts = () => {
    const postTemplate = document.getElementById("postTemplate");
    const postList = document.querySelector("#postList");
    for (let i = ((currentPage - 1) * 8); i < Math.min(((currentPage * 8)) + 8, posts.length); i++) {
        const post = posts[i];
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
            tagElement.href = `/pages/tags/tag/?tag=${encodeURIComponent(tag)}`;
            tags.appendChild(tagElement);
        })

        const postText = post.description;

        title.textContent = post.title;
        title.href = `/pages/post/?title=${encodeURIComponent(post.title)}`;
        date.textContent += `${months[post.date.getMonth() - 1]} ${post.date.getDay()}, ${post.date.getFullYear()}`;
        author.textContent = "✍️ " + post.author;
        content.innerHTML = postText;
        imgContainer.innerHTML = `<img alt="" src="${post.previewPicture}">`;

        postList.appendChild(clone);
    }

}


mobileNavBarActive();
populatePosts();
populatePagination(posts, currentPage);
populateRecentPosts(posts);
populateCategories(categories, posts);