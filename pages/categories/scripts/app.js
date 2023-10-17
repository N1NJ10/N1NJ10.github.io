import categories from "../../../scripts/categories/categories.js";
import posts from "../../../scripts/posts/posts.js";
import mobileNavBarActivate from "../../../scripts/functions/mobileNavBarActivate.js";

const populateTags = () => {
    const tags = categories;
    const tagTemplate = document.querySelector("#tagTemplate");
    const tagContainer = document.querySelector(".tags-list");
    tags.forEach(tag => {
        const clone = tagTemplate.content.cloneNode(true);
        clone.querySelector(".taxo__text").textContent = tag;
        clone.querySelector(".taxo__link").href = `/pages/categories/category/?category=${encodeURIComponent(tag.toLowerCase())}`;
        clone.querySelector(".taxo__num").textContent = posts.filter(post => post.category.toLowerCase() === tag.toLowerCase()).length;
        tagContainer.appendChild(clone);
    })
}
populateTags();
mobileNavBarActivate()