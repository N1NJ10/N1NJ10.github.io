import tags from "../../../scripts/tags/tags.js";
import posts from "../../../scripts/posts/posts.js";
import mobileNavBarActive from "../../../scripts/functions/mobileNavBarActivate.js";
import mobileNavBarActivate from "../../../scripts/functions/mobileNavBarActivate.js";

const populateTags = () => {
    const tagTemplate = document.querySelector("#tagTemplate");
    const tagContainer = document.querySelector(".tags-list");
    tags.forEach(tag => {
        const clone = tagTemplate.content.cloneNode(true);
        clone.querySelector(".taxo__text").textContent = tag;
        clone.querySelector(".taxo__link").href = `/pages/tags/tag/?tag=${encodeURIComponent(tag.toLowerCase())}`;
        clone.querySelector(".taxo__num").textContent = posts.filter(post => post.tags.includes(tag)).length;
        tagContainer.appendChild(clone);
    })
}
populateTags();
mobileNavBarActive();