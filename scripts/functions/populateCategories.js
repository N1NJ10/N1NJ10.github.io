export const populateCategories = (categories, posts) => {
    const categoryTemplate = document.getElementById("categoryTemplate");
    const categoriesList = document.querySelector(".categories-list");
    categories.forEach(category => {
        const clone = categoryTemplate.content.cloneNode(true);
        clone.querySelector(".taxo__text").textContent = category;
        clone.querySelector(".taxo__num").textContent = posts.filter(post => post.category.toLowerCase() === category.toLowerCase()).length;
        clone.querySelector(".taxo__link").href = `/pages/categories/category/?category=${category.toLowerCase()}`;
        categoriesList.appendChild(clone);
    })
}