import posts from "../../../scripts/posts/posts.js";

const postTemplate = document.querySelector("#postTemplate");
const postContainer = document.querySelector("main");
const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];


const insertPostIntoPage = () => {
    // Get the 'title' parameter from the URL
    const urlParams = new URLSearchParams(window.location.search);
    const title = urlParams.get('title');

    // Find the post with the matching title in the 'posts' array
    const currentPost = posts.find(post => post.title === title);

    const postHTML = currentPost.body;

    // Clone the post template
    const templateClone = postTemplate.content.cloneNode(true);

    // Get references to the elements in the template
    const titleEl = templateClone.querySelector(".title");
    const dateEl = templateClone.querySelector(".date");
    const authorEl = templateClone.querySelector(".author");
    const tagsContainer = templateClone.querySelector(".tags");
    const postImageEl = templateClone.querySelector("img");
    const descriptionEl = templateClone.querySelector(".description");
    const articleEl = templateClone.querySelector("article");

    // Set the content of the elements in the template
    titleEl.textContent = currentPost.title;
    dateEl.textContent = `${months[currentPost.date.getMonth() - 1]} ${currentPost.date.getDay()}, ${currentPost.date.getFullYear()}`;
    authorEl.textContent = currentPost.author;

    // Create and append tag elements to the tags container
    currentPost.tags.forEach(tag => {
        const tagElement = document.createElement("li");
        const tagButton = document.createElement("a");
        tagButton.className = "single-tag";
        tagButton.textContent = tag;
        tagButton.href = `/pages/tags/tag/?tag=${encodeURIComponent(tag.toLowerCase())}`;
        tagElement.appendChild(tagButton);
        tagsContainer.appendChild(tagElement);
    });

    // Set the source and content of the image and description elements
    postImageEl.src = currentPost.previewPicture;
    descriptionEl.textContent = currentPost.description;
    articleEl.innerHTML += postHTML;

    // Append the template clone to the post container
    postContainer.appendChild(templateClone);
}

const mobileNavBarActive = () => {
    const navButton = document.querySelector(".nav-burger");
    const navMenu = document.querySelector(".navbar-hide");
    navButton.addEventListener("click", () => {
        navMenu.className === "navbar-hide" ? navMenu.className = "navbar-display" : navMenu.className = "navbar-hide";
        navButton.className === "nav-burger" ? navButton.className = "nav-burger is-active" : navButton.className = "nav-burger";
    })
}

const insertCopyToClipboardBtn = () => {
    const allPreElements = document.querySelectorAll('pre');

    allPreElements.forEach(preElement => {
        // <i className="fa-solid fa-clipboard"></i>
        const copyToClipboardBtn = document.createElement('i');
        copyToClipboardBtn.className = 'copy-to-clipboard';
        copyToClipboardBtn.className = "fa-solid fa-clipboard copy-to-clipboard";
        preElement.previousElementSibling.appendChild(copyToClipboardBtn);
        copyToClipboardBtn.addEventListener('click', async () => {
            // Get the text content of the pre element
            const textContent = preElement.textContent;
            await navigator.clipboard.writeText(textContent);
            // Show a success message
            //     create a copied to clipboard element
            const copiedToClipboard = document.createElement('span');
            copiedToClipboard.className = 'copied-to-clipboard';
            copiedToClipboard.textContent = 'Copied to clipboard';
            preElement.previousElementSibling.appendChild(copiedToClipboard);
            setTimeout(() => {
                preElement.previousElementSibling.removeChild(copiedToClipboard);
            }, 1000);
        })

    })
}

mobileNavBarActive()
insertPostIntoPage()
insertCopyToClipboardBtn()