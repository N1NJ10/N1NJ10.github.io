const mobileNavBarActive = () => {
    const navButton = document.querySelector(".nav-burger");
    const navMenu = document.querySelector(".navbar-hide");
    navButton.addEventListener("click", () => {
        navMenu.className === "navbar-hide" ? navMenu.className = "navbar-display" : navMenu.className = "navbar-hide";
        navButton.className === "nav-burger" ? navButton.className = "nav-burger is-active" : navButton.className = "nav-burger";
    })
}

export default mobileNavBarActive;