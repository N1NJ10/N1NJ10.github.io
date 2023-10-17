export const populatePagination = (posts, currentPage, tagFilter = null) => {
    const paginationContainer = document.querySelector(".main-posts");
    const totalPages = Math.ceil(posts.length / 8);
    const paginationEl = document.createElement('ul');
    paginationEl.className = "pagination";

    if (totalPages <= 1) {
        return;
    }

    if (totalPages > 6) {
        if (currentPage <= 2) {
            for (let i = 1; i <= 3; i++) {
                paginationEl.innerHTML += `<li ${currentPage === i ? 'class="active"' : ''}><a href="${tagFilter ? `?tag=${tagFilter}&` : '?'}page=${i}">${i}</a></li>`;
            }
            paginationEl.innerHTML += `<li class="disabled">...</li>`;
            paginationEl.innerHTML += `<li><a href="${tagFilter ? `?tag=${tagFilter}&` : '?'}page=${totalPages}">${totalPages}</a></li>`;
        } else if (currentPage > totalPages - 2) {
            paginationEl.innerHTML += `<li><a href="${tagFilter ? `?tag=${tagFilter}&` : '?'}page=1">1</a></li>`;
            paginationEl.innerHTML += `<li class="disabled">...</li>`;
            for (let i = totalPages - 3; i <= totalPages; i++) {
                paginationEl.innerHTML += `<li ${currentPage === i ? 'class="active"' : ''}><a href="${tagFilter ? `?tag=${tagFilter}&` : '?'}page=${i}">${i}</a></li>`;
            }
        } else {
            paginationEl.innerHTML += `<li><a href="${tagFilter ? `?tag=${tagFilter}&` : '?'}page=1">1</a></li>`;
            paginationEl.innerHTML += `<li class="disabled">...</li>`;
            for (let i = currentPage - 1; i <= currentPage + 1; i++) {
                paginationEl.innerHTML += `<li ${currentPage === i ? 'class="active"' : ''}><a href="${tagFilter ? `?tag=${tagFilter}&` : '?'}page=${i}">${i}</a></li>`;
            }
            paginationEl.innerHTML += `<li class="disabled">...</li>`;
            paginationEl.innerHTML += `<li><a href="${tagFilter ? `?tag=${tagFilter}&` : '?'}page=${totalPages}">${totalPages}</a></li>`;
        }
    } else {
        for (let i = 1; i <= totalPages; i++) {
            paginationEl.innerHTML += `<li ${currentPage === i ? 'class="active"' : ''}><a href="${tagFilter ? `?tag=${tagFilter}&` : '?'}page=${i}">${i}</a></li>`;
        }
    }

    paginationContainer.appendChild(paginationEl);
};

export const populatePaginationWithCategories = (posts, currentPage, categoryFilter) => {
    const paginationContainer = document.querySelector(".main-posts");
    const totalPages = Math.ceil(posts.length / 8);
    const paginationEl = document.createElement('ul');
    paginationEl.className = "pagination";

    if (totalPages <= 1) {
        return;
    }

    if (totalPages > 6) {
        if (currentPage <= 2) {
            for (let i = 1; i <= 3; i++) {
                paginationEl.innerHTML += `<li ${currentPage === i ? 'class="active"' : ''}><a href="${categoryFilter ? `?category=${categoryFilter}&` : '?'}page=${i}">${i}</a></li>`;
            }
            paginationEl.innerHTML += `<li class="disabled">...</li>`;
            paginationEl.innerHTML += `<li><a href="${categoryFilter ? `?category=${categoryFilter}&` : '?'}page=${totalPages}">${totalPages}</a></li>`;
        } else if (currentPage > totalPages - 2) {
            paginationEl.innerHTML += `<li><a href="${categoryFilter ? `?category=${categoryFilter}&` : '?'}page=1">1</a></li>`;
            paginationEl.innerHTML += `<li class="disabled">...</li>`;
            for (let i = totalPages - 3; i <= totalPages; i++) {
                paginationEl.innerHTML += `<li ${currentPage === i ? 'class="active"' : ''}><a href="${categoryFilter ? `?category=${categoryFilter}&` : '?'}page=${i}">${i}</a></li>`;
            }
        } else {
            paginationEl.innerHTML += `<li><a href="${categoryFilter ? `?category=${categoryFilter}&` : '?'}page=1">1</a></li>`;
            paginationEl.innerHTML += `<li class="disabled">...</li>`;
            for (let i = currentPage - 1; i <= currentPage + 1; i++) {
                paginationEl.innerHTML += `<li ${currentPage === i ? 'class="active"' : ''}><a href="${categoryFilter ? `?category=${categoryFilter}&` : '?'}page=${i}">${i}</a></li>`;
            }
            paginationEl.innerHTML += `<li class="disabled">...</li>`;
            paginationEl.innerHTML += `<li><a href="${categoryFilter ? `?category=${categoryFilter}&` : '?'}page=${totalPages}">${totalPages}</a></li>`;
        }
    } else {
        for (let i = 1; i <= totalPages; i++) {
            paginationEl.innerHTML += `<li ${currentPage === i ? 'class="active"' : ''}><a href="${categoryFilter ? `?category=${categoryFilter}&` : '?'}page=${i}">${i}</a></li>`;
        }
    }

    paginationContainer.appendChild(paginationEl);
};
