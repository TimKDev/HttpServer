console.log("Hello JS.");

fetch("/albums")
    .then(response => response.json())
    .then(albums => {
        let dataDiv = document.getElementById("dataDiv");
        albums.forEach(album => {
            dataDiv.appendChild(createAlbumDiv(album.ID, album.Title, album.Artist, album.Price));
        });
    });

function createAlbumDiv(id, title, artist, price) {
    const albumDiv = document.createElement("div");
    albumDiv.innerHTML = `        
    <div>           
        <p><b>Id:</b> ${id}</p>
        <p><b>Title:</b> ${title}</p>
        <p><b>Artist:</b> ${artist}</p>
        <p><b>Price:</b> ${price}€</p>
    </div>
    `;
    return albumDiv;
}