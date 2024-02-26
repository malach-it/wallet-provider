function toggleBasicAuthDiv() {
    var clientAuthentication = document.getElementById('clientAuthentication');
    var basicAuthDiv = document.getElementById('basicAuthDiv');

    // Cache la zone de texte si la méthode de client sélectionnée est "none", "client_id", ou "wallet attestation"
    basicAuthDiv.style.display = (clientAuthentication.value === "none" || clientAuthentication.value === "client_id" || clientAuthentication.value === "client_secret_jwt") ? "none" : "block";
}

// Ajoute un gestionnaire d'événements au changement de la sélection
document.getElementById('clientAuthentication').addEventListener('change', toggleBasicAuthDiv);

// Appel initial pour garantir que la visibilité est correcte lors du chargement de la page
toggleBasicAuthDiv();