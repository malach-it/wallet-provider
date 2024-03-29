function selectAndShow(cardId, showFunction) {
    console.log('SSI Select : ' + cardId);
    document.querySelectorAll('.custom-card').forEach(card => {
        card.classList.remove('selected');
    });
    document.getElementById(cardId).classList.add('selected');
    showFunction(); 
}

function switchProfile(cardId) {
    console.log("Switching to: " + cardId);
    
    // Mettre à jour la valeur de l'input hidden avec le nom du SSI sélectionné
    var inputElement = document.getElementById("oidv4vcProfile");
    if (inputElement) {
        inputElement.value = cardId;
        console.debug("SSI enregistré : " + cardId);
    } else {
        console.error("Input element not found for cardId: " + cardId);
    }

    // Afficher le nom du SSI sélectionné dans l'élément HTML approprié
    var selectedSSITextElement = document.getElementById("selectedSSIText");
    if (selectedSSITextElement) {
        selectedSSITextElement.innerText = "SSI enregistré : " + cardId;
    } else {
        console.error("Element not found to display selected SSI text");
    }
}
