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







// function switchProfile(cardId) {
//     console.log("Switching to: " + cardId);
//     console.debug("2");
    
//     // Mettre à jour la valeur de l'input hidden en fonction du profil sélectionné
//     var inputId = "oidv4vcProfile" + cardId;
//     var inputElement = document.getElementById(inputId);
    
//     if (inputElement) {
//         inputElement.value = cardId;
//         console.debug("recup valeur oidv4vcProfile");
//     } else {
//         console.error("Input element not found for cardId: " + cardId);
//     }

//     // Vérifier si l'élément avec l'ID cardId existe
//     var cardElement = document.getElementById(cardId);
//     if (cardElement) {
//         // Sélectionner la carte correspondante
//         cardElement.classList.add('selected');

//         // Afficher ou masquer le profil personnalisé en fonction du profil sélectionné
//         if (cardId === "Custom") {
//             document.getElementById("customProfileDiv").setAttribute("class", "");
//             console.debug("3");
//         } else {
//             document.getElementById("customProfileDiv").setAttribute("class", "displayNone");
//             console.debug("pas recu 3");
//         }
//     } else {
//         console.error("Card element not found for cardId: " + cardId);
//     }
// }

