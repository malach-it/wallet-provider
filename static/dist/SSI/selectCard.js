document.addEventListener("DOMContentLoaded", function() {    
    var oidv4vcProfileElement = document.getElementById("oidv4vcProfile");
    if (oidv4vcProfileElement) {
        var oidv4vcProfile = oidv4vcProfileElement.value;
        console.log("Valeur de oidv4vcProfile :", oidv4vcProfile);

        var selectedCard;
        var checkbox;
        
        // Sélectionner la carte en fonction de la valeur de oidv4vcProfile
        if (oidv4vcProfile === "OWF") {
            selectedCard = document.getElementById("owfSSIButton");
        } else if (oidv4vcProfile === "HAIP") {
            selectedCard = document.getElementById("HAIPSSIButton");
        } else if (oidv4vcProfile === "EBSI") {
            selectedCard = document.getElementById("ebsiSSIButton");
        } else if (oidv4vcProfile === "DIIP") {
            selectedCard = document.getElementById("diipSSIButton");
        } else if (oidv4vcProfile === "Custom") {
            selectedCard = document.getElementById("customSSIButton");
        }
        
        // Si une carte est sélectionnée, ajouter la classe 'selected' et définir le style du bouton
        if (selectedCard) {
            selectedCard.classList.add('selected');
            checkbox = selectedCard.querySelector('.custom-button');
            checkbox.style.backgroundImage = "url('/static/img/Check_Card_SSI.svg')";
        }
    } else {
        console.error("Element not found: oidv4vcProfile");
    }
});


// checkbox sur la carte select fonctionnel 
function selectAndShow(cardId, showFunction) {
    document.querySelectorAll('.custom-card').forEach(card => {
        card.classList.remove('selected');
        var checkbox = card.querySelector('.custom-button');
        checkbox.classList.remove('selected'); 

        checkbox.style.backgroundImage = ""; 
    });

    var selectedCard = document.getElementById(cardId);
    if (selectedCard) {
        selectedCard.classList.add('selected');

        var checkbox = selectedCard.querySelector('.custom-button');
        checkbox.classList.add('selected'); 
        
        checkbox.style.backgroundImage = "url('/static/img/Check_Card_SSI.svg')";
    }

    document.querySelectorAll('.custom-card').forEach(card => {
        card.classList.remove('selected');
    });
    document.getElementById(cardId).classList.add('selected');
    showFunction(); 
}

function switchProfile(cardId) {
    //oidv4vcProfile de la config
    var inputElement = document.getElementById("oidv4vcProfile");
    if (inputElement) {
        inputElement.value = cardId;
        console.debug("SSI select : " + cardId);
    } else {
        console.error("Input element not found for cardId: " + cardId);
    }

    var selectedSSITextElement = document.getElementById("selectedSSIText");
    if (selectedSSITextElement) {
        selectedSSITextElement.innerText = "SSI select : " + cardId;
    } else {
        console.error("Error any SSI selected");
    }
}
