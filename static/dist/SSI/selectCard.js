function selectAndShow(cardId, showFunction) {
    console.log('SSI Select : ' + cardId);
    deselectAllCards();
    document.getElementById(cardId).classList.add('selected');
    showFunction();
}

function deselectAllCards() {
    console.log('Désélection de toutes les cartes.');
    document.querySelectorAll('.custom-card').forEach(card => {
        card.classList.remove('selected');
    });
}