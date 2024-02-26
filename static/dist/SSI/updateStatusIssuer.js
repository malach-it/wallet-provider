document.addEventListener('DOMContentLoaded', function () {
    var selectElement = document.getElementById('statusIssuer{{ row[0] }}');
    var selectedValue = selectElement.value;

    // Supprime les classes existantes
    selectElement.classList.remove('select-invisible', 'select-visible');

    // Ajoute la classe en fonction de la valeur sélectionnée
    selectElement.classList.add('select-' + selectedValue);
});

document.getElementById('statusIssuer{{ row[0] }}').addEventListener('change', function() {
    var selectElement = this;
    var selectedValue = selectElement.value;

    // Supprime les classes existantes
    selectElement.classList.remove('select-invisible', 'select-visible');

    // Ajoute la classe en fonction de la valeur sélectionnée
    selectElement.classList.add('select-' + selectedValue);
});