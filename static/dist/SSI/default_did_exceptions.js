document.addEventListener('DOMContentLoaded', function() {
    // Fonction pour mettre à jour les options en 4.11 en fonction de la sélection en 4.3
    function updateOptionsIn4_11() {
        // Récupérer la valeur sélectionnée en 4.3
        var defaultDid = document.getElementById('defaultDid').value;

        // Récupérer l'élément de sélection en 4.11 (format de VC)
        var vcFormatSelect = document.getElementById('vcFormat');

        // Afficher toutes les options en 4.11
        vcFormatSelect.querySelectorAll('option').forEach(function(option) {
            option.style.display = 'block';
        });

        // Appliquer les règles spécifiques en fonction de la sélection en 4.3
        if (defaultDid === 'did:jwk:p-256') {
            // Masquer ldp_vc en 4.11
            vcFormatSelect.querySelector('option[value="ldp_vc"]').style.display = 'none';

        } else if (defaultDid === 'did:key:ebsi') {
            // Masquer certaines options en 4.11
            vcFormatSelect.querySelector('option[value="ldp_vc"]').style.display = 'none';
            vcFormatSelect.querySelector('option[value="jwt_vc_json"]').style.display = 'none';
            vcFormatSelect.querySelector('option[value="jwt_vc_json-ld"]').style.display = 'none';
            vcFormatSelect.querySelector('option[value="vc+sd-jwt"]').style.display = 'none';

        } else if (defaultDid === 'did:key:eddsa') {
            // Masquer certaines options en 4.11
            vcFormatSelect.querySelector('option[value="jwt_vc"]').style.display = 'none';
            vcFormatSelect.querySelector('option[value="jwt_vc_json"]').style.display = 'none';
            vcFormatSelect.querySelector('option[value="jwt_vc_json-ld"]').style.display = 'none';
            vcFormatSelect.querySelector('option[value="vc+sd-jwt"]').style.display = 'none';
        }
    }

    // Ajouter un écouteur d'événement pour détecter les changements en 4.3
    document.getElementById('defaultDid').addEventListener('change', updateOptionsIn4_11);

    // Appeler la fonction pour la première fois au chargement de la page
    updateOptionsIn4_11();
});