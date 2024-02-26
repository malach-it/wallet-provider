// Contenu du fichier afficherEBSI_SSI.js
function afficherEBSI_SSI() {
    const vcFormatElement = document.getElementById('vcFormat');
    const clientAuthenticationElement = document.getElementById('clientAuthentication');
    const credentialManifestSupportTrueElement = document.getElementById('credentialManifestSupportTrue');
    const cryptoHolderBindingTrueElement = document.getElementById('cryptoHolderBindingTrue');
    const defaultDidElement = document.getElementById('defaultDid');
    const oidc4vciDraftElement = document.getElementById('elevenvci');
    const oidc4vpDraftElement = document.getElementById('eighteenvp');
    const scopeFalseElement = document.getElementById('scopeFalse');
    const securityLevelFalseElement = document.getElementById('permissive');
    const siopv2DraftElement = document.getElementById('twelvesiop');
    const subjectSyntaxeTypeElement = document.getElementById('did');
    const userPinDigitsElement = document.getElementById('four');

    // Valeurs EBSI SSI
    vcFormatElement.value = 'jwt_vc';
    clientAuthenticationElement.value = 'client_id';
    credentialManifestSupportTrueElement.checked = false;
    cryptoHolderBindingTrueElement.checked = true;
    defaultDidElement.value = 'did:key:ebsi';
    oidc4vciDraftElement.checked = true;
    oidc4vpDraftElement.checked = true;
    scopeFalseElement.checked = true;
    securityLevelFalseElement.checked = true;
    siopv2DraftElement.checked = true;
    subjectSyntaxeTypeElement.checked = true;
    userPinDigitsElement.checked = true;

    toggleBasicAuthDiv();
}
