function afficherHAIP_SSI() {
    const vcFormatElement = document.getElementById('vcFormat');
    const clientAuthenticationElement = document.getElementById('clientAuthentication');
    const credentialManifestSupportTrueElement = document.getElementById('credentialManifestSupportTrue');
    const cryptoHolderBindingTrueElement = document.getElementById('cryptoHolderBindingTrue');
    const defaultDidElement = document.getElementById('defaultDid');
    const oidc4vciDraftElement = document.getElementById('thirteenvci');
    const oidc4vpDraftElement = document.getElementById('twentyvp');
    const scopeTrueElement = document.getElementById('scopeTrue');
    const securityLevelFalseElement = document.getElementById('permissive');
    const siopv2DraftElement = document.getElementById('twelvesiop');
    const subjectSyntaxeTypeElement = document.getElementById('did');
    const userPinDigitsElement = document.getElementById('four');
    const ProofheaderElement = document.getElementById('kid');
    const PARElement = document.getElementById('Yes');

    // Valeurs HAIP_SSI
    vcFormatElement.value = 'vc+sd-jwt';
    clientAuthenticationElement.value = 'client_secret_jwt';
    credentialManifestSupportTrueElement.checked = false;
    cryptoHolderBindingTrueElement.checked = true;
    defaultDidElement.value = 'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation';
    oidc4vciDraftElement.checked = true;
    oidc4vpDraftElement.checked = true;
    scopeTrueElement.checked = true;
    securityLevelFalseElement.checked = true;
    siopv2DraftElement.checked = true;
    subjectSyntaxeTypeElement.checked = true;
    userPinDigitsElement.checked = true;
    ProofheaderElement.value = 'kid';
    PARElement.value = true;
    statusListCacheElement.checked = true;
    
    toggleBasicAuthDiv();
}
