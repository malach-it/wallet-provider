function afficherOWF_SSI() {
    const vcFormatElement = document.getElementById('vcFormat');
    const clientAuthenticationElement = document.getElementById('clientAuthentication');
    const credentialManifestSupportTrueElement = document.getElementById('credentialManifestSupportTrue');
    const cryptoHolderBindingTrueElement = document.getElementById('cryptoHolderBindingTrue');
    const defaultDidElement = document.getElementById('defaultDid');
    const oidc4vciDraftElement = document.getElementById('thirteenvci');
    const oidc4vpDraftElement = document.getElementById('twentyvp');
    const scopeFalseElement = document.getElementById('scopeFalse');
    const securityLevelFalseElement = document.getElementById('permissive');
    const siopv2DraftElement = document.getElementById('twelvesiop');
    const subjectSyntaxeTypeElement = document.getElementById('did');
    const userPinDigitsElement = document.getElementById('four');

    // Valeurs OWF_SSI
    const ssiOptions = {
        "vcFormat": "vc+sd-jwt",
        "proofHeader": "kid",
        "clientAuthentication": "client_id",
        "client_id": "None",
        "client_secret": "None",
        "credentialManifestSupport": false,
        "cryptoHolderBinding": true,
        "defaultDid": "did:jwk:p-256",
        "oidc4vciDraft": "13",
        "oidc4vpDraft": "18",
        "scope": false,
        "securityLevel": false,
        "siopv2Draft": "12",
        "subjectSyntaxeType": "did",
        "userPinDigits": "4",
    };

    vcFormatElement.value = ssiOptions.vcFormat;
    proofHeaderElement.value = ssiOptions.proofHeader;
    clientAuthenticationElement.value = ssiOptions.clientAuthentication;
    credentialManifestSupportTrueElement.checked = ssiOptions.credentialManifestSupport;
    cryptoHolderBindingTrueElement.checked = ssiOptions.cryptoHolderBinding;
    defaultDidElement.value = ssiOptions.defaultDid;
    oidc4vciDraftElement.checked = ssiOptions.oidc4vciDraft === "13";
    oidc4vpDraftElement.checked = ssiOptions.oidc4vpDraft === "18";
    scopeFalseElement.checked = !ssiOptions.scope;
    securityLevelFalseElement.checked = !ssiOptions.securityLevel;
    siopv2DraftElement.checked = ssiOptions.siopv2Draft === "12";
    subjectSyntaxeTypeElement.checked = ssiOptions.subjectSyntaxeType === "did";
    userPinDigitsElement.checked = ssiOptions.userPinDigits === "4";
    statusListCacheElement.checked = true;

    toggleBasicAuthDiv();
}