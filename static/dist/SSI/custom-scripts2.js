        const url = new URL(document.location);

        const searchParams = url.searchParams;
        let step = searchParams.get("step")
        if (step === "6") {
            goStep6()
        }
        //PART 1
        document.getElementById("{{config["generalOptions"]["walletType"]}}").checked = true
        document.getElementById("profileName").value = "{{config["generalOptions"]["profileName"]}}"
        document.getElementById("companyName").value = "{{config["generalOptions"]["companyName"]}}"
        document.getElementById("splashScreenTitle").value = "{{config["generalOptions"]["splashScreenTitle"]}}"
        document.getElementById("tagLine").value = "{{config["generalOptions"]["tagLine"]}}"

        //PART 2
        document.getElementById("displayProfile{{config["settingsMenu"]["displayProfile"]}}").checked = true
        document.getElementById("displayDeveloperMode{{config["settingsMenu"]["displayDeveloperMode"]}}").checked = true
        document.getElementById("displayHelpCenter{{config["settingsMenu"]["displayHelpCenter"]}}").checked = true
        document.getElementById("displaySelfSovereignIdentity{{config["settingsMenu"]["displaySelfSovereignIdentity"]}}").checked = true

        //PART 3
        document.getElementById("displaySecurityAdvancedSettings{{config["walletSecurityOptions"]["displaySecurityAdvancedSettings"]}}").checked = true
        document.getElementById("verifySecurityIssuerWebsiteIdentity{{config["walletSecurityOptions"]["verifySecurityIssuerWebsiteIdentity"]}}").checked = true
        document.getElementById("confirmSecurityVerifierAccess{{config["walletSecurityOptions"]["confirmSecurityVerifierAccess"]}}").checked = true
        document.getElementById("secureSecurityAuthenticationWithPinCode{{config["walletSecurityOptions"]["secureSecurityAuthenticationWithPinCode"]}}").checked = true

        //PART 4
        document.getElementById("displayManageDecentralizedId{{config["selfSovereignIdentityOptions"]["displayManageDecentralizedId"]}}").checked = true
        //document.getElementById("displaySsiAdvancedSettings{{config["selfSovereignIdentityOptions"]["displaySsiAdvancedSettings"]}}").checked = true
        //document.getElementById("displayVerifiableDataRegistry{{config["selfSovereignIdentityOptions"]["displayVerifiableDataRegistry"]}}").checked = true

        document.getElementById("cryptoHolderBinding{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["cryptoHolderBinding"]}}").checked = true
        document.getElementById("scope{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["scope"]}}").checked = true
        document.getElementById("credentialManifestSupport{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["credentialManifestSupport"]}}").checked = true

        //document.getElementById("oidv4vcProfile").value = "{{config["selfSovereignIdentityOptions"]["oidv4vcProfile"]}}"
        if ("{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["securityLevel"]}}" === "True") {
            document.getElementById("strict").checked = true
        }
        else {
            document.getElementById("permissive").checked = true
        }
        // let userPinDigits = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["userPinDigits"]}}"
        // userPinDigits = userPinDigits === "4" ? "four" : userPinDigits === "6" ? "six" : null
        // document.getElementById(userPinDigits).checked = true
        document.getElementById("defaultDid").value = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["defaultDid"]}}"
        document.getElementById("{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["subjectSyntaxeType"]}}").checked = true

        let oidc4vciDraft = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["oidc4vciDraft"]}}"
        oidc4vciDraft = oidc4vciDraft === "8" ? "eightvci" : oidc4vciDraft === "11" ? "elevenvci" : oidc4vciDraft === "12" ? "twelvevci" : oidc4vciDraft === "13" ? "thirteenvci" : null
        document.getElementById(oidc4vciDraft).checked = true

        let oidc4vpDraft = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["oidc4vpDraft"]}}"
        oidc4vpDraft = oidc4vpDraft === "10" ? "tenvp" : oidc4vpDraft === "18" ? "eighteenvp" : oidc4vpDraft === "13" ? "thirteenvp" : null
        document.getElementById(oidc4vpDraft).checked = true

        let siopv2Draft = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["siopv2Draft"]}}"
        siopv2Draft = siopv2Draft === "12" ? "twelvesiop" : null
        document.getElementById(siopv2Draft).checked = true
        document.getElementById("clientAuthentication").value = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["clientAuthentication"]}}"
        document.getElementById("client_id").value = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["client_id"]}}"
        document.getElementById("client_secret").value = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["client_secret"]}}"
        document.getElementById("vcFormat").value = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["vcFormat"]}}"
        document.getElementById("proofType").value = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["proofType"]}}"
        document.getElementById("proofHeader").value = "{{config["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["proofHeader"]}}"

        //PART 5
        document.getElementById("displayChatSupport{{config["helpCenterOptions"]["displayChatSupport"]}}").checked = true
        document.getElementById("customChatSupport{{config["helpCenterOptions"]["customChatSupport"]}}").checked = true
        document.getElementById("customChatSupportName").value = "{{config["helpCenterOptions"]["customChatSupportName"]}}"
        document.getElementById("customEmail").value = "{{config["helpCenterOptions"]["customEmail"]}}"
        document.getElementById("customEmailSupport{{config["helpCenterOptions"]["customEmailSupport"]}}").checked = true
        document.getElementById("displayEmailSupport{{config["helpCenterOptions"]["displayEmailSupport"]}}").checked = true



        //PART 6
        document.getElementById("displayOver13").value = "displayOver13{{config["discoverCardsOptions"]["displayOver13"]}}"
        document.getElementById("displayOver15").value = "displayOver15{{config["discoverCardsOptions"]["displayOver15"]}}"
        document.getElementById("displayOver18").value = "displayOver18{{config["discoverCardsOptions"]["displayOver18"]}}"
        document.getElementById("displayOver18_2").value = "displayOver18_2{{config["discoverCardsOptions"]["displayOver18Jwt"]}}"
        document.getElementById("displayOver21").value = "displayOver21{{config["discoverCardsOptions"]["displayOver21"]}}"
        document.getElementById("displayOver50").value = "displayOver50{{config["discoverCardsOptions"]["displayOver50"]}}"
        document.getElementById("displayOver65").value = "displayOver65{{config["discoverCardsOptions"]["displayOver65"]}}"
        document.getElementById("displayVerifiableId").value = "displayVerifiableId{{config["discoverCardsOptions"]["displayVerifiableId"]}}"
        document.getElementById("displayVerifiableId2").value = "displayVerifiableId2{{config["discoverCardsOptions"]["displayVerifiableIdJwt"]}}"
        document.getElementById("displayVerifiableIdSdJwt").value = "displayVerifiableIdSdJwt{{config["discoverCardsOptions"]["displayVerifiableIdSdJwt"]}}"
        document.getElementById("displayEmailPass").value = "displayEmailPass{{config["discoverCardsOptions"]["displayEmailPass"]}}"
        document.getElementById("displayEmailPassJwt").value = "displayEmailPassJwt{{config["discoverCardsOptions"]["displayEmailPassJwt"]}}"
        document.getElementById("displayPhonePass").value = "displayPhonePass{{config["discoverCardsOptions"]["displayPhonePass"]}}"
        document.getElementById("displayPhonePassJwt").value = "displayPhonePassJwt{{config["discoverCardsOptions"]["displayPhonePassJwt"]}}"
        document.getElementById("displayDefi").value = "displayDefi{{config["discoverCardsOptions"]["displayDefi"]}}"
        document.getElementById("displayHumanity").value = "displayHumanity{{config["discoverCardsOptions"]["displayHumanity"]}}"
        document.getElementById("displayHumanityJwt").value = "displayHumanityJwt{{config["discoverCardsOptions"]["displayHumanityJwt"]}}"
        document.getElementById("displayGender").value = "displayGender{{config["discoverCardsOptions"]["displayGender"]}}"
        document.getElementById("displayTezotopia").value = "displayTezotopia{{config["discoverCardsOptions"]["displayTezotopia"]}}"
        document.getElementById("displayChainborn").value = "displayChainborn{{config["discoverCardsOptions"]["displayChainborn"]}}"
        // document.getElementById("displayExternalIssuer").value = "displayExternalIssuer{{config["discoverCardsOptions"]["displayExternalIssuer"]}}"
        document.getElementById("displayAgeRange").value = "displayAgeRange{{config["discoverCardsOptions"]["displayAgeRange"]}}"
        document.getElementById("categoryIssuer").value = "othersCards"
        document.getElementById("backgroundColorIssuer").value = "#ffffff"

        //PART 7 
        document.getElementById("isAllowedTrue").checked = {{ config["companySignature"]["isAllowed"] }};



        //switchProfile()
        switchSupportEmail()
        // switchChat()
        function goStep1() {
            document.getElementById("customizeTitle").innerHTML = "Customize your DID Wallet : General"

            document.getElementById("step1Div").setAttribute("class", "stepDiv")
            document.getElementById("step2Div").setAttribute("class", "displayNone")
            document.getElementById("step3Div").setAttribute("class", "displayNone")
            document.getElementById("step4Div").setAttribute("class", "displayNone")
            document.getElementById("step5Div").setAttribute("class", "displayNone")
            document.getElementById("step6Div").setAttribute("class", "displayNone")
            document.getElementById("step7Div").setAttribute("class", "displayNone")
            document.getElementById("title2").setAttribute("class", "boldGreyP")
            document.getElementById("circle2").setAttribute("class", "circleInactive")
            document.getElementById("number2").setAttribute("class", "boldGreyP")
            document.getElementById("title3").setAttribute("class", "boldGreyP")
            document.getElementById("circle3").setAttribute("class", "circleInactive")
            document.getElementById("number3").setAttribute("class", "boldGreyP")
            document.getElementById("title4").setAttribute("class", "boldGreyP")
            document.getElementById("circle4").setAttribute("class", "circleInactive")
            document.getElementById("number4").setAttribute("class", "boldGreyP")
            document.getElementById("title5").setAttribute("class", "boldGreyP")
            document.getElementById("circle5").setAttribute("class", "circleInactive")
            document.getElementById("number5").setAttribute("class", "boldGreyP")
            document.getElementById("title6").setAttribute("class", "boldGreyP")
            document.getElementById("circle6").setAttribute("class", "circleInactive")
            document.getElementById("number6").setAttribute("class", "boldGreyP")
            document.getElementById("title7").setAttribute("class", "boldGreyP")
            document.getElementById("circle7").setAttribute("class", "circleInactive")
            document.getElementById("number7").setAttribute("class", "boldGreyP")
        }

        function goStep2() {
            document.getElementById("step2Div").setAttribute("class", "stepDiv")
            document.getElementById("step1Div").setAttribute("class", "displayNone")
            document.getElementById("step3Div").setAttribute("class", "displayNone")
            document.getElementById("step4Div").setAttribute("class", "displayNone")
            document.getElementById("step5Div").setAttribute("class", "displayNone")
            document.getElementById("step6Div").setAttribute("class", "displayNone")
            document.getElementById("step7Div").setAttribute("class", "displayNone")
            document.getElementById("title2").setAttribute("class", "boldPurpleP")
            document.getElementById("circle2").setAttribute("class", "circleActive")
            document.getElementById("number2").setAttribute("class", "boldWhiteP")
            document.getElementById("title3").setAttribute("class", "boldGreyP")
            document.getElementById("circle3").setAttribute("class", "circleInactive")
            document.getElementById("number3").setAttribute("class", "boldGreyP")
            document.getElementById("title4").setAttribute("class", "boldGreyP")
            document.getElementById("circle4").setAttribute("class", "circleInactive")
            document.getElementById("number4").setAttribute("class", "boldGreyP")
            document.getElementById("title5").setAttribute("class", "boldGreyP")
            document.getElementById("circle5").setAttribute("class", "circleInactive")
            document.getElementById("number5").setAttribute("class", "boldGreyP")
            document.getElementById("title6").setAttribute("class", "boldGreyP")
            document.getElementById("circle6").setAttribute("class", "circleInactive")
            document.getElementById("number6").setAttribute("class", "boldGreyP")
            document.getElementById("title7").setAttribute("class", "boldGreyP")
            document.getElementById("circle7").setAttribute("class", "circleInactive")
            document.getElementById("number7").setAttribute("class", "boldGreyP")
            document.getElementById("customizeTitle").innerHTML = "Customize your DID Wallet : Settings"

        }
        function goNextStep2() {
            if (document.getElementById("altme").checked) {
                document.getElementById("step2Div").setAttribute("class", "displayNone")
                document.getElementById("step3Div").setAttribute("class", "stepDiv")
                document.getElementById("step4Div").setAttribute("class", "displayNone")
                document.getElementById("title3").setAttribute("class", "boldPurpleP")
                document.getElementById("circle3").setAttribute("class", "circleActive")
                document.getElementById("number3").setAttribute("class", "boldWhiteP")
                document.getElementById("customizeTitle").innerHTML = "Customize your DID Wallet : Blockchain"

            }
            else {
                goStep4()
            }
        }
        function goStep3() {

            document.getElementById("step3Div").setAttribute("class", "stepDiv")
            document.getElementById("step1Div").setAttribute("class", "displayNone")
            document.getElementById("step2Div").setAttribute("class", "displayNone")
            document.getElementById("step4Div").setAttribute("class", "displayNone")
            document.getElementById("step5Div").setAttribute("class", "displayNone")
            document.getElementById("step6Div").setAttribute("class", "displayNone")
            document.getElementById("step7Div").setAttribute("class", "displayNone")
            document.getElementById("title2").setAttribute("class", "boldPurpleP")
            document.getElementById("circle2").setAttribute("class", "circleActive")
            document.getElementById("number2").setAttribute("class", "boldWhiteP")
            document.getElementById("title3").setAttribute("class", "boldPurpleP")
            document.getElementById("circle3").setAttribute("class", "circleActive")
            document.getElementById("number3").setAttribute("class", "boldWhiteP")
            document.getElementById("title4").setAttribute("class", "boldGreyP")
            document.getElementById("circle4").setAttribute("class", "circleInactive")
            document.getElementById("number4").setAttribute("class", "boldGreyP")
            document.getElementById("title5").setAttribute("class", "boldGreyP")
            document.getElementById("circle5").setAttribute("class", "circleInactive")
            document.getElementById("number5").setAttribute("class", "boldGreyP")
            document.getElementById("title6").setAttribute("class", "boldGreyP")
            document.getElementById("circle6").setAttribute("class", "circleInactive")
            document.getElementById("number6").setAttribute("class", "boldGreyP")
            document.getElementById("title7").setAttribute("class", "boldGreyP")
            document.getElementById("circle7").setAttribute("class", "circleInactive")
            document.getElementById("number7").setAttribute("class", "boldGreyP")
            document.getElementById("customizeTitle").innerHTML = "Customize your DID Wallet : Blockchain"

        }
        function goStep4() {
            document.getElementById("step4Div").setAttribute("class", "stepDiv")
            document.getElementById("step1Div").setAttribute("class", "displayNone")
            document.getElementById("step2Div").setAttribute("class", "displayNone")
            document.getElementById("step3Div").setAttribute("class", "displayNone")
            document.getElementById("step5Div").setAttribute("class", "displayNone")
            document.getElementById("step6Div").setAttribute("class", "displayNone")
            document.getElementById("step7Div").setAttribute("class", "displayNone")
            document.getElementById("title2").setAttribute("class", "boldPurpleP")
            document.getElementById("circle2").setAttribute("class", "circleActive")
            document.getElementById("number2").setAttribute("class", "boldWhiteP")
            document.getElementById("title3").setAttribute("class", "boldPurpleP")
            document.getElementById("circle3").setAttribute("class", "circleActive")
            document.getElementById("number3").setAttribute("class", "boldWhiteP")
            document.getElementById("title4").setAttribute("class", "boldPurpleP")
            document.getElementById("circle4").setAttribute("class", "circleActive")
            document.getElementById("number4").setAttribute("class", "boldWhiteP")
            document.getElementById("title5").setAttribute("class", "boldGreyP")
            document.getElementById("circle5").setAttribute("class", "circleInactive")
            document.getElementById("number5").setAttribute("class", "boldGreyP")
            document.getElementById("title6").setAttribute("class", "boldGreyP")
            document.getElementById("circle6").setAttribute("class", "circleInactive")
            document.getElementById("number6").setAttribute("class", "boldGreyP")
            document.getElementById("title7").setAttribute("class", "boldGreyP")
            document.getElementById("circle7").setAttribute("class", "circleInactive")
            document.getElementById("number7").setAttribute("class", "boldGreyP")
            document.getElementById("customizeTitle").innerHTML = "Customize your DID Wallet : SSI"

        }
        function goBackStep4() {
            if (document.getElementById("altme").checked) {
                document.getElementById("step2Div").setAttribute("class", "displayNone")
                document.getElementById("step3Div").setAttribute("class", "stepDiv")
                document.getElementById("step4Div").setAttribute("class", "displayNone")
                document.getElementById("title2").setAttribute("class", "boldPurpleP")
                document.getElementById("circle2").setAttribute("class", "circleActive")
                document.getElementById("number2").setAttribute("class", "boldWhiteP")
                document.getElementById("title3").setAttribute("class", "boldPurpleP")
                document.getElementById("circle3").setAttribute("class", "circleActive")
                document.getElementById("number3").setAttribute("class", "boldWhiteP")
                document.getElementById("title4").setAttribute("class", "boldGreyP")
                document.getElementById("circle4").setAttribute("class", "circleInactive")
                document.getElementById("number4").setAttribute("class", "boldGreyP")
                document.getElementById("title5").setAttribute("class", "boldGreyP")
                document.getElementById("circle5").setAttribute("class", "circleInactive")
                document.getElementById("number5").setAttribute("class", "boldGreyP")
                document.getElementById("title6").setAttribute("class", "boldGreyP")
                document.getElementById("circle6").setAttribute("class", "circleInactive")
                document.getElementById("number6").setAttribute("class", "boldGreyP")
                document.getElementById("title7").setAttribute("class", "boldGreyP")
                document.getElementById("circle7").setAttribute("class", "circleInactive")
                document.getElementById("number7").setAttribute("class", "boldGreyP")
                document.getElementById("customizeTitle").innerHTML = "Customize your DID Wallet : Blockchain"

            }
            else {
                goStep2()
            }
        }
        function goStep5() {
            document.getElementById("step5Div").setAttribute("class", "stepDiv")
            document.getElementById("step1Div").setAttribute("class", "displayNone")
            document.getElementById("step2Div").setAttribute("class", "displayNone")
            document.getElementById("step3Div").setAttribute("class", "displayNone")
            document.getElementById("step4Div").setAttribute("class", "displayNone")
            document.getElementById("step6Div").setAttribute("class", "displayNone")
            document.getElementById("step7Div").setAttribute("class", "displayNone")
            document.getElementById("title2").setAttribute("class", "boldPurpleP")
            document.getElementById("circle2").setAttribute("class", "circleActive")
            document.getElementById("number2").setAttribute("class", "boldWhiteP")
            document.getElementById("title3").setAttribute("class", "boldPurpleP")
            document.getElementById("circle3").setAttribute("class", "circleActive")
            document.getElementById("number3").setAttribute("class", "boldWhiteP")
            document.getElementById("title4").setAttribute("class", "boldPurpleP")
            document.getElementById("circle4").setAttribute("class", "circleActive")
            document.getElementById("number4").setAttribute("class", "boldWhiteP")
            document.getElementById("title5").setAttribute("class", "boldPurpleP")
            document.getElementById("circle5").setAttribute("class", "circleActive")
            document.getElementById("number5").setAttribute("class", "boldWhiteP")
            document.getElementById("title6").setAttribute("class", "boldGreyP")
            document.getElementById("circle6").setAttribute("class", "circleInactive")
            document.getElementById("number6").setAttribute("class", "boldGreyP")
            document.getElementById("title7").setAttribute("class", "boldGreyP")
            document.getElementById("circle7").setAttribute("class", "circleInactive")
            document.getElementById("number7").setAttribute("class", "boldGreyP")
            document.getElementById("customizeTitle").innerHTML = "Customize your DID Wallet : Support"

        }
        function goStep6() {
            document.getElementById("step6Div").setAttribute("class", "stepDiv")
            document.getElementById("step1Div").setAttribute("class", "displayNone")
            document.getElementById("step2Div").setAttribute("class", "displayNone")
            document.getElementById("step3Div").setAttribute("class", "displayNone")
            document.getElementById("step5Div").setAttribute("class", "displayNone")
            document.getElementById("step4Div").setAttribute("class", "displayNone")
            document.getElementById("step7Div").setAttribute("class", "displayNone")
            document.getElementById("title2").setAttribute("class", "boldPurpleP")
            document.getElementById("circle2").setAttribute("class", "circleActive")
            document.getElementById("number2").setAttribute("class", "boldWhiteP")
            document.getElementById("title3").setAttribute("class", "boldPurpleP")
            document.getElementById("circle3").setAttribute("class", "circleActive")
            document.getElementById("number3").setAttribute("class", "boldWhiteP")
            document.getElementById("title4").setAttribute("class", "boldPurpleP")
            document.getElementById("circle4").setAttribute("class", "circleActive")
            document.getElementById("number4").setAttribute("class", "boldWhiteP")
            document.getElementById("title5").setAttribute("class", "boldPurpleP")
            document.getElementById("circle5").setAttribute("class", "circleActive")
            document.getElementById("number5").setAttribute("class", "boldWhiteP")
            document.getElementById("title6").setAttribute("class", "boldPurpleP")
            document.getElementById("circle6").setAttribute("class", "circleActive")
            document.getElementById("number6").setAttribute("class", "boldWhiteP")
            document.getElementById("title7").setAttribute("class", "boldGreyP")
            document.getElementById("circle7").setAttribute("class", "circleInactive")
            document.getElementById("number7").setAttribute("class", "boldGreyP")
            document.getElementById("customizeTitle").innerHTML = "Customize your DID Wallet : Issuer marketplace"

        }

        function goStep7() {
            document.getElementById("step7Div").setAttribute("class", "stepDiv")
            document.getElementById("step6Div").setAttribute("class", "displayNone")
            document.getElementById("step1Div").setAttribute("class", "displayNone")
            document.getElementById("step2Div").setAttribute("class", "displayNone")
            document.getElementById("step3Div").setAttribute("class", "displayNone")
            document.getElementById("step5Div").setAttribute("class", "displayNone")
            document.getElementById("step4Div").setAttribute("class", "displayNone")
            document.getElementById("title2").setAttribute("class", "boldPurpleP")
            document.getElementById("circle2").setAttribute("class", "circleActive")
            document.getElementById("number2").setAttribute("class", "boldWhiteP")
            document.getElementById("title3").setAttribute("class", "boldPurpleP")
            document.getElementById("circle3").setAttribute("class", "circleActive")
            document.getElementById("number3").setAttribute("class", "boldWhiteP")
            document.getElementById("title4").setAttribute("class", "boldPurpleP")
            document.getElementById("circle4").setAttribute("class", "circleActive")
            document.getElementById("number4").setAttribute("class", "boldWhiteP")
            document.getElementById("title5").setAttribute("class", "boldPurpleP")
            document.getElementById("circle5").setAttribute("class", "circleActive")
            document.getElementById("number5").setAttribute("class", "boldWhiteP")
            document.getElementById("title6").setAttribute("class", "boldPurpleP")
            document.getElementById("circle6").setAttribute("class", "circleActive")
            document.getElementById("number6").setAttribute("class", "boldWhiteP")
            document.getElementById("title7").setAttribute("class", "boldPurpleP")
            document.getElementById("circle7").setAttribute("class", "circleActive")
            document.getElementById("number7").setAttribute("class", "boldWhiteP")
            document.getElementById("customizeTitle").innerHTML = "Customize your DID Wallet : Signature"

        }

        function switchTzproRpcNode() {
            if (document.getElementById("tzproRpcNode").checked) {

                document.getElementById("tzproApiKeyDiv").setAttribute("class", "optionDiv")
            }
            else {

                document.getElementById("tzproApiKeyDiv").setAttribute("class", "displayNone")
            }
        }
        function switchInfuraRpcNode() {
            if (document.getElementById("infuraRpcNode").checked) {

                document.getElementById("infuraApiKeyDiv").setAttribute("class", "optionDiv")
            }
            else {

                document.getElementById("infuraApiKeyDiv").setAttribute("class", "displayNone")
            }
        }
        function switchProfile() {
            console.log("switching to " + document.getElementById("oidv4vcProfile").value)
            if (document.getElementById("oidv4vcProfile").value === "custom") {
                document.getElementById("customProfileDiv").setAttribute("class", "")
            }
            else {
                document.getElementById("customProfileDiv").setAttribute("class", "displayNone")
            }
        }

        function switchSupportEmail() {
            if (document.getElementById("customEmailSupportTrue").checked === true) {
                document.getElementById("customEmailDiv").setAttribute("class", "optionDiv")
            } else {
                document.getElementById("customEmailDiv").setAttribute("class", "displayNone")

            }
        }
        function switchChat() {
            if (document.getElementById("customChatSupportTrue").checked === true) {
                document.getElementById("customChatDiv").setAttribute("class", "optionDiv")
            } else {
                document.getElementById("customChatDiv").setAttribute("class", "displayNone")

            }
        }
        function generateRandomString(length) {
            const characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            let result = '';
            for (let i = 0; i < length; i++) {
                result += characters.charAt(Math.floor(Math.random() * characters.length));
            }
            return result;
        }
        function generateCredentials() {
            document.getElementById("client_id").value = "urn:" + generateRandomString(12)
            document.getElementById("client_secret").value = generateRandomString(12)
        }
        function previewImage(event) {
            var preview = document.getElementById('preview');
            preview.src = URL.createObjectURL(event.target.files[0]);
        }
        function switchSignature() {
            if (document.getElementById("CustomSignaturetrue").checked === true) {
                document.getElementById("customSignatureDiv").setAttribute("class", "optionDiv")
            } else {
                document.getElementById("customSignatureDiv").setAttribute("class", "displayNone")

            }
        }
