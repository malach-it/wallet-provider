document.addEventListener("DOMContentLoaded", function() {
    var selectElements = document.querySelectorAll('[id^="display"]');
    
    selectElements.forEach(function(selectElement) {
        // Set the initial background color based on the selected option
        updateSelectBackground(selectElement);

        // Add an event listener to handle changes in selection
        selectElement.addEventListener("change", function() {
        updateSelectBackground(this);
        });
    });

    function updateSelectBackground(element) {
        var selectedValue = element.value;

        // Remove existing classes
        element.classList.remove("select-visible", "select-invisible");

        // Add the appropriate class based on the selected option
        if (selectedValue === "displayOver13True" || selectedValue === "displayOver15True" ||
            selectedValue === "displayOver18True" || selectedValue === "displayOver18_2True" ||
            selectedValue === "displayOver21True" || selectedValue === "displayOver50True" ||
            selectedValue === "displayOver65True" || selectedValue === "displayVerifiableIdTrue" ||
            selectedValue === "displayVerifiableId2True" || selectedValue === "displayVerifiableIdSdJwtTrue" ||
            selectedValue === "displayEmailPassTrue" || selectedValue === "displayEmailPassJwtTrue" || 
            selectedValue === "displayPhonePassTrue" || selectedValue === "displayPhonePassJwtTrue"|| 
            selectedValue === "displayDefiTrue" || selectedValue === "displayHumanityTrue" || 
            selectedValue === "displayHumanityJwtTrue"|| selectedValue === "displayAgeRangeTrue" || 
            selectedValue === "displayGenderTrue" || selectedValue === "displayTezotopiaTrue" || 
            selectedValue === "displayChainbornTrue") {
        element.classList.add("select-visible");
        } else if (selectedValue === "displayOver13False" || selectedValue === "displayOver15False" ||
                selectedValue === "displayOver18False" || selectedValue === "displayOver18_2False" ||
                selectedValue === "displayOver21False" || selectedValue === "displayOver50False" ||
                selectedValue === "displayOver65False" || selectedValue === "displayVerifiableIdFalse" ||
                selectedValue === "displayVerifiableId2False" || selectedValue === "displayVerifiableIdSdJwtFalse" ||
                selectedValue === "displayEmailPassFalse" || selectedValue === "displayEmailPassJwtFalse" || 
                selectedValue === "displayPhonePassFalse" || selectedValue === "displayPhonePassJwtFalse"|| 
                selectedValue === "displayDefiFalse" || selectedValue === "displayHumanityFalse" ||
                selectedValue === "displayHumanityJwtFalse" || selectedValue === "displayAgeRangeFalse" ||
                selectedValue === "displayGenderFalse" || selectedValue === "displayTezotopiaFalse" || 
                selectedValue === "displayChainbornFalse") {
        element.classList.add("select-invisible");
        }
    }
    });

    //Copie mail
    function copySpanText() {
        // Get the span element
        var spanText = document.getElementById("mySpan");
                                
        // Create a temporary input element
        var tempInput = document.createElement("input");
                                    
        // Set the value of the temporary input to the text content of the span
        tempInput.value = spanText.textContent;
                                
        // Append the temporary input to the body
        document.body.appendChild(tempInput);
                                
        // Select the text in the temporary input
        tempInput.select();
        tempInput.setSelectionRange(0, 99999); // For mobile devices
                                
        // Copy the text inside the temporary input
        document.execCommand("copy");
                                
        // Remove the temporary input from the DOM
        document.body.removeChild(tempInput);
                                
        // Display a notification (popup) to indicate that the email has been copied
        vNotify.success({ text: 'Email copied!', title: 'Succes', sticky: false });
    }

    //Copie mail external issuer
    function copySpanTextTabExternalIssuer(index) {
        // Get the span element based on the index
        var spanText = document.getElementById("issuerContact" + index);

        // Create a temporary input element
        var tempInput = document.createElement("input");
        
        // Set the value of the temporary input to the text content of the span
        tempInput.value = spanText.textContent;

        // Append the temporary input to the body
        document.body.appendChild(tempInput);

        // Select the text in the temporary input
        tempInput.select();
        tempInput.setSelectionRange(0, 99999); // For mobile devices

        // Copy the text inside the temporary input
        document.execCommand("copy");

        // Remove the temporary input from the DOM
        document.body.removeChild(tempInput);

        // Display a notification (popup) to indicate that the email has been copied
        vNotify.success({ text: 'Email copied!', title: 'Succes', sticky: false });
    }

    var updateIssuer;
    var idIssuer;
    function resetIssuerForm() {
        document.getElementById("titleIssuer").value = ""
        document.getElementById("subtitleIssuer").value = ""
        document.getElementById("categoryIssuer").value = "othersCards"
        document.getElementById("formatIssuer").value = "ldp_vc"
        document.getElementById("descriptionIssuer").value = ""
        document.getElementById("howToGetItIssuer").innerHTML = ""
        document.getElementById("expirationDateIssuer").value = ""
        document.getElementById("nameIssuer").value = ""
        document.getElementById("URLIssuer").value = ""
        document.getElementById("logoIssuer").value = ""
        document.getElementById("textColorIssuer").value = "#ffffff"
        document.getElementById("backgroundURLIssuer").value = ""
        document.getElementById("backgroundColorIssuer").value = "#202ffc"
        // document.getElementById("whyGetThisCardIssuer").value=""
        document.getElementById("websiteIssuer").value=""

    }

    resetIssuerForm()
    function openIssuerPopup(action, id) {

        if (document.getElementById("overlay").getAttribute("class") === "displayNone") {
            document.getElementById("overlay").setAttribute("class", "");
            document.getElementById('issuerPopup').scrollTop = 0;
            if (action === "add") {
                resetForm()
                document.getElementById("backgroundColorIssuer").value = "#202ffc"

                document.getElementById("lastLineButtonPopup").innerHTML = "CREATE VC ISSUER"
                document.getElementById("deleteVCButton").setAttribute("class", "displayNone")
                updateIssuer = "add"
            }
            else if (action === "modify") {
                idIssuer = id
                fetch('/get_issuer_infos/' + id, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }).then(res => {
                    res.json().then(data => {
                        console.log(data)
                        document.getElementById("titleIssuer").value = data.title
                        document.getElementById("subtitleIssuer").value = data.subtitle
                        document.getElementById("categoryIssuer").value = data.category
                        document.getElementById("formatIssuer").value = data.format
                        document.getElementById("descriptionIssuer").value = data.description
                        document.getElementById("howToGetItIssuer").innerHTML = data.howToGetIt
                        document.getElementById("expirationDateIssuer").value = data.expirationDate
                        document.getElementById("nameIssuer").value = data.name
                        document.getElementById("URLIssuer").value = data.url
                        document.getElementById("logoIssuer").value = data.logo_url
                        document.getElementById("textColorIssuer").value = data.text_color
                        document.getElementById("backgroundURLIssuer").value = data.background_url
                        document.getElementById("backgroundColorIssuer").value = data.background_color
                        document.getElementById("privacyIssuer").value = data.privacy

                    })
                })
                document.getElementById("lastLineButtonPopup").innerHTML = "UPDATE VC"
                document.getElementById("deleteVCButton").setAttribute("class", "buttonAltmeInversed")
                updateIssuer = "modify"
            }
        }
        else {
            document.getElementById("overlay").setAttribute("class", "displayNone")
            resetIssuerForm()
        }
    }

    function resetForm(){
        document.getElementById("titleIssuer").value = ""
                        document.getElementById("subtitleIssuer").value = ""
                        document.getElementById("categoryIssuer").value = "othersCards"
                        document.getElementById("formatIssuer").value = "ldp_vc"
                        document.getElementById("descriptionIssuer").value = ""
                        document.getElementById("howToGetItIssuer").innerHTML = ""
                        document.getElementById("expirationDateIssuer").value = ""
                        document.getElementById("nameIssuer").value = ""
                        document.getElementById("URLIssuer").value = ""
                        document.getElementById("logoIssuer").value = ""
                        document.getElementById("textColorIssuer").value = ""
                        document.getElementById("backgroundURLIssuer").value = ""
                        document.getElementById("backgroundColorIssuer").value = ""
                        document.getElementById("privacyIssuer").value = "public"
    }

    function updateIssuerTable() {
        let data = {
            "title": document.getElementById("titleIssuer").value,
            "subtitle": document.getElementById("subtitleIssuer").value,
            "category": document.getElementById("categoryIssuer").value,
            "format": document.getElementById("formatIssuer").value,
            "description": document.getElementById("descriptionIssuer").value,
            "howToGetIt": document.getElementById("howToGetItIssuer").value,
            "expirationDate": document.getElementById("expirationDateIssuer").value,
            "name": document.getElementById("nameIssuer").value,
            "url": document.getElementById("URLIssuer").value,
            "logo_url": document.getElementById("logoIssuer").value,
            "text_color": document.getElementById("textColorIssuer").value,
            "background_url": document.getElementById("backgroundURLIssuer").value,
            "background_color": document.getElementById("backgroundColorIssuer").value,
        }
        if (updateIssuer === "add") {
            fetch('/add_issuer_db', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    privacyIssuer: document.getElementById("privacyIssuer").value,
                    data: data
                })
            })
                .then(response => {
                    console.log(response.status); if (response.status === 200) {

                        let step = searchParams.get("step")

                        if (step === "6") {
                            window.location.reload();
                        }
                        else { window.location.replace("/setup?step=6#addCredential"); }
                    }
                })
                .catch(error => console.error('Error:', error));
        }
        else if (updateIssuer === "modify") {
            fetch('/modify_issuer_db', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    privacyIssuer: document.getElementById("privacyIssuer").value,
                    id: idIssuer,
                    data: data
                })
            })
                .then(response => {
                    console.log(response.status); if (response.status === 200) {

                        let step = searchParams.get("step")

                        if (step === "6") {
                            window.location.reload();
                        }
                        else { window.location.replace("/setup?step=6#addCredential"); }
                    }
                })
                .catch(error => console.error('Error:', error));
        }
    }

    function removeIssuer() {
        fetch('/remove_issuer_db', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: idIssuer,
            })
        })
            .then(response => {
                console.log(response.status); if (response.status === 200) {

                    let step = searchParams.get("step")

                    if (step === "6") {
                        window.location.reload();
                    }
                    else { window.location.replace("/setup?step=6#addCredential"); }
                }
            })
            .catch(error => console.error('Error:', error));
    }

    // function changeStatusExternalIssuer(idIssuer, nameIssuer, selectElement) {
    //     console.log("Change status initiated for issuer " + idIssuer);
        
    //     let newStatus = selectElement.value;
    //     console.log("Setting issuer " + idIssuer + " to " + newStatus);

    //     debugger; 

    //     fetch('/change_issuer_config', {
    //         method: 'POST',
    //         headers: {
    //             'Content-Type': 'application/json'
    //         },
    //         body: JSON.stringify({
    //             id: idIssuer,
    //             newStatus: newStatus
    //         })
    //     })
    //     // debugger;
    //     .then(response => {
    //         console.log("Server response status:", response.status);

    //         // Vérifier si la réponse est OK (200)
    //         if (response.ok) {
    //             return response.json(); // Parse la réponse JSON
    //         } else {
    //             throw new Error('Server response error');
    //         }
    //     })
    //     // debugger;
    //     .then(data => {
    //         console.log("Server response data:", data);
    //         vNotify.info({ text: 'Issuer ' + nameIssuer + " set to " + newStatus, title: 'Info', sticky: true });
    //     })
    //     // debugger;
    //     .catch(error => {
    //         console.error('Error:', error);
    //     });
    // }



    function changeStatusExternalIssuer(idIssuer,nameIssuer) {
        let newStatus = document.getElementById("statusIssuer" + idIssuer).value
        console.log("setting issuer " + idIssuer + " to " + newStatus)

        fetch('/change_issuer_config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: idIssuer,
                newStatus: newStatus
            })
        })
            .then(response => { console.log(response.status);vNotify.info({ text: 'Issuer '+nameIssuer+" set to "+newStatus, title: 'Info', sticky: true }); })
            .catch(error => console.error('Error:', error));
    }

    function modifyIssuer(id, owner) {
        if (owner === "1") {
            console.log("owner")
            openIssuerPopup("modify", id)
        }
        else {
            console.log("not owner")
        }
    }
    {% for row in issuers_availables %}
    document.getElementById("statusIssuer{{row[0]}}").value = {{ row[10] }} === 1 ? "visible" : "invisible"
    document.getElementById('statusIssuer{{row[0]}}').addEventListener('click', function (e) {
        e.stopPropagation(); // Prevent the click event from bubbling up
        // Do other stuff here
    });
    {% endfor %}

    document.getElementById('buttonMenu').addEventListener('click', () => {
        if (document.getElementById('imageButtonMenu').getAttribute("class") === "imgButtonMenuInactive") {
            document.getElementById('menuDiv').setAttribute("class", "flex");
            document.body.style.overflow = 'hidden';
            document.getElementById('imageButtonMenu').setAttribute("class", "imgButtonMenuActive");
            document.getElementById('imageButtonMenu').setAttribute("src", "/static/img/crossMenu.png")
        }
        else if (document.getElementById('imageButtonMenu').getAttribute("class") === "imgButtonMenuActive") {
            document.getElementById('menuDiv').setAttribute("class", "");
            document.body.style.overflow = '';
            document.getElementById('imageButtonMenu').setAttribute("class", "imgButtonMenuInactive");
            document.getElementById('imageButtonMenu').setAttribute("src", "/static/img/div.png")
        }
    })