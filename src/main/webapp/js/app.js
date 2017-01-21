
/* Generate a fingerprint string for the browser */
function generateFingerprint(){
    //Generate a string based on "stable" information taken from the browser
    //We call here "stable information", information that normally don't change during the user browse the application just after authentication
    var fingerprint = [];

    //Take plugins
    for(var i = 0; i < navigator.plugins.length; i++){
       fingerprint.push(navigator.plugins[i].name);
       fingerprint.push(navigator.plugins[i].filename);
       fingerprint.push(navigator.plugins[i].description);
       fingerprint.push(navigator.plugins[i].version);
    }

    //Take User Agent
    fingerprint.push(navigator.userAgent);

    //Take Screen resolution
    fingerprint.push(screen.availHeight);
    fingerprint.push(screen.availWidth);
    fingerprint.push(screen.colorDepth);
    fingerprint.push(screen.height);
    fingerprint.push(screen.pixelDepth);
    fingerprint.push(screen.width);

    //Take Graphical card info
    //See http://output.jsbin.com/ovekor/3/
    try {
        //Add a Canvas element if the body do not contains one
        if ( $("#glcanvas").length == 0 ){
            $(document.body).append("<canvas id='glcanvas'></canvas>");
        }
        //Get ref on Canvas
        var canvas = document.getElementById("glcanvas");
        //Retrieve Canvas properties
	    gl = canvas.getContext("experimental-webgl");
	    gl.viewportWidth = canvas.width;
	    gl.viewportHeight = canvas.height;
        fingerprint.push(gl.getParameter(gl.VERSION));
        fingerprint.push(gl.getParameter(gl.SHADING_LANGUAGE_VERSION));
        fingerprint.push(gl.getParameter(gl.VENDOR));
        fingerprint.push(gl.getParameter(gl.RENDERER));
        fingerprint.push(gl.getSupportedExtensions().join());
    } catch (e) {
        //Get also error because it's will be stable too..
        fingerprint.push(e);
    }

    //Last and, in order to made this browser unique, generate a random ID that we will store
    //in local storage (in order to be persistent after browser close/reopen)
    //Add this ID because, in Enterprise, most of the time browser have the same configuration
    var browserUniqueID = localStorage.getItem("browserUniqueID");
    if (browserUniqueID === null) {
      localStorage.setItem("browserUniqueID", CryptoJS.lib.WordArray.random(80));
      browserUniqueID = localStorage.getItem("browserUniqueID");
    }
    fingerprint.push(browserUniqueID);

    return fingerprint.join();
}

/* Handle request for JWT token and local storage*/
function getToken(){
    var login = $("#login").val();
    var fingerprint = generateFingerprint();
    var fingerprintHash = CryptoJS.SHA256(fingerprint);
    var postData = "login=" + encodeURIComponent(login) + "&password=test&browserFingerprintDigest=" + encodeURIComponent(fingerprintHash);

    $.post("/services/authenticate", postData,function (data){
        if(data.status == "Authentication successful !"){
            $("#infoZone").removeClass();
            $("#infoZone").addClass("alert alert-success");
            $("#infoZone").text("Token received and stored in session storage !");
            sessionStorage.setItem("token", data.token);
        }else{
            $("#infoZone").removeClass();
            $("#infoZone").addClass("alert alert-warning");
            $("#infoZone").text(data.status);
            sessionStorage.removeItem("token");
        }
    })
    .fail(function(jqXHR, textStatus, error){
        $("#infoZone").removeClass();
        $("#infoZone").addClass("alert alert-danger");
        $("#infoZone").text(error);
        sessionStorage.removeItem("token");
    });
}

/* Handle request for JWT token validation */
function validateToken(){
    var token = sessionStorage.getItem("token");
    var fingerprint = generateFingerprint();
    var fingerprintHash = CryptoJS.SHA256(fingerprint);
    var postData = "browserFingerprintDigest=" + encodeURIComponent(fingerprintHash);

    if(token == undefined || token == ""){
        $("#infoZone").removeClass();
        $("#infoZone").addClass("alert alert-warning");
        $("#infoZone").text("Obtain a JWT token first :)");
        return;
    }

    $.ajax({
        url: "/services/validate",
        type: "POST",
        beforeSend: function(xhr) {
            xhr.setRequestHeader("Authorization", "bearer " + token);
        },
        data: postData,
        success: function(data) {
            if (data.status.startsWith("Token OK")) {
                $("#infoZone").removeClass();
                $("#infoZone").addClass("alert alert-success");
                $("#infoZone").text(data.status);
            } else {
                $("#infoZone").removeClass();
                $("#infoZone").addClass("alert alert-warning");
                $("#infoZone").text(data.status);
            }
        },
        error: function(jqXHR, textStatus, error) {
            $("#infoZone").removeClass();
            $("#infoZone").addClass("alert alert-danger");
            $("#infoZone").text(error);
        },
    });
}

/* Handle events wiring */
$( document ).ready(function() {
    $( "#authAction" ).click(function() {
      getToken();
    });
    $( "#valAction" ).click(function() {
      validateToken();
    });
});