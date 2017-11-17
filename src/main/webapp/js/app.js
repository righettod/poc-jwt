
/* Handle request for JWT token and local storage*/
function getToken(){
    var login = $("#login").val();
    var postData = "login=" + encodeURIComponent(login) + "&password=test";

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

/* Handle request for JWT token revocation (logout) */
function revokeToken(){
var token = sessionStorage.getItem("token");

    if(token == undefined || token == ""){
        $("#infoZone").removeClass();
        $("#infoZone").addClass("alert alert-warning");
        $("#infoZone").text("Obtain a JWT token first :)");
        return;
    }

    $.ajax({
        url: "/services/revoke",
        type: "POST",
        beforeSend: function(xhr) {
            xhr.setRequestHeader("Authorization", "bearer " + token);
        },
        success: function(data) {
            if (data.status.startsWith("Token successfully revoked")) {
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
    $( "#revokeAction" ).click(function() {
      revokeToken();
    });
});