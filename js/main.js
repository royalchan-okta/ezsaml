function resizeTextArea(textArea) {
    textArea.css('height', '1px');
    textArea.css('height', (textArea.prop('scrollHeight') + 25) + 'px');
}

function hideAll() {
	$('#hidden_raw_saml').hide();

	$('#urldecode').hide();
	$('#b64decode').hide();
	$('#compression').hide();
	$('#output').hide();
	$('#error').hide();
}

function show(selector, s) {
	$('#' + selector).show();
	$('#' + selector + ' div.value').text(s);
}

function appendOutputParam(name, val) {
	if (name && val) {
	    $('#output_params').append('<div class="param_value"><span class="param_label">' + name + ': </span>' + val + '</div>');
    }
}

var millisInDay = 24 * 60 * 60 * 1000;
var millisInHour = 60 * 60 * 1000;
var millisInMinute = 60 * 1000;
var millisInSecond = 1000;

function getMillisToLargestUnit(millis) {
	if (millis > millisInDay) {
		return (millis / millisInDay).toFixed(2) + " days";
	} else if (millis > millisInHour) {
		return (millis / millisInHour).toFixed(2) + " hours";
	} else if (millis > millisInMinute) {
		return (millis / millisInMinute).toFixed(2) + " minutes";
	} else if (millis > millisInSecond) {
		return (millis / millisInSecond).toFixed(2) + " seconds";
	}
	return millis + " milliseconds";
}

function getDateString(xmlDate) {
	var date = new Date(xmlDate);
	var millis = new Date().getTime() - date.getTime();
	var inThePast = millis > 0;
	if (!inThePast) {
		millis = -millis;
	}

	return xmlDate + " (" + getMillisToLargestUnit(millis) + (inThePast ? " ago" : "remaining") + ")";
}

function output(s) {
	$('#output').show();

	$('#hidden_raw_saml').val(s);
	$('#output_area').val(vkbeautify.xml(s));
	resizeTextArea($('#output_area'));

	$('#output_params').empty();
	parser = new DOMParser();
	xmlDoc = parser.parseFromString(s, "text/xml");

	appendOutputParam("Type", xmlDoc.documentElement.tagName)
	appendOutputParam("ID", xmlDoc.documentElement.getAttribute("ID"));
	appendOutputParam("Issued At", getDateString(xmlDoc.documentElement.getAttribute("IssueInstant")));
	appendOutputParam("Protocol Binding", xmlDoc.documentElement.getAttribute("ProtocolBinding"));
	appendOutputParam("Provider Name", xmlDoc.documentElement.getAttribute("ProviderName"));
	appendOutputParam("ACS URL", xmlDoc.documentElement.getAttribute("AssertionConsumerServiceURL"));
	appendOutputParam("Destination", xmlDoc.documentElement.getAttribute("Destination"));

	var issuerElements = xmlDoc.documentElement.getElementsByTagName('saml:Issuer');
	if (issuerElements.length > 0) {
		appendOutputParam("Issuer", issuerElements[0].innerHTML);
	}
}

function isValidSAML(s) {
	parser = new DOMParser();
	xmlDoc = parser.parseFromString(s, "text/xml");
	if (xmlDoc.getElementsByTagName('parsererror').length > 0) {
		return false;
	}

	var tagName = xmlDoc.documentElement.tagName;

	return tagName.endsWith("AuthnRequest")
		|| tagName.endsWith("Response") 
		|| tagName.endsWith("LogoutRequest")
		|| tagName.endsWith("LogoutResponse");
}

requirejs(["js/vendor/pako"], function(pako) {
    var test = { my: 'super', puper: [456, 567], awesome: 'pako' };

	var binaryString = pako.deflate(JSON.stringify(test), { to: 'string' });

	$('#saml_input').on('keyup paste', _.debounce(function() {
		hideAll();
		//resizeTextArea($("#saml_input"));

	    var input = $("#saml_input").val();
	    
	    var isUrlEncoded = false;
	    try {
		    var decoded = decodeURIComponent(input);
		    while (decoded !== input) {
		    	isUrlEncoded = true;
		    	input = decoded;
		    	decoded = decodeURIComponent(input);
		    }
		} catch (e) {
			// meh
		}
		var urlDecoded;
	    if (isUrlEncoded) {
	    	show('urldecode', input);
	    	urlDecoded = input;
	    }

	    if (isValidSAML(input)) {
	    	output(input);
	    	return;
	    }

	    var base64decoded;
	    try {
	    	base64decoded = atob(input)

	    	// for debug 
	    	//show('b64decode', base64decoded)
	    } catch (e) {
	    	// meh
	    }

	    if (isValidSAML(base64decoded)) {
	    	show('compression', 'No');
	    	output(base64decoded);
	    } else {
	    	try {
	    		var decompressed = pako.inflate(base64decoded, { raw: true, to: 'string' });
	    		if (decompressed) {
		  			output(decompressed);
		  			show('compression', 'Yes');
		  		} else {
		  			//show('error', "Invalid Input:" + e);
		  		}
	  		} catch (e) {
	  			//show('error', "Invalid Input:" + e);
	  		}
	    }
	}, 100));
});

 $(document).ready(function(){
 	hideAll();

 	new Clipboard('.copy-raw', {
      text: function(trigger) {
          return $("#hidden_raw_saml").val();
      }
  	});

  	new Clipboard('.copy-pretty', {
      text: function(trigger) {
          return $("#output_area").val();
      }
  	});

    $("#saml_input").val("fZLLTsMwEEX3SPyD5X1eIARYTVABISrxiGhgwc51JonBj%2BBxGvh73BQELOj2embuueOZnb1rRdbgUFqT0yxOKQEjbC1Nm9PH6io6oWfF%2Ft4MuVY9mw%2B%2BMw%2FwNgB6EjoNsukhp4MzzHKUyAzXgMwLtpzf3rCDOGW9s94KqyhZXOa05Z2QvXjRjVzpprdKqrZruxdjegVKq9dOrGotekqevrEONlgLxAEWBj03Pkhpdhylp1F2VKUZSw9ZevJMSfnldC7NNsEurNW2CNl1VZVReb%2BspgFrWYO7C9UB1dpWQSys3tiXHFGug9xwhUDJHBGcD4AX1uCgwS3BraWAx4ebnHbe98iSZBzH%2BGdMwhPf2aHt%2FGjdK24lgbSY9sumiO7XYncH4N8AtNhpMUt%2BTS%2B%2BvnKTcHFZhvWLDzJXyo4XDrgP8bwbQror6zT3%2FwNkcTYpso6aqZQNBnsQspFQU5IUW9e%2FNxMu6RM%3D");
 });



