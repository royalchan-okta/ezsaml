function resizeTextArea(textArea) {
    textArea.css('height', '1px');
    textArea.css('height', (textArea.prop('scrollHeight') + 25) + 'px');
}

function hideAll() {
	$('#hidden_raw_saml').hide();
	$('#message').hide();
	$('#urldecode').hide();
	$('#b64decode').hide();
	$('#compression').hide();
	$('#output').hide();
	$('#relay_state').hide();
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

function appendMessageParam(name, val) {
	if (name && val) {
	    $('#message_params').append('<div class="param_value"><span class="param_label">' + name + ': </span>' + val + '</div>');
    }
}

function appendAssertionParam(assertionNode) {
	if (assertionNode && assertionNode.length > 0) {
		var html = '<div class="param_value">' + 
	    	'<div class="param_label">Assertion</div><div id="assertion_params">';

	    $.each($('saml\\:Conditions', assertionNode).get(), function (key, conditionNode) {
	    	if (conditionNode.getAttribute('NotBefore')) {
	    		html += '<div class="assertion_param"><span class="assertion_param_label">NotBefore: </span>' + getDateString(conditionNode.getAttribute('NotBefore')) + '</div>'
	    	}
	    	if (conditionNode.getAttribute('NotOnOrAfter')) {
	    		html += '<div class="assertion_param"><span class="assertion_param_label">NotOnOrAfter: </span>' + getDateString(conditionNode.getAttribute('NotOnOrAfter')) + '</div>'
	    	} 
	    });

	    $.each($('saml\\:AuthnStatement', assertionNode).get(), function (key, authnNode) {
	    	if (authnNode.getAttribute('AuthnInstant')) {
	    		html += '<div class="assertion_param"><span class="assertion_param_label">AuthnInstant: </span>' + getDateString(authnNode.getAttribute('AuthnInstant')) + '</div>'
	    	}
	    	if (authnNode.getAttribute('SessionNotOnOrAfter')) {
	    		html += '<div class="assertion_param"><span class="assertion_param_label">SessionNotOnOrAfter: </span>' + getDateString(authnNode.getAttribute('SessionNotOnOrAfter')) + '</div>'
	    	} 
	    });

	    html += '<div class="assertion_param"><span class="assertion_param_label">Attributes: </span>';
	    $.each($('saml\\:Attribute', assertionNode).get(), function (key, attrNode) {
	    	if (attrNode.getAttribute('Name')) {
	    		html += '<div class="assertion_param_attrs"><span class="assertion_param_label">' + attrNode.getAttribute('Name') + ': </span>';
	    		$.each($('saml\\:AttributeValue', attrNode).get(), function (key, valueNode) {
	    			html += valueNode.innerHTML + '<br>';
	    		});
	    		html += '</div>';
	    	}
	    });
	    html += '</div>';

	    html += '</div></div>';
	    $('#output_params').append(html);
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

	return xmlDate + " (" + getMillisToLargestUnit(millis) + (inThePast ? " ago" : " remaining") + ")";
}

function output(s) {
	$('#output').show();

	$('#hidden_raw_saml').val(s);
	$('#output_area').val(vkbeautify.xml(s));
	resizeTextArea($('#output_area'));

	$('#output_params').empty();
	parser = new DOMParser();
	xmlDoc = parser.parseFromString(s, "text/xml");

	appendOutputParam("Type", xmlDoc.documentElement.tagName.split(":")[1])
	appendOutputParam("ID", xmlDoc.documentElement.getAttribute("ID"));
	appendOutputParam("InResponseTo", xmlDoc.documentElement.getAttribute("InResponseTo"));
	appendOutputParam("Issued At", getDateString(xmlDoc.documentElement.getAttribute("IssueInstant")));

	if (xmlDoc.documentElement.getAttribute("ProtocolBinding")) {
		var bindingArray = xmlDoc.documentElement.getAttribute("ProtocolBinding").split(':');
		appendOutputParam("Protocol Binding", bindingArray[bindingArray.length - 1]);
	}
	
	appendOutputParam("Provider Name", xmlDoc.documentElement.getAttribute("ProviderName"));
	appendOutputParam("ACS URL", xmlDoc.documentElement.getAttribute("AssertionConsumerServiceURL"));
	appendOutputParam("Destination", xmlDoc.documentElement.getAttribute("Destination"));

	var issuerElements = xmlDoc.documentElement.getElementsByTagName('saml:Issuer');
	if (issuerElements.length > 0) {
		appendOutputParam("Issuer", issuerElements[0].innerHTML);
	}

	appendAssertionParam($('saml\\:Assertion', xmlDoc));
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

function tryParseQueryParams(s, msg, orgParams) {
	if (orgParams == null) {
		orgParams = {};
	}

	var split = s.split('?');
	if (split.length != 2) {
		return;
	}

	var appRegex = new RegExp('/app/[^/]+/[^/]+/');
	var match = appRegex.exec(s);
	if (match) {
		var components = match[0].split('/')
		orgParams
		orgParams["App Name"] = components[2];
		orgParams["App External Id"] = components[3];
	}

	var orgRegex = new RegExp('[a-zA-Z0-9]+.(okta|okta1|oktapreview).com');
	match = orgRegex.exec(s);
	if (match) {
		orgParams["Org Domain"] = match[0];
	}

	var ret = { 'message': msg };
	var params = split[1].split('&');
	for (var i = 0; i < params.length; ++i) {
		var paramPair = params[i].split('=');
		if (paramPair.length != 2) {
			continue;
		}

		if (paramPair[0] === 'SAMLRequest' || paramPair[0] === 'RelayState') {
			ret[paramPair[0]] = decodeURIComponent(paramPair[1]);
		} else if (paramPair[0] === 'fromURI') {
			// special okta case, parse into fromURI
			var newMsg = 'Parsed fromURI query parameter for SAMLRequest.';
			return tryParseQueryParams(decodeURIComponent(paramPair[1]), newMsg, orgParams);
		}
	}

	ret["orgParams"] = orgParams;
	return ret;
}

requirejs(["js/vendor/pako"], function(pako) {
	$('#saml_input').on('keyup paste', _.debounce(function() {
		hideAll();

	    var input = $("#saml_input").val();

	    if (isValidSAML(input)) {
	    	output(input);
	    	return;
	    }

	   	var queryParams = tryParseQueryParams(input, 'Parsed URL for SAMLRequest.');
	   	if (queryParams) {
	   		if (queryParams['SAMLRequest']) {
	   			input = queryParams['SAMLRequest'];
	   		}
	   		if (queryParams['RelayState']) {
	   			show('relay_state', queryParams['RelayState']);
	   		}
	   		if (queryParams['message']) {
	   			show('message', queryParams['message']);
	   			$('#message_params').empty();
	   			$.each(queryParams['orgParams'], function (k, v) {
	   				appendMessageParam(k, v);
	   			});
	   		}
	   	}

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

 });



