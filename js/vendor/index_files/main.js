function formatXml(xml) {
    var formatted = '';
    var reg = /(>)(<)(\/*)/g;
    xml = xml.replace(reg, '$1\r\n$2$3');
    var pad = 0;
    jQuery.each(xml.split('\r\n'), function(index, node) {
        var indent = 0;
        if (node.match( /.+<\/\w[^>]*>$/ )) {
            indent = 0;
        } else if (node.match( /^<\/\w/ )) {
            if (pad != 0) {
                pad -= 1;
            }
        } else if (node.match( /^<\w[^>]*[^\/]>.*$/ )) {
            indent = 1;
        } else {
            indent = 0;
        }

        var padding = '';
        for (var i = 0; i < pad; i++) {
            padding += '  ';
        }

        formatted += padding + node + '\r\n';
        pad += indent;
    });

    return formatted;
}

function resizeTextArea(textArea) {
    textArea.css('height', '1px');
    textArea.css('height', (textArea.prop('scrollHeight') + 25) + 'px');
}

function hideAll() {
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

function output(s) {
	$('#output').show();

	$('#output_area').val(s);
	resizeTextArea($('#output_area'));

	$('#output_params').empty();
	parser = new DOMParser();
	xmlDoc = parser.parseFromString(s, "text/xml");

	appendOutputParam("Type", xmlDoc.documentElement.tagName)
	appendOutputParam("ID", xmlDoc.documentElement.getAttribute("ID"));
	appendOutputParam("Issued At", xmlDoc.documentElement.getAttribute("IssueInstant"));
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
	    	output(formatXml(input));
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
		  			output(formatXml(decompressed));
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
 });



