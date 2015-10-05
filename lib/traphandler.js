#!/usr/bin/node

/*
 The trap handler will receive SNMP trap information from snmptrapd.
 The trap data is received on STDIN. An example packet would look like:

 cisco-sg300-28-4.example.com
 UDP: [10.0.1.109]:161->[10.0.1.70]:162
 .1.3.6.1.2.1.1.3.0 10:9:13:05.10
 .1.3.6.1.6.3.1.1.4.1.0 .1.3.6.1.6.3.1.1.5.3
 .1.3.6.1.2.1.2.2.1.1.63 63
 .1.3.6.1.2.1.2.2.1.7.63 up
 .1.3.6.1.2.1.2.2.1.8.63 down
 .1.3.6.1.6.3.18.1.3.0 10.0.1.109
 .1.3.6.1.6.3.18.1.4.0 "public"
 .1.3.6.1.6.3.1.1.4.3.0 .1.3.6.1.6.3.1.1.5

 The first line is the FQDN/address of the device that sent the trap.
 The second line shows from where to where the packet was sent.
 The following lines contain the data (as OID-value pairs) that is sent with the trap.

 For easier readability, here's an annotated version of the same packet:

 cisco-sg300-28-4.example.com
 UDP: [10.0.1.109]:161->[10.0.1.70]:162
 .1.3.6.1.2.1.1.3.0         10:9:13:05.10           sysUpTime       How long the agent has been running.
 .1.3.6.1.6.3.1.1.4.1.0     .1.3.6.1.6.3.1.1.5.3    snmpTrapOID     The type of trap. coldStart, warmStart, linkDown, linkUp
 .1.3.6.1.2.1.2.2.1.1.63    63                      ifIndex         The unique index for the network interface.
 .1.3.6.1.2.1.2.2.1.7.63    up                      ifAdminStatus   The desired state of the interface.
 .1.3.6.1.2.1.2.2.1.8.63    down                    ifOperStatus    The current state of the interface.
 .1.3.6.1.6.3.18.1.3.0      10.0.1.109              agentAddress    The IP address of the agent.
 .1.3.6.1.6.3.18.1.4.0      "public"                community       The community this trap was sent to.
 .1.3.6.1.6.3.1.1.4.3.0     .1.3.6.1.6.3.1.1.5      snmpTrapEnterprise
 */

"use strict";

var Promise = require( "bluebird" );

var argv = require( "minimist" )( process.argv.slice( 2 ) );
//noinspection JSUnresolvedFunction
var fs    = Promise.promisifyAll( require( "fs" ) );
var snmp  = require( "net-snmp" );
var spawn = require( "child_process" ).spawn;

var OID_NIC_NAMES = "1.3.6.1.2.1.2.2.1.2";

readStdin()
	.then( processBuffer );

/**
 * We'd usually expect the whole trap data to be sent in a single chunk,
 * but we'll buffer here, just to make sure.
 * @returns {bluebird|exports|module.exports}
 */
function readStdin() {
	var buffer = "";
	if( argv.file ) {
		return readTrapFromFile( argv.file );
	}
	return new Promise( function( resolve, reject ) {
		process.stdin.resume();
		process.stdin.setEncoding( "utf8" );
		process.stdin.on( "data", function( data ) {
			buffer += data;
		} );
		process.stdin.on( "end", function onEnd() {
			resolve( buffer );
		} );
		process.stdin.on( "error", reject );
	} );
}

function readTrapFromFile( filename ) {
	//noinspection JSUnresolvedFunction
	return fs.readFileAsync( filename, "utf-8" )
}

function processBuffer( buffer ) {
	// Extract the hostname, and the communication indicator from the buffer.
	var firstLineLength  = buffer.indexOf( "\n" );
	var secondLineLength = buffer.indexOf( "\n", firstLineLength + 1 ) - firstLineLength;

	var hostname = buffer.substr( 0, firstLineLength );
	var commLine = buffer.substr( firstLineLength + 1, secondLineLength - 1 );

	// Now cut off the two lines from the buffer.
	buffer = buffer.substr( firstLineLength + secondLineLength + 1 );

	/*
	 Here is an example of what the following lines might print:
	 ---TRAP RECEIVED 2015-07-14T15:17:10.138Z ---
	 HOST: cisco-sg300-28-5.example.com
	 COMM: UDP: [10.0.1.120]:161->[10.0.1.70]:162
	 RBUF:
	 .1.3.6.1.2.1.1.3.0 27:18:05:36.24
	 .1.3.6.1.6.3.1.1.4.1.0 .1.3.6.1.6.3.1.1.5.4
	 .1.3.6.1.2.1.2.2.1.1.52 52
	 .1.3.6.1.2.1.2.2.1.7.52 up
	 .1.3.6.1.2.1.2.2.1.8.52 up
	 .1.3.6.1.6.3.18.1.3.0 10.0.1.120
	 .1.3.6.1.6.3.18.1.4.0 "public"
	 .1.3.6.1.6.3.1.1.4.3.0 .1.3.6.1.6.3.1.1.5

	 PBUF:
	 [{".1.3.6.1.2.1.1.3.0":"27:18:05:36.24"},{".1.3.6.1.6.3.1.1.4.1.0":".1.3.6.1.6.3.1.1.5.4"},{".1.3.6.1.2.1.2.2.1.1.52":"52"},{".1.3.6.1.2.1.2.2.1.7.52":"up"},{".1.3.6.1.2.1.2.2.1.8.52":"up"},{".1.3.6.1.6.3.18.1.3.0":"10.0.1.120"},{".1.3.6.1.6.3.18.1.4.0":"public"},{".1.3.6.1.6.3.1.1.4.3.0":".1.3.6.1.6.3.1.1.5"}]
	 ---TRAP COMPLETE---
	 */

	var varbinds = parseVarbinds( buffer );
	varbinds.map( translateTrapVarbind );

	return getAdditionalInfo( varbinds )
		.then( function( varbinds ) {
			writeToBuffer( "---TRAP RECEIVED " + new Date().toISOString() + " ---\n" );
			writeToBuffer( "HOST: " + hostname + "\n" );
			writeToBuffer( "COMM: " + commLine + "\n" );
			writeToBuffer( "RBUF:\n" + buffer + "\n" );

			writeToBuffer( "PBUF:\n" );
			printVarBinds( varbinds );

			writeToBuffer( "---TRAP COMPLETE---\n" );

			return submitCheckResult( hostname, varbinds );
		} );
}

function submitCheckResult( hostname, varbinds ) {
	var host         = hostname.substr( 0, hostname.indexOf( "." ) );
	var service      = "SNMP Traps";
	var state        = 3;
	var pluginOutput = "";

	var varbindType = varbindByKey( varbinds, "Type" );

	switch( varbindType.value ) {
		case "linkDown":
			service      = varbindByKey( varbinds, "Interface" ).value;
			state        = 2;
			pluginOutput = service + " " + varbindByKey( varbinds, "Type" ).value;
			break;
		case "linkUp":
			service      = varbindByKey( varbinds, "Interface" ).value;
			state        = 0;
			pluginOutput = service + " " + varbindByKey( varbinds, "Type" ).value;
			break;
		default:
			return;
	}

	//EXEC /usr/share/nagios3/plugins/eventhandlers/submit_check_result "$r" "snmp_traps" 2 "$O: $1 $2 $3 $4 $5"
	spawn( "/usr/share/nagios3/plugins/eventhandlers/submit_check_result", [ host, service, state, pluginOutput ] );
}

function parseVarbinds( buffer ) {
	var bufferPointer = 0;
	var bufferKey     = "";
	var bufferValue   = "";
	var inValue       = false;
	var pairs         = [];

	var inString = false;

	for( ; bufferPointer < buffer.length; ++bufferPointer ) {
		if( buffer[ bufferPointer ] === "\"" ) {
			inString = !inString;
			continue;
		}

		if( buffer[ bufferPointer ] === "\n" && !inString ) {
			var pair = { key : bufferKey, value : bufferValue };
			pairs.push( pair );
			bufferKey   = "";
			bufferValue = "";
			inValue     = false;
			continue;
		}

		if( buffer[ bufferPointer ] === " " && !inValue ) {
			inValue = true;
			continue;
		}

		if( inValue ) {
			bufferValue += buffer[ bufferPointer ];
		} else {
			bufferKey += buffer[ bufferPointer ];
		}
	}

	return pairs;
}

function translateTrapVarbind( varbind ) {
	if( 0 === varbind.key.indexOf( ".1.3.6.1.2.1.1.3.0" ) ) {
		varbind.key = "UP for";
	} else if( 0 === varbind.key.indexOf( ".1.3.6.1.6.3.1.1.4.1.0" ) ) {
		varbind.key = "Type";
	} else if( 0 === varbind.key.indexOf( ".1.3.6.1.2.1.2.2.1.1." ) ) {
		varbind.key = "Interface#";
	} else if( 0 === varbind.key.indexOf( ".1.3.6.1.2.1.2.2.1.7." ) ) {
		varbind.key = "Administrative";
	} else if( 0 === varbind.key.indexOf( ".1.3.6.1.2.1.2.2.1.8." ) ) {
		varbind.key = "Operational";
	} else if( 0 === varbind.key.indexOf( ".1.3.6.1.6.3.18.1.3.0" ) ) {
		varbind.key = "Address";
	} else if( 0 === varbind.key.indexOf( ".1.3.6.1.6.3.18.1.4.0" ) ) {
		varbind.key = "Community";
	} else if( 0 === varbind.key.indexOf( ".1.3.6.1.6.3.1.1.4.3.0" ) ) {
		varbind.key = "Enterprise";
	}

	if( 0 === varbind.value.indexOf( ".1.3.6.1.6.3.1.1.5.1" ) ) {
		varbind.value = "coldStart";
	} else if( 0 === varbind.value.indexOf( ".1.3.6.1.6.3.1.1.5.2" ) ) {
		varbind.value = "warmStart";
	} else if( 0 === varbind.value.indexOf( ".1.3.6.1.6.3.1.1.5.3" ) ) {
		varbind.value = "linkDown";
	} else if( 0 === varbind.value.indexOf( ".1.3.6.1.6.3.1.1.5.4" ) ) {
		varbind.value = "linkUp";
	} else if( 0 === varbind.value.indexOf( ".1.3.6.1.6.3.1.1.5.5" ) ) {
		varbind.value = "authenticationFailure";
	}
	return varbind;
}

function printVarBinds( varbinds ) {
	var maxKeyLength = varbinds.reduce( function( previous, current ) {
		return Math.max( current.key.length, previous );
	}, 0 );
	for( var varbindIndex = 0; varbindIndex < varbinds.length; ++varbindIndex ) {
		writeToBuffer( varbinds[ varbindIndex ].key + new Array( maxKeyLength - varbinds[ varbindIndex ].key.length + 1 )
				.join( " " ) + ": " + varbinds[ varbindIndex ].value + "\n" );
	}
}

function getAdditionalInfo( varbinds ) {
	return new Promise( function( resolve, reject ) {
		var varbindAddress   = varbindByKey( varbinds, "Address" );
		var varbindCommunity = varbindByKey( varbinds, "Community" );
		var varbindInterface = varbindByKey( varbinds, "Interface#" );

		if( !varbindAddress || !varbindCommunity || !varbindInterface ) {
			return resolve( varbinds );
		}

		var session = snmp.createSession( varbindAddress.value, varbindCommunity.value );
		session.get( [ OID_NIC_NAMES + "." + varbindInterface.value ], function( error, nameVarbinds ) {
			if( error ) {
				return reject( error );
			}

			varbinds.push( { key : "Interface", value : nameVarbinds[ 0 ].value.toString() } );

			resolve( varbinds );
		} );
	} );
}

function varbindByKey( varbinds, key ) {
	return varbinds.filter( function( varbind ) {
		return varbind.key === key;
	} )[ 0 ];
}

function writeToBuffer( content ) {
	console.log( content );
	if( argv.log ) {
		fs.appendFileSync( argv.log, content );
	}
}
