#!/usr/bin/node

"use strict";

var argv = require( "minimist" )( process.argv.slice( 2 ) );
var Humanize = require( "humanize-plus" );
var Promise = require( "bluebird" );
var snmp = require( "net-snmp" );

var OID_NIC_NAMES = "1.3.6.1.2.1.2.2.1.2";
var OID_NIC_INOCTETS = "1.3.6.1.2.1.2.2.1.10";
var OID_NIC_OUTOCTETS = "1.3.6.1.2.1.2.2.1.16";

var session = snmp.createSession( argv.hostname, argv.community );

getNicOid( new InterfaceStatistics( argv.interface ) )
	.then( getSnmpIndex )
	.then( getInterfaceMetrics )
	.then( calculateSpeed )
	.then( printResults );

function InterfaceStatistics( interfacePattern ) {
	// The pattern used to find the interface.
	this.interfacePattern = interfacePattern;
	// The name of the interface.
	this.interfaceName = "Unknown Interface";
	// The OID that points to the name of this interface.
	this.interfaceOid = "0";
	// The index of the interface inside the SNMP tree.
	this.interfaceIndex = 0;
	// How many incoming octets were processed.
	this.inOctets = 0;
	// How many outgoing octets were processed.
	this.outOctets = 0;
	// Seconds since the last check.
	this.timeDelta = 0;
	// The average transfer speed since the previous check.
	this.speedIn = 0;
	// The average transfer speed since the previous check.
	this.speedOut = 0;
}

function getNicOid( interfaceStats ) {
	return new Promise( function( resolve, reject ) {
		var nicPattern = new RegExp( interfaceStats.interfacePattern );

		session.subtree( OID_NIC_NAMES,
			function( varbinds ) {
				for( var i = 0; i < varbinds.length; i++ ) {
					if( snmp.isVarbindError( varbinds[ i ] ) ) {
						console.error( snmp.varbindError( varbinds[ i ] ) )
					} else {
						var nicName = varbinds[ i ].value.toString();
						if( nicPattern.test( nicName ) ) {
							interfaceStats.interfaceName = nicName.replace( /[\r\n\t\0]/g, "" );
							interfaceStats.interfaceOid = varbinds[ i ].oid.toString();
							return resolve( interfaceStats );
						}
					}
				}
			}, function( error ) {
				if( error ) {
					reject( error );
				}
			} );
	} );
}

function getSnmpIndex( interfaceStats ) {
	interfaceStats.interfaceIndex = Number( interfaceStats.interfaceOid.substr( interfaceStats.interfaceOid.lastIndexOf( "." ) + 1 ) );
	return interfaceStats;
}

function getInterfaceMetrics( interfaceStats ) {
	return new Promise( function( resolve, reject ) {
		var oidsToGet = [ OID_NIC_INOCTETS + "." + interfaceStats.interfaceIndex, OID_NIC_OUTOCTETS + "." + interfaceStats.interfaceIndex ];
		session.get( oidsToGet, function( error, varbinds ) {
			if( error ) {
				return reject( error );
			}

			var inOctets = varbinds[ 0 ];
			var outOctets = varbinds[ 1 ];

			interfaceStats.inOctets = inOctets.value.toString();
			interfaceStats.outOctets = outOctets.value.toString();

			resolve( interfaceStats );
		} );
	} );
}

function calculateSpeed( interfaceStats ) {
	if( argv.lastcheck ) {
		var lastCheck = parseInt( argv.lastcheck );
		var currentTime = Math.floor( Date.now() / 1000 );
		var delta = currentTime - lastCheck;
		interfaceStats.timeDelta = delta;
	}
	if( argv.previous ) {
		var previousInOctets = parseInt( getValueFromPerfData( argv.previous, "octets_in" ) );
		var previousOutOctets = parseInt( getValueFromPerfData( argv.previous, "octets_out" ) );

		var deltaInOctets = interfaceStats.inOctets - previousInOctets;
		var deltaOutOctets = interfaceStats.outOctets - previousOutOctets;

		// TODO: Handle counter overflow
		var speedIn = Math.max( 0, deltaInOctets / interfaceStats.timeDelta );
		var speedOut = Math.max( 0, deltaOutOctets / interfaceStats.timeDelta );

		interfaceStats.speedIn = speedIn;
		interfaceStats.speedOut = speedOut;
	}
	return interfaceStats;
}

function getValueFromPerfData( perfData, value ) {
	var valuePrefixLength = value.length + "=".length;
	var valueStart = perfData.indexOf( value );
	var valueEnd = perfData.indexOf( ", ", valueStart );
	if( -1 === valueEnd ) {
		valueEnd = perfData.length;
	}
	return perfData.substring( valueStart + valuePrefixLength, valueEnd );
}

function printResults( interfaceStats ) {
	var speedInfo = "(IN: " + Humanize.fileSize( interfaceStats.speedIn ) + "/s, OUT: " + Humanize.fileSize( interfaceStats.speedOut ) + "/s)";
	var statusLine = interfaceStats.interfaceName + " " + speedInfo;
	var performanceData = "octets_in=" + interfaceStats.inOctets + ", octets_out=" + interfaceStats.outOctets + ", speed_in=" + interfaceStats.speedIn + ", speed_out=" + interfaceStats.speedOut;
	console.log( statusLine + " | " + performanceData );
}
