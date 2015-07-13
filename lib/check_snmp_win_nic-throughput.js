#!/usr/bin/node

"use strict";

var argv = require( "minimist" )( process.argv.slice( 2 ) );
var Promise = require( "bluebird" );
var snmp = require( "net-snmp" );

var OID_NIC_NAMES = "1.3.6.1.2.1.2.2.1.2";
var OID_NIC_INOCTETS = "1.3.6.1.2.1.2.2.1.10";
var OID_NIC_OUTOCTETS = "1.3.6.1.2.1.2.2.1.16";

var session = snmp.createSession( argv.hostname, argv.community );

getNicOid( new InterfaceStatistics( argv.interface ) )
	.then( getSnmpIndex )
	.then( getInterfaceMetrics )
	.then( printResults );

function InterfaceStatistics( interfacePattern ) {
	this.interfacePattern = interfacePattern;
	this.interfaceName = "Unknown Interface";
	this.interfaceOid = "0";
	this.interfaceIndex = 0;
	this.inOctets = 0;
	this.outOctets = 0;
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
							interfaceStats.interfaceName = nicName;
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

function printResults( interfaceStats ) {
	console.log( interfaceStats.interfaceName + " IN: " + interfaceStats.inOctets + ", OUT: " + interfaceStats.outOctets );
}
