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
//noinspection JSUnresolvedFunction
var fs = Promise.promisifyAll( require( "fs" ) );
var snmp = require( "net-snmp" );

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

function processBuffer( buffer ) {
	// Extract the hostname, and the communication indicator from the buffer.
	var firstLineLength = buffer.indexOf( "\n" );
	var secondLineLength = buffer.indexOf( "\n", firstLineLength + 1 ) - firstLineLength;

	var hostname = buffer.substr( 0, firstLineLength );
	var commLine = buffer.substr( firstLineLength + 1, secondLineLength - 1 );

	// Now cut off the two lines from the buffer.
	buffer = buffer.substr( firstLineLength + secondLineLength + 1 );

	writeToBuffer( "---TRAP RECEIVED " + new Date().toISOString() + " ---\n" );
	writeToBuffer( "HOST: " + hostname + "\n" );
	writeToBuffer( "COMM: " + commLine + "\n" );

	var varbinds = parseVarbinds( buffer );
	writeToBuffer( JSON.stringify( varbinds ) );

	writeToBuffer( "---TRAP COMPLETE---\n" );
}

function parseVarbinds( buffer ) {
	var bufferPointer = 0;
	var bufferKey = "";
	var bufferValue = "";
	var inValue = false;
	var pairs = [];

	var inString = false;

	for( ; bufferPointer < buffer.length; ++bufferPointer ) {
		if( buffer[ bufferPointer ] === "\"" ) {
			inString = !inString;
			continue;
		}

		if( buffer[ bufferPointer ] === "\n" && !inString ) {
			var pair = {};
			pair[ bufferKey ] = bufferValue;
			pairs.push( pair );
			bufferKey = "";
			bufferValue = "";
			inValue = false;
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

function writeToBuffer( content ) {
	//noinspection JSUnresolvedFunction
	return fs.appendFileAsync( "/tmp/test", content );
}
