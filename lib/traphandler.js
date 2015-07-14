#!/usr/bin/node

"use strict";

var fs = require( "fs" );

fs.writeFile( "/tmp/test", process.argv.join( "|" ), function( err ) {
	if( err ) {
		return console.log( err );
	}
} );
