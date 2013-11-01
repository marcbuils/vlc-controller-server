/*jslint nomen: true*/
/*global require */
var requirejs = require('requirejs');

requirejs.config({
    baseUrl: 'src',
    nodeRequire: require
});

requirejs(['vlcControlerServer'], function (vlcControlerServer) {
    'use strict';

    vlcControlerServer().lancer();
});