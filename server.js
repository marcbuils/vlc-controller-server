var requirejs = require('requirejs');

requirejs.config({
    baseUrl: 'src',
    nodeRequire: require   
});

requirejs(['vlcControlerServer'], function (vlcControlerServer) {
    vlcControlerServer.start();
});