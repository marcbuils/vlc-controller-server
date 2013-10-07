// Serveur de controle pour VLC
// ----------------------------
//
define([
    'lodash',
    'socket.io',
    'vlc-api',
    'config',
    'require'
], function (_, io, vlcApi, config, requirejs) {
    'use strict';

    var module = function () {
        if (!module.initialized) {
            module.initialize();
            module.initialized = true;
        }

        return module;
    };
   
    _.extend(module, {
        initialized: false,
        listeVideos: null,
       
        // *** initialize() ***  
        // Initialisation du module.  
        // 
        // @return undefined
        // 
        initialize: function () {},
       
        // *** start() ***  
        // Vidage la playliste VLC.  
        // Ajout de la video d'introduction sur VLC.  
        // Récupération de la liste des vidéos diponibles.  
        // Demarrage du serveur WebSocket.  
        // Mise en place d'envoi automatique de vidéo.
        // 
        // @return undefined  
        //
        start: function () {
            console.debug("Demarrage du serveur");
           
            this.viderPlaylistVLC();
            this.ajouterVideoIntroduction();
            this.recupererListeVideosDisponibles();
            this.demarrerServeurWebsocket();
            this.demarrerEnvoiVideoSiPlaylistVide();
        },
       
        // *** viderPlaylistVLC() ***  
        // Vide la playliste VLC.  
        // 
        // @return undefined
        //
        viderPlaylistVLC: function () {
            vlcApi.status.empty();
        },
       
        // *** ajouterVideoIntroduction() ***  
        // Ajout de la video d'introduction sur VLC.
        // 
        // @return undefined
        //
        ajouterVideoIntroduction: function () {
            vlcApi().status.play(config.PATH_VIDEO_INTRODUCTION);
        },
               
        // *** recupererListeVideosDisponibles() ***  
        // Récupération de la liste des vidéos diponibles.
        // 
        // @return undefined
        //
        recupererListeVideosDisponibles: function () {
            requirejs(['json!' + config.URL_LISTE_VIDEO], function (listeVideos) {
                this.listeVideos = listeVideos;
            });
        },
               
        // *** demarrerServeurWebsocket() ***  
        // Demarrage du serveur WebSocket.
        //
        // @return undefined
        //
        demarrerServeurWebsocket: function () {
            io = io.listen(config.WEBSOCKET_PORT);
            io.sockets.on('connection', _.bind(this.onconnection, this));
        },
         
        // *** demarrerEnvoiVideoSiPlaylistVide() ***  
        // Mise en place d'envoi automatique de vidéo.
        //
        // @return undefined
        //
        demarrerEnvoiVideoSiPlaylistVide: function () {
            setInterval(
                _.bind(this.envoyerVideoSiPlaylistVide, this),
                config.INTERVAL_VERIFICATION_STATUS_VLC
            );
        },
       
        // *** onconnection() ***  
        // Callback appelée lors de la réception de commandes WebSocket.
        // Lit une vidéo lors de la reception de la commande play.
        // 
        // @return undefined
        //
        onconnection: function (socket) {
            socket.on('play', _.bind(this.onplay, this));
        },
       
        // *** onplay() ***  
        // Lit une vidéo lors de la reception de la commande play. 
        // 
        // @param struct data  
        // @return undefined
        //
        onplay: function (data) {
            this.play(data.input);
        },
       
        // *** play() ***  
        // Lit une vidéo. 
        // 
        // @param strint input  
        // @return undefined
        //
        play: function (input) {
            console.debug("Demande de lecture d'une vidéo: ", input);
            
            vlcApi().status.play(input, function () {
                console.debug("Vidéo démarrée: ", input);
            });
        },
                
        envoyerVideoSiPlaylistVide: function () {
            vlcApi.status.
        }
    });
       
    return {
        start: _.bind(module().start, module)
    };
});