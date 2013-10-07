// Serveur de controle pour VLC
// ----------------------------
//
/*jslint nomen: true*/
/*global define, console, setInterval */
define([
    'lodash',
    'socket.io',
    'vlc-api',
    'config',
    'require'
], function (_, io, vlcApi, config, requirejs) {
    'use strict';

    var module = {
        initialized: false,
        listeVideos: null,

        // *** lancer() ***  
        // Lancement de l'application  
        // - Vidage la playliste VLC.  
        // - Ajout de la video d'introduction sur VLC.  
        // - Récupération de la liste des vidéos diponibles.  
        // - Demarrage du serveur WebSocket.  
        // - Mise en place d'envoi automatique de vidéo.
        // 
        // @return undefined  
        //
        demarrer: function () {
            console.debug("Demarrage du serveur");

            this.viderPlaylistVLC();
            this.lireVideoIntroduction();
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
        lireVideoIntroduction: function () {
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
            io.sockets.on('connection', _.bind(this.initialiserCommandesClient, this));
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

        // *** initialiserCommandesClient() ***  
        // Initialise les commandes utilisables par les clients.
        // Lit une vidéo lors de la reception de la commande play.
        // 
        // @return undefined
        //
        initialiserCommandesClient: function (socket) {
            socket.on('play', _.bind(this.recupererInformationsLecturePuisLectureVideo, this));
        },

        // *** recupererInformationsLecturePuisLectureVideo() ***  
        // Récupère les informations sur la vidéo en cours de lecture pour savoir
        // si l'intro doit être ajoutée ou non avant de lire la video demandée
        // 
        // @param struct data  
        // @return undefined
        //
        recupererInformationsLecturePuisLectureVideo: function (data) {
            vlcApi.status.get(this.lireIntroSiNecessaireEtAjoutVideo);
        },

        // *** lireIntroSiNecessaireEtAjouterVideo() ***  
        // Si l'intro n'est pas en cours de lecture, lire l'intro
        // et ajoute la nouvelle vidéo à la playlist
        // 
        // @param struct infos  
        // @return undefined
        //
        lireIntroSiNecessaireEtAjouterVideo: function (infos) {
            if (infos.information.category.meta.filename !== config.PATH_VIDEO_INTRODUCTION) {
                
            }
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

        // ** envoyerVideoSiPlaylistVide **  
        // Ajoute une vidéo dans la playlist si nécessaire
        //
        // @return undefined
        //
        envoyerVideoSiPlaylistVide: function () {
            vlcApi.status.empty();
        }
    };

    return {
        lancer: _.bind(module().lancer, module)
    };
});