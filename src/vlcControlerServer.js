// Serveur de controle pour VLC
// ----------------------------
//
// ** Interfaces d'entrées **  
// - Fonction lancer  
// - Commande Websocket play  
// - Vérification à interval régulier
//
// ** Interfaces de sortie **  
// - Ajout de vidéos dans la playlist VLC  
// - Lecture de vidéos dans VLC
//

/*jslint nomen: true*/
/*global define, console, setInterval */
define([
    'lodash',
    'socket.io',
    'request',
    'vlc-api',
    'config',
    'q',
    'path'
], function (_, io, request, vlcApi, config, Q, path) {
    'use strict';

    var module = function () {
        if (!module._initialized) {
            module._initialize();
            module._initialized = true;
        }

        return module;
    };

    _.extend(module, {
        _initialized: false,
        _listeVideos: [],

        _initialize: function () {
            vlcApi({
                host: config.HOST,
                port: config.PORT
            });
        },

        // *** lancer() ***  
        // Lancement de l'application  
        // - Vidage la playliste VLC.  
        // - Récupération de la liste des vidéos diponibles.  
        // - Demarrage du serveur WebSocket.  
        // - Mise en place d'envoi automatique de vidéo.
        // 
        // @return undefined  
        //
        lancer: function () {
            console.log("Demarrage du serveur");

            this._viderPlaylistVLC();
            this._lireVideoIntroduction();
            this._recupererListeVideosDisponibles();
            this._demarrerServeurWebsocket();
            this._demarrerEnvoiVideoSiPlaylistVide();
        },

        _viderPlaylistVLC: function () {
            vlcApi().status.empty();
        },

        _recupererListeVideosDisponibles: function () {
            request({
                method: 'GET',
                uri: config.URL_LISTE_VIDEO,
                qs: {}
            }, _.bind(function (err, res, body) {
                console.log('Liste des videos disponibles: ', body);
                this._listeVideos = JSON.parse(body);
            }, this));
        },

        _demarrerServeurWebsocket: function () {
            io = io.listen(config.WEBSOCKET_PORT);
            io.sockets.on('connection', _.bind(this._initialiserCommandesClient, this));
        },

        _demarrerEnvoiVideoSiPlaylistVide: function () {
            setInterval(
                _.bind(this._envoyerVideoSiPlaylistVide, this),
                config.INTERVAL_VERIFICATION_STATUS_VLC
            );
        },

        _initialiserCommandesClient: function (socket) {
            socket.on('play', _.bind(this._lireIntroSiNecessaireEtAjouterVideo, this));
        },

        // *** lireIntroSiNecessaireEtAjouterVideo(donnees) ***  
        // Récupère les informations sur la vidéo en cours de lecture pour savoir
        // si l'intro doit être ajoutée ou non avant de lire la video demandée
        // 
        // @param struct donnees  
        // @return undefined
        //
        _lireIntroSiNecessaireEtAjouterVideo: function (donnees) {
            vlcApi().status(_.bind(function (vide, infos) {
                if (!this._estVideoIntroduction(infos.information.category.meta.filename)) {
                    this._lireVideoIntroduction();
                }

                this._ajouterVideo(donnees.input);
                this._cleanerPlaylistApresLecture();
            }, this));
        },

        _estVideoIntroduction: function (nomFichierVideo) {
            //@todo fonctionnalité a réactiver lors la fonction supprimer sera OK
            return false && nomFichierVideo === config.FILENAME_VIDEO_INTRODUCTION + config.EXT_VIDEO;
        },

        _lireVideoIntroduction: function () {
            vlcApi().status.play(config.PATH_VIDEO + config.FILENAME_VIDEO_INTRODUCTION + config.EXT_VIDEO, function ()  {});
        },

        _ajouterVideo: function (cheminFichierVideo) {
            var video = config.PATH_VIDEO + path.basename(cheminFichierVideo) + config.EXT_VIDEO;
            
            console.log("Demande d'ajout d'une vidéo: ", video);

            vlcApi().status.enqueue(video, function () {
                console.log("Vidéo ajoutée: ", video);
                vlcApi().status.enqueue(config.PATH_VIDEO + config.FILENAME_VIDEO_INTRODUCTION + config.EXT_VIDEO, _.bind(function () {
                    console.log("Vidéo Introduction ajoutée");
                }, this));
            });
        },

        /* 
         * Ne conserver que les 2 derniers fichiers de la playlist
         * (Introdusction en cours de lecture + vidéo à lire)
         */
        _cleanerPlaylistApresLecture: function () {
            vlcApi().playlist(_.bind(function (vide, playlist) {
                var i = 0,
                    nbVideosASupprimer = playlist.children[0].children.length - 2;

                for (i = 0; i < nbVideosASupprimer; i = i + 1) {
                    this._supprimerVideo(playlist.children[0].children[i].id);
                }
            }, this));
        },

        _supprimerVideo: function (idVideo) {
            //@todo: Debugger cette fonctionalité
            //vlcApi().status["delete"](idVideo);
        },

        // ** envoyerVideoSiPlaylistVide **  
        // Ajoute une vidéo dans la playlist si nécessaire
        //
        // @return undefined
        //
        _envoyerVideoSiPlaylistVide: function () {
            new Q()
                .then(function () {
                    var deferred = Q.defer();

                    vlcApi().status(function (vide, infos) {
                        deferred.resolve(infos);
                    });

                    return deferred.promise;
                })
                .then(function (infos) {
                    var deferred = Q.defer();

                    vlcApi().playlist(function (vide, playlist) {
                        deferred.resolve([infos, playlist]);
                    });

                    return deferred.promise;
                })
                .spread(_.bind(function (infos, playlist) {
                    var posDerniereVideo = playlist.children[0].children.length - 1,
                        cheminVideo = '',
                        posVideo = 0;

                    if (infos.currentplid == playlist.children[0].children[posDerniereVideo].id) {
                        posVideo = parseInt(Math.random() * this._listeVideos.length, 10);
                        cheminVideo = this._listeVideos[posVideo];

                        this._ajouterVideoAutomatique(cheminVideo.src);
                        this._cleanerPlaylistApresAjoutAutomatique();
                    }
                }, this));
        },

        _ajouterVideoAutomatique: function (cheminVideo) {
            new Q()
                .then(_.bind(function () {
                    var deferred = Q.defer();

                    vlcApi().status.enqueue(config.PATH_VIDEO + path.basename(cheminVideo) + config.EXT_VIDEO, _.bind(function () {
                        deferred.resolve();
                    }, this));

                    return deferred.promise;
                }, this))
                .then(_.bind(function () {
                    var deferred = Q.defer();

                    vlcApi().status.enqueue(config.PATH_VIDEO + config.FILENAME_VIDEO_INTRODUCTION + config.EXT_VIDEO, _.bind(function () {
                        deferred.resolve();
                    }, this));

                    return deferred.promise;
                }, this));
        },

        /* 
         * Ne conserver que les 3 derniers fichiers de la playlist
         * (Vidéo en cours de lecture + introduction + nouvelle vidéo à lire)
         */
        _cleanerPlaylistApresAjoutAutomatique: function () {
            vlcApi().playlist(_.bind(function (vide, playlist) {
                var i = 0,
                    nbVideosASupprimer = playlist.children[0].children.length - 3;

                for (i = 0; i < nbVideosASupprimer; i = i + 1) {
                    this._supprimerVideo(playlist.children[0].children[i].id);
                }
            }, this));
        }
    });

    return module;
});