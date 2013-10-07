/*jslint nomen: true*/
/*global module */
module.exports = function (grunt) {
    'use strict';

    // Project configuration.
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        conf: {
            distDir: 'dist',
            jsAppFileName: 'index.js'
        },

        clean: {
            dist: ['<%= conf.distDir %>']
        },

        requirejs: {
            compile: {
                options: {
                    name: 'index',
                    mainConfigFile: 'index.js',
                    out: '<%= conf.distDir %>/<%= conf.jsAppFileName %>'
                }
            }
        },

        connect: {
            dev: {
                options: {
                    port: 8081,
                    base: ''
                }
            }
        },

        watch: {
            options: {
                livereload: true
            },
            all: {
                files: [],
                tasks: []
            }
        }
    });

    // Load plugins
    grunt.loadNpmTasks('grunt-contrib-requirejs');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-contrib-connect');
    grunt.loadNpmTasks('grunt-contrib-watch');

    // task(s).
    grunt.registerTask('dist', [
        'clean:dist',
        'requirejs'
    ]);
    grunt.registerTask('default', ['dist']);
    //grunt.registerTask('deploy', ['dist', 'ftp-deploy:dist']);
    grunt.registerTask('serve', ['connect:dev', 'watch']);
};