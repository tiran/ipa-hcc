//
// IPA plugin for consoleDot
// Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
// See COPYING for license
//

define([
        'freeipa/phases',
        'freeipa/ipa'
    ],
    function(phases, IPA) {

        // helper function
        function get_item(array, attr, value) {
            for (var i = 0, l = array.length; i < l; i++) {
                if (array[i][attr] === value) return array[i];
            }
            return null;
        }

        var consoledot_host_plugin = {};

        consoledot_host_plugin.add_consoledot_host_pre_op = function() {
            var section = {
                name: 'consoledothost',
                label: '@i18n:consoledothost.name',
                fields: [{
                    name: 'consoledotorgid',
                    flags: ['w_if_no_aci'],
                    read_only: true
                }, {
                    name: 'consoledotsubscriptionid',
                    flags: ['w_if_no_aci']
                }, {
                    name: 'consoledotinventoryid',
                    flags: ['w_if_no_aci']
                }, {
                    name: 'consoledotcertsubject',
                    flags: ['w_if_no_aci'],
                    read_only: true
                }]
            };
            var facet = get_item(IPA.host.entity_spec.facets, '$type', 'details');
            facet.sections.push(section);
            return true;
        };

        phases.on('customization', consoledot_host_plugin.add_consoledot_host_pre_op);

        return consoledot_host_plugin;
    });
