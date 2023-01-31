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

    var consoledot_config_plugin = {};

    consoledot_config_plugin.add_consoledot_config_pre_op = function() {
        var section = {
            name: 'consoledot',
            label: '@i18n:consoledotconfig.name',
            fields: [{
                name: 'consoledotorgid',
                flags: ['w_if_no_aci']
            }]
        };
        var facet = get_item(IPA.serverconfig.entity_spec.facets, '$type', 'details');
        facet.sections.push(section);
        return true;
    };

    phases.on('customization', consoledot_config_plugin.add_consoledot_config_pre_op);

    return consoledot_config_plugin;
});
