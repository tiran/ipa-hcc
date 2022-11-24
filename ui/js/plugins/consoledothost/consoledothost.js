//
// IPA plugin for consoleDot
// Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
// See COPYING for license
//

define([
        'freeipa/phases',
        'freeipa/ipa',
        'freeipa/reg',
        'freeipa/util'
    ],
    function(phases, IPA, reg, util) {

        // helper function
        function get_item(array, attr, value) {
            for (var i = 0, l = array.length; i < l; i++) {
                if (array[i][attr] === value) return array[i];
            }
            return null;
        }

        var consoledot_host_plugin = {};

        // show consoleDot fields on detailed page
        consoledot_host_plugin.add_consoledot_host_pre_op = function() {
            var section = {
                name: 'consoledothost',
                label: '@i18n:consoledothost.name',
                fields: [{
                    name: 'consoledotsubscriptionid',
                    flags: ['w_if_no_aci']
                }, {
                    name: 'consoledotinventoryid',
                    flags: ['w_if_no_aci']
                }, {
                    name: 'consoledotorgid',
                    flags: ['w_if_no_aci'],
                    read_only: true
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

        // add registration status and deep link to overview page
        consoledot_host_plugin.add_consoledot_host_search = function() {
            var column = {
                name: 'consoledotinventoryid',
                label: '@i18n:consoledothost.inventory',
                formatter: 'consoledot_host_link'
            }
            var facet = get_item(IPA.host.entity_spec.facets, '$type', 'search');
            facet.columns.push(column);
            return true;
        }

        phases.on('customization', consoledot_host_plugin.add_consoledot_host_search);

        // custom HTML formatter to render a consoleDot inventory ID as deep
        // link into consoleDot Insights.
        consoledot_host_plugin.consoledot_host_link_formatter = function(spec) {
            var that = IPA.formatter(spec);

            that.type = 'html';

            that.format = function(value) {
                if (util.is_empty(value)) {
                    return '';
                }
                return '<a href="https://console.redhat.com/insights/inventory/'+value+'">'+value+'</a>';
            };
            return that;
        };

        consoledot_host_plugin.register = function() {
            var f = reg.formatter;
            f.register('consoledot_host_link', consoledot_host_plugin.consoledot_host_link_formatter);
        }

        phases.on('customization', consoledot_host_plugin.register);

        return consoledot_host_plugin;
    });
