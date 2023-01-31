//
// IPA plugin for Hybrid Cloud Console
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

        var hcc_host_plugin = {};

        // show Hybrid Cloud Console fields on detailed page
        hcc_host_plugin.add_hcc_host_pre_op = function() {
            var section = {
                name: 'hcchost',
                label: '@i18n:hcchost.name',
                fields: [{
                    name: 'hccsubscriptionid',
                    flags: ['w_if_no_aci']
                }, {
                    name: 'hccinventoryid',
                    flags: ['w_if_no_aci']
                }, {
                    name: 'hccorgid',
                    flags: ['w_if_no_aci'],
                    read_only: true
                }, {
                    name: 'hcccertsubject',
                    flags: ['w_if_no_aci'],
                    read_only: true
                }]
            };
            var facet = get_item(IPA.host.entity_spec.facets, '$type', 'details');
            facet.sections.push(section);
            return true;
        };

        phases.on('customization', hcc_host_plugin.add_hcc_host_pre_op);

        // add registration status and deep link to overview page
        hcc_host_plugin.add_hcc_host_search = function() {
            var column = {
                name: 'hccinventoryid',
                label: '@i18n:hcchost.inventory',
                formatter: 'hcc_host_link'
            }
            var facet = get_item(IPA.host.entity_spec.facets, '$type', 'search');
            facet.columns.push(column);
            return true;
        }

        phases.on('customization', hcc_host_plugin.add_hcc_host_search);

        // custom HTML formatter to render a Hybrid Cloud Console inventory ID as deep
        // link into Hybrid Cloud Console's host based inventory (Insights Inventory).
        hcc_host_plugin.hcc_host_link_formatter = function(spec) {
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

        hcc_host_plugin.register = function() {
            var f = reg.formatter;
            f.register('hcc_host_link', hcc_host_plugin.hcc_host_link_formatter);
        }

        phases.on('customization', hcc_host_plugin.register);

        return hcc_host_plugin;
    });
