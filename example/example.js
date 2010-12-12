#!/usr/bin/env node

var sys       = require('sys'),
    ldapauth  = require('../ldapauth'); // Path to ldapauth.node

var ldap_host = 'ldap.company.com',
ldap_port = 389,
username  = 'cn=username,o=USERS',
password  = 'password',
groups = 'ou=CMS,o=GROUPS';

ldapauth.authenticate(ldap_host, ldap_port, username, password, groups,
  function(err, result) {
    if (err) {
      sys.puts(err);
    } else {
      sys.puts('Result: ' + result);
    }
  });
