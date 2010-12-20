#!/usr/bin/env node

var sys       = require('sys'),
    ldapauth  = require('../ldapauth'); // Path to ldapauth.node

var ldap_host = 'localhost',
ldap_port = 389,
username  = 'cn=username,o=USERS',
password  = 'password',
groups = 'ou=CMS,o=GROUPS';
timeout = 10;

ldapauth.authenticate(ldap_host, ldap_port, username, password, groups, timeout,
  function(err, result) {
    if (err) {
      sys.puts(err);
    } else {
      sys.puts('Result: ' + result);
    }
  });
