#!/usr/bin/bash

# Uses .netrc file for auth
/usr/bin/curl -s -k -n -H "Content-Type: application/json" -X POST -d '{"jsonrpc":"2.0", "method":"runCmds", "params":{ "version":1, "cmds":["enable", "show ip access-lists YourAccessList"], "format":"text"}, "id":""}' https://YourAristaSwitch/command-api | perl -e 'use JSON; my $scalar = JSON->new->utf8->decode(<>); my $data = $scalar->{"result"}; foreach my $line(@$data) { foreach my $key(keys %$line) { print $line->{$key} ."\n";}}'
