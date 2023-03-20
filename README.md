# ntopng-elephantflowblock
Block elephant flows in Arista switches

This is just a couple of simple scripts to manage the automatic blocking and unblocking of elephant flows detected on your network via NTOPNG

Proably mostly useful in high speed research environments where elephant flows are common

Reads the NTOPNG output for elephant flows and cuts them off so that IDS does not need to waste CPU cycles on uninteresting network flows
