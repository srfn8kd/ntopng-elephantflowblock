# ntopng-elephantflowblock
Block elephant flows detected by NTOPNG in Arista switches

This is just a couple of simple scripts to manage the automatic blocking and unblocking of elephant flows detected on your network via NTOPNG, monitors the NTOPNG output log for elephant flows and cuts them off so that IDS does not need to waste CPU cycles on uninteresting network flows

Proably mostly useful in high speed research environments where large uninteresting elephant flows are commonplace

Does not prevent IDS from alerting to potentially malicous elephant flows, such as data exfiltration - the caveat being if you set up detection correctly in NTOPNG based on intimate knowlege of your network environment
