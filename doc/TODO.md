### TODO list (in no particular order
- Add DNS validation check
- Make days configurable
- Un-fudge the various configuration dicts (self.ca, self.cfg, etc)
- Make client.yml template more templated
- Move to python-based logging
- Add file-based logging
- Create separate OSCP responder
  * openssl ocsp -index db/as65342-autosign.db -port 8888 -rsigner certs/as65342-autosign.pem -rkey private/as65342-autosign.key -CA certs/as65342-autosign.pem -text
  * openssl ocsp -issuer certs/as65342-autosign.pem -cert certs/alita.as65342.net.pem -host 127.0.0.1 -port 8888
- Setup pki website
- Add various root certs + bundles + crl's etc to pki website
- Add network-based ACLs

### pkiclient
- fetch_new_token_and_config -> make hostname based on socket.gethostname()
- APIClient.new_server_cert -> Make vhost detection automagic
