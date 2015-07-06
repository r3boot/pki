### TODO list (in no particular order
- Add DNS validation check
- Make days configurable
- Un-fudge the various configuration dicts (self.ca, self.cfg, etc)
- Make client.yml template more templated

### pkiclient
- fetch_new_token_and_config -> make hostname based on socket.gethostname()
- APIClient.new_server_cert -> Make vhost detection automagic
