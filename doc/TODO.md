### TODO list (in no particular order
- Make all validation checks restrictive (and add option to make them permissive)
- Make sure all api calls are properly restricted
- Add DNS validation check
- Make days configurable
- Make paths absolute in root.cfg
- Make sure templates are installed into workspace
- Un-fudge the various configuration dicts (self.ca, self.cfg, etc)
- Move templates into scripts

### pkiclient
- fetch_new_token_and_config -> make hostname based on socket.gethostname()
- APIClient.new_server_cert -> Make vhost detection automagic
