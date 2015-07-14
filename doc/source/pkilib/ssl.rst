pkilib.ssl -- Wrapper around openssl
++++++++++++++++++++++++++++++++++++++++++++++++++++++

Introduction
,,,,,,,,,,,,
The ssl.OpenSSL class contains a set of functions which can be used to operate
a multi-level CA. A 3-level structure is used, which allows for an offline
root certificate. This CA is structured as follows::

   +---------+    +-----------------+    +-------------+
   | Root CA |--->| Intermediary CA |--->| Autosign CA |
   +---------+    +-----------------+    +-------------+
                                            /       \
                                  +------------+ +------------+
                                  | TLS server | | TLS server |
                                  +------------+ +------------+


Loading the configuration
,,,,,,,,,,,,,,,,,,,,,,,,,
The examples below assume that you've loaded the configuration into a
dictionary. The following code block shows an example how to achieve this::

   config = yaml.load(open('pki.yml', 'r').read())


Setting up the Root CA
,,,,,,,,,,,,,,,,,,,,,,
The following example shows how to configure the Root CA and generate all
required files::

   root = OpenSSL(config, CA_ROOT)
   name = root.ca_data['name']
   cfg_file = root.ca_data['cfg']

   # Temporary file containing the (unencrypted) CA password
   PWFILE = 'password.temp'
   open(PWFILE, 'w').write('some password')

   # Generate the directory structure for this CA
   if not root.setup_ca_structure():
       print('Failed to initialize root CA')
       sys.exit(1)

   # Generate a key and CSR for this CA
   if not root.genkey(cfg_file, name, pwfile=PWFILE):
       print('Failed to generate root key')
       sys.exit(1)

   # Self-sign the root certificate
   if not root.selfsign(name, pwfile=PWFILE):
       print('Failed to self-sign root csr')
       sys.exit(1)

   # Cleanup the temporary password file
   os.unlink(PWFILE)

Setting up the Intermediary CA
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
The following example shows how to configure the Intermediary CA and all its
relevant files. Note, this example assumes that you've configured the Root CA
according to the example above::

   intermediary = OpenSSL(config, CA_INTERMEDIARY)
   name = intermediary.ca_data['name']
   cfg_file = intermediary.ca_data['cfg']
   csr = intermediary.ca_data['csr']
   crt = intermediary.ca_data['crt']
   days = intermediary.ca_data['days']

   # Temporary file containing the (unencrypted) CA password
   PWFILE = 'password.temp'
   open(PWFILE, 'w').write('some password')

   # Generate the directory structure for this CA
   if not intermediary.setup_ca_structure():
       print('Failed to initialize intermediary CA')
       sys.exit(1)

   # Generate the key and CSR for this CA
   if not intermediary.genkey(cfg_file, name, pwfile=PWFILE):
       print('Failed to generate intermediary key')
       sys.exit(1)

   # Sign the CSR using the Root CA's key
   if not root.sign_intermediary(csr, crt, PWFILE, days):
       print('Failed to sign intermediary csr')
       sys.exit(1)

   # Cleanup the temporary password file
   os.unlink(PWFILE)

Setting up the Autosign CA
,,,,,,,,,,,,,,,,,,,,,,,,,,
The following example creates the Autosign CA, and assumes that the root and
intermediary CA's have been configured according to the examples above::

   autosign = OpenSSL(config, CA_AUTOSIGN)
   name = autosign.ca_data['name']
   cfg = autosign.ca_data['cfg']
   csr = autosign.ca_data['csr']
   crt = autosign.ca_data['crt']
   days = autosign.ca_data['days']

   # Temporary file containing the (unencrypted) CA password
   PWFILE = 'password.temp'
   open(PWFILE, 'w').write('some password')

   # Create the directory structure for this CA
   if not autosign.setup_ca_structure():
       print('Failed to initialize autosign CA')
       sys.exit(1)

   # Generate a key and certificate for this CA
   if not autosign.genkey(cfg, name):
       print('Failed to generate autosign key')
       sys.exit(1)

   # Sign the CSR using the intermediary CA key
   if not intermediary.sign_intermediary(csr, crt, PWFILE, days):
       print('Failed to sign autosign csr')
       sys.exit(1)

   # Cleanup the temporary password file
   os.unlink(PWFILE)
 
Generate a new TLS server certificate
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
The following example shows how to generate a new TLS server certificate,
which can be used on servers for both server and client authentication. It
assumes that you've configured the whole PKI stack as shown above::

   SERVER_FQDN = 'test.host.name'
   SERVER_CFG = './workspace/{0}.cfg'.format(SERVER_FQDN)

   # Generate the configuration file for the TLS server request
   cfg = autosign.gen_server_cfg(SERVER_FQDN)
   open(SERVER_CFG, 'w').write(cfg)

   # Generate a key and certificate for this host
   if not autosign.genkey(SERVER_CFG, SERVER_FQDN):
       print('Failed to generate key for {0}'.format(SERVER_FQDN))
       sys.exit(1)

   # Sign the CSR using the Autosign CA key
   if not autosign.sign(SERVER_FQDN):
       print('Failed to sign csr for {0}'.format(SERVER_FQDN))
        sys.exit(1)

API documentation for pkilib.ssl.OpenSSL
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
.. autoclass:: pkilib.ssl.OpenSSL
   :members:
