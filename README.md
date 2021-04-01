# ATDP - Domain Controller Automation Scripts
----


## Certificate Functions

* `cert_gen_config.psd1` - template configuration file for certificate generation
* `gen_all_cert_requests.ps1` - wrapper script to generate certifcate signing requests for each domain controller listed in the config file
* `gen_client_csr.ps1` - individual script to generate a CSR for a single server (copied to individual servers and run by the wrapper script)
* `import_all_certs.ps1` - wrapper script to import all of the signed client certificates for each domain controller listed in the config file
* `import_client_cert.ps1` - individual script to import a signed certificate file (as well as the root-ca and intermediate-ca certs) for a single server (copied to individual servers and run by the wrapper script)
## Event Forwarding GPO Configuration

* `event_forwarding_module_functions.psm1` - function definitions for event forwarding module
* `configure_windows_event_forwarding.ps1` - wrapper script to configure windows event forwarding GPO for domain controllers
* `test_wec_connectivty.ps1` - script to test WEC connectivity (with certificate authentication) after certificates are configured.
