# ATDP - Domain Controller Automation Scripts
----


## Certificate Functions

* `cert_gen_config.psd1` - template configuration file for certificate generation
* `gen_all_cert_requests.ps1` - wrapper script to generate certifcate signing requests for each domain controller listed in the config file
* `gen_client_csr.ps1` - individual script to generate a CSR for a single server (copied to individual servers and run by the wrapper script)
* `import_all_certs.ps1` - wrapper script to import all of the signed client certificates for each domain controller listed in the config file
* `import_client_cert.ps1` - individual script to import a signed certificate file (as well as the root-ca and intermediate-ca certs) for a single server (copied to individual servers and run by the wrapper script)
* `cert_functions.psm1` - module with certificate functions
* `remove_atdp_certs.ps1` - remove the atdp certificates from the computer it's run from (used in deprovisioning)

NOTE: when using these scripts, the administrator should first configure the `cert_gen_config.psd1` file appropriately for their environment.
## Event Forwarding GPO Configuration

* `event_forwarding_module_functions.psm1` - function definitions for event forwarding module
* `configure_windows_event_forwarding.ps1` - wrapper script to configure windows event forwarding GPO for domain controllers
* `test_wec_connectivty.ps1` - script to test WEC connectivity (with certificate authentication) after certificates are configured.
* `test_all_client_configurations.ps1` - test WEC configuration and connectivity (with certificate auth) on all hosts configured in the `cert_get_config.psd1` file; also requires an `atdp_subscription_data.psd1` configuration file to define the wec hostname and issuer CA thumbprint. Should be run with the `-Verbose` argument to ensure the best detail.

NOTE: running either `configure_windows_event_forwarding.ps1` or `test_wec_connectivity.ps1` will force the user to configure the WEC and Issuer CA if no confiruation file is present.

## Setting Domain SACLs and Proper Audit Policy for Detectors

* `set_domain_sacls.ps1` - sets the domain SACLs on all objects required for proper audit record events to be generated that the detectors look for