use crate::negotiate::ProtocolConfig;
use crate::{NegotiatedProtocol, Ntlm, Result};

/// Identity advertised by the NTLM server in Type 2 Challenge.
#[derive(Debug, Clone)]
pub struct NtlmServerIdentity {
    pub netbios_computer_name: String,
    pub netbios_domain_name: String,
    pub dns_computer_name: String,
    pub dns_domain_name: String,
}

#[derive(Debug, Clone, Default)]
pub struct NtlmConfig {
    /// Computer name, or "workstation name", of the client machine performing the authentication attempt
    ///
    /// This is also referred to as the "Source Workstation".
    pub client_computer_name: Option<String>,
    pub server_identity: Option<NtlmServerIdentity>,
    /// Always reject NTLM authentication after receiving Type 3.
    pub always_reject_authentication: bool,
}

impl NtlmConfig {
    pub fn new(client_machine_name: String) -> Self {
        Self {
            client_computer_name: Some(client_machine_name),
            server_identity: None,
            always_reject_authentication: false,
        }
    }
}

impl ProtocolConfig for NtlmConfig {
    fn new_instance(&self) -> Result<NegotiatedProtocol> {
        Ok(NegotiatedProtocol::Ntlm(Ntlm::with_config(Clone::clone(self))))
    }

    fn box_clone(&self) -> Box<dyn ProtocolConfig> {
        Box::new(Clone::clone(self))
    }
}
