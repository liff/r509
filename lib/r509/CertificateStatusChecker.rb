require 'openssl'

class CertificateStatusChecker
    def initialize(issuer_config)
        @config = issuer_config
    end

    def get_status(certid)
        #TODO...check anything
        {:certid=>certid,:status=>OpenSSL::OCSP::V_CERTSTATUS_GOOD,:revocation_reason=>0,:revocation_time=>nil,:config=>@config}
    end
end
