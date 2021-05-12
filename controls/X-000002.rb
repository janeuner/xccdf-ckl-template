# encoding: UTF-8

control 'X-000002' do
  title "The organization must protect authenticator content from unauthorized disclosure."
  desc  "The use of hard-coded passwords increases the possibility of password guessing tremendously. This plugin test looks for all string literals and checks the following conditions:

  This rule is for detections of gosec/g101.  Detections are triggered on string matches for any one of:
    [ “password”, “pass”, “passwd”, “pwd”, “secret”, “token” ]

  Note: this will generate many mitigated reports.  Therefore, the check procedure is a peer review procedure for of any type of network authentication, to ensure that all authentication procedures undergo a qualified peer review.

  Open Source Documentation: https://securego.io/docs/rules/g101.html
  "
  desc  'rationale', ''
  desc  'check', "Review each report to determine likelihood that authenticator content is included in the application code.

  If the authenticator content is likely to be usable in operational environments, the finding is a CAT I.

  IASAE-certified software engineers must audit the implementation.  If the software unit implements authentication and has not been audited by a IASAE-certified software engineer, the finding is a CAT II. See DoD 8570.01-M for information about IASAE personnel requirements.

  The IASAE-certified software engineer shall classify authenticators used by the procedure according to the Authenticator/Verifier types defined by NIST SP 800-63-3B. The engineer shall audit the implementation's authentication procedure, utilizing the Credential Service Provider (CSP) requirements from DoDI 8520.03 (2021) to determine acceptance criteria.  

  For non-cryptographic authentication procedures:

  1) The engineer confirms that the implementation elicits the following capabilities:
  • resistance to brute-force attacks
  • resistance to request replay
  • resistance to offline attacks
  If the IASAE engineer should determines any of the conditions are not met, the finding is a CAT II.

  2) If the engineer determines that the non-cryptographic authentication procedure is utilized for OT&E or Production deployments, the finding is a CAT II.  These deployments should implement to DoD PKI or other cryptographic authenticator.

  3) If the engineer confirms that the non-cryptographic authentication procedure is NOT utilized for OT&E and Production deployments, it is not a finding.
  
  For cryptographic authentication procedures:

  1) The engineer confirms that the implementation requires use of mandated cryptographic algorthms and key lengths.  For unclassified data protection, refer to NIST 800-131A. For SECRET or TOP SECRET data protection, see V-70189 in the DISA Application Security and Development Security Technical Implementation Guide (STIG).  If these requirements are not met, the finding is a CAT II.

  2) The engineer reviews OT&E or Production deployments for use of DoD PKI.  If DoD PKI (as described by DODI 8520.02) can be used for authentication, and a non-DoD PK is being used, the finding is a CAT III.  At the time of this writing, this only applies when X.509 certificates are being used to for cryptographic authentication. 
  
  3) Otherwise, it is not a finding.
"
  desc  'fix', "
  Implement DoD PKI in accordance with DoDI 8520.03. 

  Implement a cryptographic authentication in accordance with NIST SP 800-131A or V-70189.

  Implement resistance to brute-force attacks,  request replay, and offline attacks.
"
  impact 0.5
  tag severity: 'high'
  tag gtitle: 'IA-5-GOSEC-000001'
  tag gid: 'gid_unused'
  tag rid: 'gosec-g101_rule'
  tag stig_id: 'stig_id_unused'
  tag fix_id: 'fix_id_unused'
  tag cci: ['CCI-000183']
  tag nist: ['IA-5 h']
end
