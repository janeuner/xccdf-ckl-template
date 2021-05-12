# bTitle
"bDescription"

Field | Description | Example
----- | ----------- | -------
control | A **vulnerability identifier** string that uniquely identifies the rule. | V-nnnnnn for DISA rules, or X-nnnnnn for experimental rules.
title | A **single-sentence description** of the rule being applied. | "The application must destroy the session ID value and/or cookie on logoff or browser close."
desc | A **multi-paragraph discussion** about the rule.  Discussion shall include identification of the threat, the pre-disposing conditions, and the mitigation provided by the rule. The discussion should also identify dependencies amongst rules, wherever applicable. |
desc 'rationale' | When the rule is overridden by a system owner, provide a **single-paragraph rationale** that describe the mitigating conditions/controls.  Otherwise, leave this value empty. | "CAC authentiation does not apply."
desc 'check' | A **multi-paragraph procedure** to confirm that a procedure has been implemented. |
desc 'fix' | A **multi-paragraph procedure** to implement a procedure. |
impact | *unused* |
tag severity | CAT III: *low*; CAT II: *medium*; CAT I: *high* |
tag gtitle | A **Rule Name** string that maps the rule to an originating SRG requirement. | SRG-APP-000220-DB-000149, where SRG-APP-000220 is a rule from the *ASD STIG*, DB-000149 is tailored to the *Database SRG*. The rule name is then used in the PostgreSQL STIG.
tag gid | (optional) auto populated from *title* - not currently supported |
tag rid | (required) Rule ID; must be populated for each rule.  Should be unique. | *SV-214049r508027_rule*
tag stig_id | (optional) STIG ID; not currently supported | PGS9-00-000200
tag fix_id | (optional) Fix ID; not currently supported | F-15263r360779_fix
tag cci | (optional) One or more DoD CCIs. Associates this rule with RMF assessment procedures. | ['CCI-000134']
tag legacy | (optional) One or move legacy identifiers. | ['SV-87495', 'V-72843']
tag nist | (optional) One or more RMF Controls.  Associates this rule with NIST RMF controls. | ['AU-9', 'IA-5 (1) (c)']