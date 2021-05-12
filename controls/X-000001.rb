# encoding: UTF-8

control 'X-000001' do
  title 'The application must protect from command injection.'
  desc  "A command injection attack is an attack on a vulnerable application where improperly validated input is passed to a command shell setup in the application. The result is the ability of an attacker to execute OS commands via the application.

  A command injection allows an attacker to execute their own commands with the same privileges as the application executing.

  This rule is for detections of eslint-plugin-security/detect-child-process.  The detect-child-process linter will flag instances of:
    require('child_process');
  
  The developer must ensure that business users cannot modify the input to any exec() invocations in trusted execution environments.

  Open Source Documentation: https://github.com/gkouziik/eslint-plugin-security-node/blob/master/docs/rules/detect-child-process.md
  "
  desc  'rationale', 'SYSTEMNAME does not use Javascript/Typescript in production, so findings on this linter are unlikely to be impactful and should be assessed after other CAT Is.  Therefore, the SYSTEMNAME default severity for this finding type is CAT II.'
  desc  'check', "Identify and assess the command injection points from the public, application users, or any other unprivileged actor.

  Analyze input validation procedures, taking care to consider special characters that may be used for command injection such as | ; & $ > < ' !

  If any injection points provide input to exec() invocations in trusted production execution environments, override this finding to CAT I.

  If exec() invocations in the development pipeline can only be modified as result of a peer-reviewed pull request, this is mitigated to CAT III and an accepted risk for the SYSTEMNAME software development program.
"
  desc  'fix', "
  Structured input data should be matched to defined (static const) values; and the defined values should be used to invoke commands.
  
  Unstructured input data needs to be sanitized for invalid characters. A deny list of characters is an option but it may be difficult to think of all of the characters to validate against. Also there may be some that were not discovered as of yet. An allow list containing only allowable characters or command list should be created to validate the user input. Characters that were missed, as well as undiscovered threats, should be eliminated by this list.

  General deny list to be included for command injection can be | ; & $ > < ' \ ! >> #
  
  Escape or filter special characters for Windows,   ( ) < > & * ‘ | = ? ; [ ] ^ ~ ! . \" % @ / \\ : + , ` 
  
  Escape or filter special characters for Linux, { } ( ) > < & * ‘ | = ? ; [ ] $ – # ~ ! . \" %  / \\ : + , `  
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-ESLINT-000001'
  tag gid: 'gid_unused'
  tag rid: 'eslint-plugin-security-detect-child-process_rule'
  tag stig_id: 'stig_id_unused'
  tag fix_id: 'fix_id_unused'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end

