
## Skills Activation

This project has domain-specific skills available in `**/skills/**`. You MUST activate the relevant skill whenever you work in that domain—don't wait until you're stuck.


## Conventions

- All documentation and comments must be in ASD-STE100 Simplified Technical English
- You must follow all existing code conventions used in this application. When creating or editing a file, check sibling files for the correct structure, approach, and naming.
- Use descriptive names for variables and methods. For example, `isRegisteredForDiscounts`, not `discount()`.
- Check for existing components to reuse before writing a new one.

## Tests

- Tests use Pest v5
- All code must be covered by unit tests. If you add a new feature, you must also add unit tests for it.
- Tests must assert positive and negative cases, including edge cases. If you find a bug, write a test that reproduces it before fixing it.

## Code checks

- After you change PHP code, run `composer format` and then `composer analyse`.
- Run both commands before you finish the task.

Implementation plan
1. Set the package contract. Add PHPStan as a package dependency. State the supported PHP and PHPStan versions. Keep rule classes small and use descriptive names.
2. Define one report format. Each report must show a severity, a CWE number, a short reason, and a link in this form: https://cwe.mitre.org/data/definitions/79.html. Give each report a stable PHPStan error identifier. Keep severity separate from the probability score in the README: severity describes possible harm; probability describes confidence in the finding.
3. Build a small first set of web rules. Start with CWE-79 (cross-site scripting) and CWE-89 (SQL injection). For each rule, specify which PHP values it checks, where those values can cause harm, and which protections it recognises. Report only cases the rule can support. Do not claim that a type check proves a value is safe.
4. Put a simple document next to each rule. Use the same name for the class and its document. State what the rule detects, show a short unsafe PHP example, show a safe example, and list known limits. Link to the full MITRE CWE entry.
5. Make the rules easy to install and change. Provide a PHPStan configuration file that registers the rules. Let users enable rules one at a time and set a minimum probability score. Document the defaults and show the installation steps in the README.
6. Test each rule with Pest. Add tests for an unsafe case, a safe case, and relevant edge cases. Check the severity, CWE link, error identifier, and report line. Add an integration test that loads the package configuration and runs PHPStan on sample PHP files.
7. Release in stages. Complete the report format and one rule first. Use what you learn to simplify the shared code. Add the second rule only after the first rule, its document, and its tests work together. Add more web CWEs only when their detection limits are clear.