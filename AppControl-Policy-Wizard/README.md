# App Control Policy Wizard

This is the production successor to the legacy wizard under `WDAC-Policy-Wizard`. It is being delivered through a capability-by-capability strangler migration so both applications can be validated side by side.

Included interactions:

- Fluent navigation, Mica backdrop, system theme support, and responsive layout
- A single create/edit flow sourced from Signed and reputable, Windows only, or an existing policy
- Automatic output naming under the user's `Documents\AppControl` folder
- Inline validation and a review screen
- Unique policy ID, base policy ID, friendly name, and version `1.0.0.0`
- Real creation of a multiple-policy XML and compiled `.cip`

Template sources receive a new policy identity. Existing policy sources preserve their identity, rules, and options while automatically incrementing the least-significant version field with the production wizard's UInt16 rollover behavior. Edited policies use the `<source>_v<new-version>.xml` naming convention. The current milestone does not customize rules or policy options, and event-derived rule creation is not included.

## Architecture

- `src\AppControl.PolicyWizard.Core` contains WinUI-independent policy models, XML inspection, versioning, output planning, and workflow orchestration.
- `src\AppControl.PolicyWizard.Infrastructure.Windows` contains Windows PowerShell and ConfigCI integration.
- `src\AppControl.PolicyWizard.WinUI` contains presentation, navigation, and application composition.
- `tests\AppControl.PolicyWizard.Core.Tests` verifies policy behavior without requiring WinUI or ConfigCI.
- `tests\AppControl.PolicyWizard.Parity.Tests` validates migrated behavior against legacy policy assets and expectations.
- `migration\capabilities.json` is the source of truth for the migration burndown.

View the current side-by-side burndown with:

```powershell
.\AppControl-Policy-Wizard\migration\Get-Burndown.ps1
```

Capabilities advance from `legacy-only` through characterization, implementation, validation, and eventual legacy retirement. A legacy workflow is not removed until its successor evidence is recorded and validated.

Each capability also has a product-decision state. Substantive workflow changes move from `pending-review` to `proposed` and then `accepted` through a design checkpoint before implementation. Validated capabilities must have an accepted target direction.

## Continuous integration

The `App Control Policy Wizard` workflow runs the core and parity suites, builds ARM64 and x64, and publishes the current migration burndown. It is path-scoped so the legacy wizard's existing build remains independent.

## Run

Install the .NET 8 SDK and enable **Windows Developer Mode**, then run:

```powershell
dotnet run --project .\AppControl-Policy-Wizard\src\AppControl.PolicyWizard.WinUI\AppControl.PolicyWizard.WinUI.csproj -p:Platform=ARM64
```

Use `-p:Platform=x64` on an x64 development machine.

The project uses Microsoft's WinApp build tooling to register a temporary debug package identity before launch.

Enabling Developer Mode requires administrator approval in Windows Settings under **System > Advanced > For developers**.
