# ckanext-sse

A custom CKAN extension built specifically for the Scottish and Southern Electricity Distribution Data Portal (SSEN). This extension enhances CKAN’s core functionality by introducing custom actions, validators, permission labels, and view blueprints to better support data management and user experience for SSEN.

## Features

- **Custom Package Controller Enhancements:**  
  Automatically generates and updates dataset URLs based on organizational context, ensuring consistency across the portal.

- **Advanced Permission Labeling:**  
  Dynamically assigns permission labels to datasets and users, based on dataset status, groups, organizations, and collaboration roles.

- **Custom Validators:**  
  Provides a suite of validators including:
  - `coverage_json_object`
  - `schema_json_object`
  - `resource_type_validator`
  - `schema_output_string_json`
  - `ib1_trust_framework_validator`
  - `ib1_sensitivity_class_validator`
  - `ib1_dataset_assurance_validator`

- **Metadata Schema for the UK's Energy Sector:**  
  Defines a comprehensive metadata schema based on DCAT and Dublin Core standards, tailored specifically for the UK's energy sector.

- **Extended Actions:**  
  Overrides standard CKAN actions with custom implementations for:
  - Package creation, update, display, and search.
  - Daily activity reports via `daily_report_activity`.
  - Extended search capabilities through `search_package_list`.

- **Blueprint Integration:**  
  Supplies custom blueprints for dataset views, providing additional routes and UI components tailored for the distribution data portal.

- **Resource Controller Logic:**  
  Automatically flags geospatial resources by detecting the GeoJSON format and updating resource metadata accordingly.

- **Signal Subscriptions:**  
  Integrates with CKAN’s signal system to extend or modify behavior at key events during the dataset lifecycle.

- **Password Policy:**  
  Implements SSE’s IA-5 and IA-5.1 authentication standards: passphrase strength, no reuse of the last eight passwords, and rotation every 365 days (60 for sysadmins). See [Password policy](#password-policy).

## Installation

### Prerequisites

- **CKAN v2.10.x**  
  *Note: This extension has been tested exclusively with CKAN v2.10.x.*
- Python 3.6+.

### Install via pip

```bash
pip install ckanext-sse
```

### Install from Source

Clone the repository and install the extension in editable mode:

```bash
git clone https://github.com/datopian/ckanext-sse.git
cd ckanext-sse
pip install -e .
```

## Configuration

1. **Enable the Plugin:**  
   Add `sse` to the `ckan.plugins` line in your `ckan.ini` configuration file:

   ```ini
   ckan.plugins = sse ...  # include other plugins as needed
   ```

2. **Template and Asset Directories:**  
   The extension automatically adds its custom templates and static assets. Ensure your CKAN configuration points to the correct directories if you have custom overrides.

3. **DCAT Base URI:**  
   The extension uses the `ckanext.dcat.base_uri` configuration setting to construct dataset URLs. Set this parameter in your `ckan.ini` if required:

   ```ini
   ckanext.dcat.base_uri = http://your-ckan-instance-url
   ```

## Password policy

Implements SSE’s *Standard for Identification and Authentication* IA-5 and
IA-5.1 as far as a CKAN portal can. `ckanext/sse/password_policy.py` documents
the reasoning behind each hook and maps every clause of the standard to the
code that enforces it.

**Strength.** CKAN’s only rule is “8 characters or longer”. This extension
replaces its `user_password_validator`, so the policy applies everywhere a
password is set — registration, the profile form, the forgotten-password
reset, and `user_create`/`user_update` over the API. A password must:

- be at least 12 characters, or 15 for an administration account (a CKAN
  sysadmin), up to a maximum of 128;
- not repeat the same character more than four times in a row;
- not contain ascending or descending sequences — three or more digits
  (`123`, `4321`) or four or more letters (`abcd`);
- not be a common, expected or compromised password — checked with common
  character substitutions undone, so `P@ssw0rd!` is rejected along with
  `Password123`;
- not contain the user’s username, full name or email address;
- not be a previous password with the number changed (`Welcome100` →
  `Welcome101`).

There is deliberately **no character-class requirement**. The standard prefers
passphrases and recommends the “three random word” approach, and demanding an
uppercase, a digit and a symbol works against both. Set
`ckanext.sse.password.require_character_classes = true` for a deployment that
wants one anyway.

The rules are rendered next to every password field from
`h.sse_password_policy_rules()`, which reads the same configuration the
validator does, so the hint cannot drift from what is enforced. A sysadmin is
shown the 15-character rule that will actually be applied to them.

IA-5.1 a and b ask for a list of common, expected and compromised passwords
that is “updated continually”, which a list baked into the source cannot be.
Point `ckanext.sse.password.blocklist_file` at a file of one word per line — a
compromised-password corpus, a dictionary, or both — and replacing it becomes a
deployment step rather than a release. The file is re-read when its mtime
changes, so no restart is needed. Entries are matched against the whole
password rather than as substrings, so a corpus full of ordinary English words
does not ban the passphrases the standard asks for.

**Reuse.** Every password a user has held is recorded as a hash in the
`user_password_history` table, and a new password is verified against the last
eight. The current password always counts, whatever the history length is set
to. Rows past the configured length are deleted rather than kept — they are old
credentials, so retaining more than the check consults is a liability.

**Rotation.** 365 days for ordinary users and 60 for sysadmins, per IA-5 f.
Past the window the user is redirected to the profile form on any page request
until they change their password. Logout and the forgotten-password reset stay
reachable, so the block is not a trap. The action API is exempt: an API token is
a separate credential with its own lifecycle, and answering a JSON call with a
redirect to an HTML form breaks the client rather than protecting anything.

Nothing needs migrating and nobody is locked out on the day this ships: the
history table is seeded from each user’s live password hash on their first
request, which starts a full window for them. Later changes made outside the
actions — `ckan user setpass`, for instance — are picked up the same way.

### Not enforced here

Nothing in a CKAN extension can enforce these, and they are listed so the gap
is visible rather than assumed covered:

- passwords transmitted only under TLS (IA-5.1 c) — an ingress concern;
- admin accounts not sharing a password with the holder’s AD account (f);
- passphrases not reused outside SSE;
- “not a single dictionary word” is only as good as the configured blocklist
  file; the built-in list covers common passwords, not the dictionary.

Related controls in the same standards that this extension does **not**
implement, and which need their own work: AC-7 (lock an account for 30 minutes
after six consecutive failed logons), AC-2.3 (disable accounts after 45 days
without a logon), and AC-2.5/AC-11 (idle session timeout).

### Settings

| Setting | Default | Effect |
| --- | --- | --- |
| `ckanext.sse.password.min_length` | `12` | Minimum length. Floor of 8. |
| `ckanext.sse.password.privileged_min_length` | `15` | Minimum for sysadmins. |
| `ckanext.sse.password.max_length` | `128` | Maximum length. Caps the cost of hashing an oversized submission. |
| `ckanext.sse.password.history_length` | `8` | Previous passwords that may not be reused. `0` checks only the current one. |
| `ckanext.sse.password.expiry_days` | `365` | Rotation window. `0` disables the block entirely. |
| `ckanext.sse.password.privileged_expiry_days` | `60` | Rotation window for sysadmins. |
| `ckanext.sse.password.warn_days` | `14` | How far ahead of expiry to warn, once per browser session. `0` disables. |
| `ckanext.sse.password.max_repeat` | `4` | Longest run of one repeated character still allowed. |
| `ckanext.sse.password.max_digit_sequence` | `2` | Longest run of consecutive digits still allowed. |
| `ckanext.sse.password.max_letter_sequence` | `3` | Longest run of consecutive letters still allowed. |
| `ckanext.sse.password.increment_window` | `3` | How far either side of the number to look when detecting an incremented password. |
| `ckanext.sse.password.require_character_classes` | `false` | Demand upper, lower, digit and symbol. Off, because the standard prefers passphrases. |
| `ckanext.sse.password.blocklist_file` | – | Path to a maintained blocklist, one word per line. |
| `ckanext.sse.password.extra_blocklist` | – | Extra words banned anywhere in a password, space or comma separated. |

### Note for tests

`factories.User` defaults to a ten-character `faker.password()`, which this
policy rejects, so a bare `factories.User()` raises `ValidationError` while the
plugin is enabled. Pass an explicit password — see
`ckanext/sse/tests/test_password_policy.py`.

## Usage

Once installed and configured, the extension integrates seamlessly with CKAN. Key behaviors include:

- **Dataset Creation & Editing:**  
  During creation or editing, the extension generates a consistent URL for datasets based on whether they belong to an organization or are user-created.

- **Permission Labels:**  
  Datasets and users are assigned labels such as `public`, `member-{org_id}`, `creator-{user_id}`, and collaborator-specific labels, facilitating fine-grained access control.

- **Custom Actions:**  
  Enhanced actions like `package_create`, `package_update`, and `package_search` are available for extended dataset management and reporting.

- **Geospatial Data Flagging:**  
  On resource creation, if a resource’s format is GeoJSON, it is automatically flagged as geospatial—enabling better discovery and filtering within the portal.

## Development

### Running Tests

Tests ensure the extension’s functionality remains robust. To run the tests, execute:

```bash
pytest
```

`test.ini` inherits `../ckan/test-core.ini`, which assumes CKAN’s source sits
alongside this repository. In the Docker development environment, where CKAN
lives at `/srv/app/src/ckan` and the extensions at `/srv/app/src_extensions`,
point pytest at an ini that inherits the right path and uses the `ckan_test`
database:

```bash
pytest --ckan-ini /path/to/your-test.ini ckanext/sse/tests
```

### Contributing

Contributions are welcome! Please follow these steps when contributing:

1. Fork the repository.
2. Create a feature branch.
3. Write tests and ensure they pass.
4. Submit a pull request with a detailed description of your changes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details on our guidelines and code of conduct.

## Support

If you encounter any issues or have questions, please open an issue on GitHub or reach out to the maintainers.
