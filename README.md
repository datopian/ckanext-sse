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

### Contributing

Contributions are welcome! Please follow these steps when contributing:

1. Fork the repository.
2. Create a feature branch.
3. Write tests and ensure they pass.
4. Submit a pull request with a detailed description of your changes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details on our guidelines and code of conduct.

## Support

If you encounter any issues or have questions, please open an issue on GitHub or reach out to the maintainers.
