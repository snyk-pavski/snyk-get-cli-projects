# Get Snyk CLI Projects 

Lists Snyk Projects originating from a CLI scan across multiple Snyk Organisations in a Group.

## Features

`get_cli_projects.py` - gathers project information for entire Snyk Orgnisation. Uses [Snyk's REST API](https://apidocs.snyk.io/).

## Configuration

Install dependencies
```sh
pip install -r requirements.txt
```

Update variables in `get_cli_projects.py`. Get the latest API Version from [Snyk's REST API](https://apidocs.snyk.io/)
```py
API_VERSION = "2024-08-15"
RATE_LIMIT_DELAY = 0.2 (in seconds)
```

## Usage

### Gather project information 

Run the script locally

```sh
python3 get_cli_projects.py --group YOUR_GROUP_ID --token YOUR_API_TOKEN
```

Script will output `project_data.json` file. Edit the file as necessary. Example below

```json
[
    {
        "snyk_product": "Snyk_Container",
        "created": "2024-10-08T15:14:59.833Z",
        "cli_monitored_at": "2024-10-08T15:24:19.752Z",
        "org_name": "*****",
        "org_id": "*****",
        "project_name": "*****",
        "project_id": "*****",
        "project_type": "deb",
        "target_file": "",
        "status": "active",
        "origin": "cli"
    }
]
