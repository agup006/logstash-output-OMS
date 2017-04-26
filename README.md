# Logstash output plugin for sending data to Microsoft Operations Management Suite (OMS)

## Summary
This plugin sends Logstash events to the specified Microsoft OMS workspace.

## Installation

First, build the plugin gem:
```sh
gem build logstash-output-oms.gemspec
```

You can then install this plugin using the Logstash "plugin" or "logstash-plugin" (for newer versions of Logstash) command:
```sh
logstash-plugin install logstash-output-oms-[VERSION].gem
```

For more information, see Logstash reference [Working with plugins](https://www.elastic.co/guide/en/logstash/current/working-with-plugins.html).

## Testing

First, replace the following variables in spec/outputs/oms_spec.rb with values specific to your OMS workspace:
- let(:workspace_id) { "---- WORKSPACE ID ----" }
- let(:shared_key) { "---- SHARED KEY ----" }
- let(:log_type) { "---- LOG TYPE ----" }

Run the following command:
```sh
bundle exec rspec
```

## Configuration
### Required Parameters
__*shared_key*__

The shared access key to the target workspace.

OR

__*oms_creds_file*__

A file containing the shared access key to the target workspace.

AND

__*workspace_id*__

The OMS workspace ID.

AND

__*log_type*__

The type of logs being sent to OMS.

### Examples
```
output
{
    oms
    {
        shared_key => "XXXXXXXXXXXXXXXXXXX"
        workspace_id => "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        log_type => "syslog"
    }
}
```

## More information
We welcome you to provide feedback and/or contribute to the project.