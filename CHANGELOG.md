## 2.0.2
 - Combined the unofficial Logstash OMS output plugin with the existing HTTP output plugin (version 2.1.3)
## 2.0.1
 - Add encoding: utf-8 to spec files. This can help prevent issues during testing.
## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
