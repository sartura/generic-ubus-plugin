# Content
* About
* Usage

# About
The test samples and the test run code is provided with the plugin. The test
data is provided in the TOML file. The tests cover:
* modification of the generic ubus YANG module
    * add, modify, delete
* retrieving the state data for the registered ubus objects
* RPC calls
    * ubus call
    * module install
    * feature enable/disable

# Usage
Procedure to run the tests:

```
go run netconf.go
```