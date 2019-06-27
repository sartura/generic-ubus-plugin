# Content
* About the plugin
* Configuration xml
* Ubus call RPC call
* Module install RPC call
* Feature enable/disable RPC call
* Ubus object filtering

# About the plugin
Generic ubus plugin enables to register an ubus object (a.k.a. ubus path) and
its methods with designated messages in the dedicated generic ubus YANG model.
All the ubus object that are listed in the generic ubus YANG module are used to
retrieve the ubus data and present them as sysrepo state data. Every ubus
object that is listed in the generic ubus YANG model there should have its own
YANG module that describes the resulting data and how it should be presented.
For more inforamtion on how to write ubus specific YANG module follow the link:
[How to write ubus specific YANG module]().<!-- TODO add the link to the repo-->

The state data is previewed when a NETCONF `get` request is issued on YANG module
for a given ubus object according to its YANG module definition.

Description of the generic ubus YANG module will be provided as well
as an example of the configuration data in XML format.

Additional features of the plugin include various RPC calls. In the plugin there
are three RPC calls: (1) Ubus call RPC, (2) module install RPC and (3) feature
enable/disable RPC call.

Detailed description on the RPC calls, how to issue them and RPC responses will
be provided in the following sections.

Test example data is provided in the plugin for detailed explanation read
the dedicated test [README.md]() <!-- TODO add the link -->

# Configuration xml
In this section the focus will be on the generic ubus plugin YANG module.
An explanation of the YANG module structure will be provided and every YANG
element is going to be described. Along with the description a YANG module
snippet will be provided as well as an XML example of the configurational data.

The structure of the YANG module can be seen here:
```
container generic-ubus-config {
    list ubus-objec {
        key name;
        leaf name {
            type string;
        }
        leaf yang-module {
            type string;
        }
        list method {
            key name;
            leaf name {
                type string;
            }
            leaf message {
                type string;
            }
        }
    }
}
```

The root container in the YANG module is the `generic-ubus-config` container.
The container contains a YANG list of ubus object. This enables to specify all
ubus object for which the state data wants to be previewed.


The ubus object YANG list contains necessary information to uniquely identify a
ubus object, YANG leaf `name` and its YANG module, YANG leaf `yang-module`,
holding the state data representation. Along with the ubus object and YANG
module name fields, ubus object contains a YANG list `method`, that represents
all the ubus methods that the given ubus object supports.

The `method` YANG list contains necessary information to identify the method and
additionally enables to specify the method arguments, referred to as `message`.

The cardinality of all the elements in the generic ubus YANG module for the
configurational data is as follows:

| YANG element        | cardinality |
|---------------------|:-----------:|
| generic-ubus-config |      0..1   |
| ubus object         |      0..n   |
| name                |      1      |
| yang-module         |      1      |
| method              |      0..n   |
| name                |      1      |
| message             |      0..1   |

Next follows a simple example where an ubus object named `object1` with its YANG
module named `module1` and its method `method1` with the message `message1` is
being tracked with the generic ubus plugin YANG module.

```
<generic-ubus-config xmlns="https://terastream/ns/yang/terastream-generic-ubus">
  <ubus-object>
    <name>object1</name>
    <yang-module>module1</yang-module>
    <method>
        <name>method1</name>
        <message>message1</message>
    </method>
  </ubus-object>
</generic-ubus-config>
```

# Ubus call RPC call
This section will cover the ubus call RPC and show an example on how to invoke
the RPC call and what responses to expect.

The RPC enables to execute an ubus call command for a specific ubus object and
its method with an optional message. YANG definition for the ubus call RPC is
listed below:

```
rpc ubus call {
    input {
        list ubus-invocation {
            key "ubus-object ubus-method";
            leaf ubus-object {
                type string;
            }
            leaf ubus-method {
                type string;
            }
            leaf ubus-method-message {
                type string;
            }
        }
    }
    output {
        list ubus-result {
            key ubus-invocation;
            leaf ubus-invocation {
                type string;
            }
            leaf ubus-response {
                type string;
            }
        }
    }
}
```

The input of the YANG RPC statement contains a list of ubus invocations that
need to be called on a system. The `ubus-invocation` YANG list contains the
ubus object name, YANG leaf `ubus-object`, ubus method name, YANG leaf
`ubus-method` and ubus method message, YANG leaf `ubus-method-message`.

The output of the YANG RPC statement contains a list of ubus results denoted
a YANG list `ubus result`. The list contains two YANG leaf elements:
(1) `ubus-invocation`, string that contains the ubus call command that was
executed and (2) `ubus-repons`, string in JSON format containg the ubus call
response.

The cardinality of the YANG RPC statement elements is as follows:

| YANG element        | cardinality |
|---------------------|:-----------:|
| input                             |
| ubus-invocation     |      0..n   |
| ubus-object         |      1      |
| ubus-method         |      1      |
| ubus-method-messgage|      0..1   |
| output                            |
| ubus-result         |      0..n   |
| ubus-invocation     |      1      |
| ubus-response       |      1      |


A simple example of how to make a YANG RPC call on the ubus object named
`object1` invoking the ubus method `method1` with no method message.

```
<ubus-call xmlns="https://terastream/ns/yang/terastream-generic-ubus">
        <ubus-invocation>
                <ubus-object>object1</ubus-object>
                <ubus-method>method1</ubus-method>
        </ubus-invocation>
</ubus-call>
```

An example of the response for the above RPC call.

```
<ubus-result xmlns="https://terastream/ns/yang/terastream-generic-ubus">
  <ubus-invocation>router.wireless status {"vif":wl0"}</ubus-invocation>
  <ubus-response>{"wldev":"wl0","radio":1,"ssid":"PANTERA-7666","bssid":"00:22:07:67:78:57","encryption":"WPA2 PSK","frequency":5,"channel":100,"bandwidth":80,"noise":-74,"rate":433}</ubus-response>
</ubus-result>
```

In the case of an error while invoking the ubus call the NETCONF will report the
error.

# Module install RPC call
This section will cover the module install RPC. The purpose of the module
install RPC is to enable instaling new YANG module regarding ubus calls from
a NETCONF client using the generic ubus plugin.

The YANG RPC statement, for the module install RPC is defined as follows:

```
rpc module-install {
    input {
        leaf-list module-name-full {
            type string;
        }
    }
    output {
        list module-install-result {
            key module-name-full;
            leaf module-name-full {
                type string;
            }
            leaf module-install-status {
                type string;
            }
        }
    }
}
```

The input of the YANG RPC statement contains a YANG leaf-list of the module
name that needs to be installed. The module name needs to be provided alongside
the path (absolute or relative) to the YANG module.

The output statement of the RPC YANG statement contains a YANG list named
`module-install-result` tha consist of the module name (with path to the module)
and the status of the module install command.

| YANG element               | cardinality |
|----------------------------|:-----------:|
| input                                    |
| module-name-full           |    0..n     |
| output                                   |
| module-install-result      |    0..n     |
| module-name-full           |    1        |
| module-install-status      |    1        |



The example of the module install YANG RPC call for installing two modules
named `module1` and `module2`.

```
<module-install xmlns="https://terastream/ns/yang/terastream-generic-ubus">
        <module-name-full>/tmp/module1.yang</module-name-full>
        <module-name-full>/tmp/module2.yang</module-name-full>
</module-install>
```

A possible response for the above RPC call show two possible RPC responses
one shows that the module installation has successfully completed and the other
indicates an error.

```
<module-install-result xmlns="https://terastream/ns/yang/terastream-generic-ubus">
  <module-name-full>/root/module1.yang</module-name-full>
  <module-install-status>Installation of module /root/module1.yang succeeded</module-install-status>
</module-install-result>
<module-install-result xmlns="https://terastream/ns/yang/terastream-generic-ubus">
  <module-name-full>/root/module2.yang</module-name-full>
  <module-install-status>Installation of module /root/module2.yang failed, error: 256</module-install-status>
</module-install-result>

```

# Feature enable/disable RPC call

This section will cover the feature enable/disable YANG RPC call. The purpose of
this YANG RPC is to provide feature enable/disable operations ubus specific
YANG modules by using the generic ubus plugin.

The YANG RPC statement, for the feature enable/disable RPC is defined as
follows:

```
rpc feature-update {
    input {
        list feature-update-invocation {
            key "module-name feature-name";
            leaf module-name {
                    type string;
            }
            leaf feature-name {
                    type string;
            }
            choice feature-action {
                    case enable-action {
                        container enable {
                            presence;
                        }
                    }
                    case disable-action {
                        container disable {
                            presence;
                        }
                    }
            }
        }
    }
    output {
        list feature-update-result {
            key feature-invocation-full;
            leaf feature-invocation-full {
                    type string;
            }
            leaf feature-update-status {
                    type string;
            }
        }
    }
}
```

The input of the YANG RPC is a YANG list `feature-update-invocation`, containing
the YANG leafs `module-name` and `feature-name`. Additionally it contains
a choice statement which enables to select one of two YANG presence containers
that indicate if the feature should be enabled or disabled.

The output of the YANG RPC is a YANG list `feature-udpate-result`, containing
a YANG leaf statement `feature-invocation-full` for the feature and module that
were used and a YANG leaf statement  `feature-update-status` holding the
information of the command execution status.


The cardinality of the YANG RPC statement elements is as follows:

| YANG element               | cardinality |
|----------------------------|:-----------:|
| input                                    |
| feature-update-invocation  |    0..n     |
| module-name                |    1        |
| feature-name               |    1        |
| enable*                    |    0..1     |
| disable*                   |    0..1     |
| output                                   |
| feature-update-result      |    0..n     |
| feature-invocation-full    |    1        |
| feature-update-status      |    1        |

<span>
* if enable container exists disable container must not exist and vice versa
</span>

An example for the feature enable/disable YANG RPC call is shown bellow:

```
<feature-update xmlns="https://terastream/ns/yang/terastream-generic-ubus">
        <feature-update-invocation>
                <module-name>module1</module-name>
                <feature-name>feature1</feature-name>
                <enable/>
        </feature-update-invocation>
        <feature-update-invocation>
                <module-name>module2</module-name>
                <feature-name>feature2</feature-name>
                <disable/>
        </feature-update-invocation>
</feature-update>
```

A possible response for the above RPC call show two possible RPC responses
one shows that the module installation has successfully completed and the other
indicates an error.

```
<feature-update-result xmlns="https://terastream/ns/yang/terastream-generic-ubus">
  <feature-invocation-full>module1 feature1</feature-invocation-full>
  <feature-update-status>Enabeling feature feature1 in module module1 succeeded.</feature-update-status>
</feature-update-result>
<feature-update-result xmlns="https://terastream/ns/yang/terastream-generic-ubus">
  <feature-invocation-full>module2 feature2</feature-invocation-full>
  <feature-update-status>Enabeling feature feature2 in module module2 failed. Error: 256.</feature-update-status>
</feature-update-result>

```

# Ubus object filtering
In this section the ubus object filtering feature will be discuses. The purpose
of this feature is to enable the retrieval of ubus state data of only specific
ubus objects/methods.

This is accomplished by adding a file that contains regular expressions that
determine which ubus object will bi ignored and stated date will note be
retrieved for them. The file name, and file path, is specified in the
CMakeLists.txt file. If the file does not exists or it was deleted the plugin
will print an information message and all the ubus object will be available