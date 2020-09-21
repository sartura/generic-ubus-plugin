# Sysrepo Generic UBUS plugin (DT)

## Introduction

This Sysrepo plugin is responsible for bridging OpenWrt [**ubus**](https://openwrt.org/docs/techref/ubus) and Sysrepo/YANG RPC mechanism.

Generic ubus plugin enables registering a ubus object (a.k.a. ubus path) and
its methods with designated messages in the dedicated generic ubus YANG model.
All ubus objects that are listed in the generic ubus YANG module are used to
retrieve the ubus data and present them as sysrepo state data. Every ubus object
that is listed in the generic ubus YANG model should have its own YANG module
that describes the resulting data and how it should be presented. For more
information on how to write a ubus-specific YANG module follow the link:
[How to write ubus-specific YANG module](https://github.com/sartura/generic-ubus-yang-modules).

The state data is previewed when a NETCONF `get` request is issued on YANG module
for a given ubus object according to its YANG module definition.

Description of the generic ubus YANG module will be provided as well as an
example of the configuration data in XML format.

Additional features of the plugin include various RPC calls. In the plugin there
are three RPC calls: (1) Ubus call RPC, (2) module install RPC and (3) feature
enable/disable RPC call.

Detailed description of the RPC calls, how to issue them and RPC responses are
provided in the following sections.

Test example data is provided in the plugin. For detailed explanation, read the
dedicated test README.md

## Development Setup

Setup the development environment using the provided [`setup-dev-sysrepo`](https://github.com/sartura/setup-dev-sysrepo) scripts. This will build all the necessary components and initialize a sparse OpenWrt filesystem.

Subsequent rebuilds of the plugin may be done by navigating to the plugin source directory and executing:

```
$ export SYSREPO_DIR=${HOME}/code/sysrepofs
$ cd ${SYSREPO_DIR}/repositories/plugins/generic-ubus-plugin

$ rm -rf ./build && mkdir ./build && cd ./build
$ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_PREFIX_PATH=${SYSREPO_DIR} \
		-DCMAKE_INSTALL_PREFIX=${SYSREPO_DIR} \
		-DCMAKE_BUILD_TYPE=Debug \
		..
-- The C compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
[...]
-- Configuring done
-- Generating done
-- Build files have been written to: ${SYSREPO_DIR}/repositories/plugins/generic-ubus-plugin/build

$ make && make install
[...]
[100%] Linking C executable sysrepo-plugin-dt-generic-ubus
[100%] Built target sysrepo-plugin-dt-generic-ubus
[100%] Built target sysrepo-plugin-dt-generic-ubus
Install the project...
-- Install configuration: "Debug"
-- Installing: ${SYSREPO_DIR}/bin/sysrepo-plugin-dt-generic-ubus
-- Set runtime path of "${SYSREPO_DIR}/bin/sysrepo-plugin-dt-generic-ubus" to ""

$ cd ..
```

Before using the plugin it is necessary to install relevant YANG modules. For this particular plugin, the following commands need to be invoked:

```
$ cd ${SYSREPO_DIR}/repositories/plugins/dhcp
$ export LD_LIBRARY_PATH="${SYSREPO_DIR}/lib64;${SYSREPO_DIR}/lib"
$ export PATH="${SYSREPO_DIR}/bin:${PATH}"

$ sysrepoctl -i ./yang/terastream-generic-ubus@2019-06-28.yang
```

## YANG Overview

The `terastream-generic-ubus` YANG module with the `ts-gu` prefix consists of the following `container` paths:

* `/terastream-generic-ubus:generic-ubus-config` — holds the necessary information for the generic ubus plugin

The following items are not configurational i.e. they are `rpc` call endpoints:

* `/terastream-generic-ubus:ubus-call` — ubus call mechanism for ubus objects that do not have their YANG module implemented on the system
* `/terastream-generic-ubus:module-install` — for installing a ubus-specific YANG module
* `/terastream-generic-ubus:feature-update` — for enabling and disabling features for a YANG module

The YANG module structure is shown below:
```
container generic-ubus-config {
    leaf ubus-object-filter-file {
        type string;
    }
    list ubus-object {
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
ubus objects for which the state data wants to be previewed.


The ubus object YANG list contains necessary information to uniquely identify a
ubus object, YANG leaf `name` and its YANG module, and YANG leaf `yang-module`
which holds the state data representation. Along with the ubus object and YANG
module name fields, the ubus object contains a YANG list `method`, that
represents all the ubus methods that the given ubus object supports.

The `method` YANG list contains necessary information to identify the method and
additionally enables specifying the method arguments, referred to as `message`.

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

This section covers the ubus call RPC and shows an example on how the RPC call
can be invoked and what responses to expect.

The RPC enables executing a ubus call command for a specific ubus object and its
method with an optional message. YANG definition for the ubus call RPC is listed
below:

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
need to be called on the system. The `ubus-invocation` YANG list contains the
ubus object name, YANG leaf `ubus-object`, ubus method name, YANG leaf
`ubus-method` and the ubus method message, YANG leaf `ubus-method-message`.

The output of the YANG RPC statement contains a list of ubus results denoted
in a YANG list `ubus result`. The list contains two YANG leaf elements: (1)
`ubus-invocation`, a string that contains the ubus call command that was
executed and (2) `ubus-response`, a string in JSON format containing the ubus
call response.

The cardinality of the YANG RPC statement elements is as follows:

| YANG element        | cardinality |
|---------------------|:-----------:|
| input                             |
| ubus-invocation     |      0..n   |
| ubus-object         |      1      |
| ubus-method         |      1      |
| ubus-method-message |      0..1   |
| output                            |
| ubus-result         |      0..n   |
| ubus-invocation     |      1      |
| ubus-response       |      1      |

This section covers the module install RPC. The module is used for installing
a new YANG module regarding ubus calls from a NETCONF client using the generic
ubus plugin.

The YANG RPC statement for the module install RPC is defined as follows:

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

The input of the YANG RPC statement contains a YANG leaf-list of the module name
that needs to be installed. The module name needs to be provided alongside the
path (absolute or relative) to the YANG module.

The output statement of the RPC YANG statement contains a YANG list named
`module-install-result` that consist of the module name (with path to the
module) and the status of the module install command.

| YANG element               | cardinality |
|----------------------------|:-----------:|
| input                                    |
| module-name-full           |    0..n     |
| output                                   |
| module-install-result      |    0..n     |
| module-name-full           |    1        |
| module-install-status      |    1        |

This section covers the feature enable/disable YANG RPC call. This YANG RPC is
used to provide feature enable/disable operations for ubus-specific YANG modules
by using the generic ubus plugin.

The YANG RPC statement for the feature enable/disable RPC is defined as follows:

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

The input of the YANG RPC is a YANG list `feature-update-invocation` containing
the YANG leafs `module-name` and `feature-name`. Additionally, it contains
a choice statement which enables selecting one of two YANG presence containers
that indicate if the feature should be enabled or disabled.

The output of the YANG RPC is a YANG list `feature-update-result` containing
a YANG leaf statement `feature-invocation-full` for the feature and module that
were used, and a YANG leaf statement `feature-update-status` that holds
information on the command execution status.


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
* if an enable container exists, the disable container must not exist and vice versa
</span>



## Running and Examples

This plugin is installed as the `sysrepo-plugin-dt-generic-ubus` binary to `${SYSREPO_DIR}/bin/` directory path. Simply invoke this binary, making sure that the environment variables are set correctly:

```
$ sysrepo-plugin-dt-generic-ubus
[INF]: plugin: Starting session ...
[INF]: Session 3 (user "...") created.
[INF]: plugin: Initializing plugin ...
[INF]: plugin: sr_plugin_init_cb
[INF]: Scheduled changes not applied because of other existing connections.
[INF]: Session 4 (user "...") created.
[INF]: plugin: Subcribing to module change
[INF]: plugin: Subscribing to ubus call rpc
[INF]: plugin: Subscribing to module install rpc
[INF]: plugin: Subscribing to feature update rpc
[INF]: plugin: Succesfull init
[...]
```

Output from the plugin is expected as the plugin has no UCI configuration to load from the device into either the `startup` or the `running` datastore. This can be show by invoking the following commands:

```
$ sysrepocfg -X -d startup -f json -m 'terastream-generic-ubus'
{

}

$ sysrepocfg -X -d running -f json -m 'terastream-generic-ubus'
{

}
```

Below is a simple example of a ubus object being tracked by the generic ubus
plugin YANG module. The ubus object is named `object1`, its YANG module is named
`module1` and its method `method1` contains the message `message1`.

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

Below is a simple example of how to make a YANG RPC call on the ubus object
named `object1` invoking the ubus method `method1` with no method message:

```
<ubus-call xmlns="https://terastream/ns/yang/terastream-generic-ubus">
        <ubus-invocation>
                <ubus-object>object1</ubus-object>
                <ubus-method>method1</ubus-method>
        </ubus-invocation>
</ubus-call>
```

An example response for the above RPC call:

```
<ubus-result xmlns="https://terastream/ns/yang/terastream-generic-ubus">
  <ubus-invocation>router.wireless status {"vif":wl0"}</ubus-invocation>
  <ubus-response>{"wldev":"wl0","radio":1,"ssid":"PANTERA-7666","bssid":"00:22:07:67:78:57","encryption":"WPA2 PSK","frequency":5,"channel":100,"bandwidth":80,"noise":-74,"rate":433}</ubus-response>
</ubus-result>
```

In case of an error while invoking the ubus call, NETCONF will report the error.

The example below shows the module install YANG RPC call for installing two
modules named `module1` and `module2`:

```
<module-install xmlns="https://terastream/ns/yang/terastream-generic-ubus">
        <module-name-full>/tmp/module1.yang</module-name-full>
        <module-name-full>/tmp/module2.yang</module-name-full>
</module-install>
```

An example response for the above RPC call given below shows two RPC responses:
the first shows that the module installation has completed successfully and the
second one indicates an error:

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

An example feature enable/disable YANG RPC call is shown below:

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

An example response for the above RPC call shows two possible RPC responses: the
first shows that the module installation has successfully completed and the
second one indicates an error:

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

Ubus object filtering feature is used
to enable the retrieval of ubus state data of only specific ubus
objects/methods.

The filtering feature is accomplished in the following way:
* creating a file in a desired location and adding regular expressions for ubus object that need to be filtered out,
* specifying the file path and file name in the generic ubus configuration YANG model (terastream-generic-ubus).

If the file is empty, does not exist or is not specified in the terastream-generic-ubus YANG module no ubus object will be filtered out.