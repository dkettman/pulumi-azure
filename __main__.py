import pulumi
import pulumi_tls as tls
import base64

from pulumi_azure_native import resources, network, compute
from pulumi_random import random_string
from pprint import pprint
from dataclasses import dataclass, field


# Import the program's configuration settings
config = pulumi.Config()
vm_size = config.get("vmSize", "Standard_B2s")
admin_username = config.get("adminUsername", "cs_admin")
admin_password = config.get("adminPassword", "Cyb3rS0lve!!")

# os_image_publisher, os_image_offer, os_image_sku, os_image_version = os_image.split(":")

# Get common lab resources
resource_group = resources.get_resource_group("rg-cybersolve-labs")
virtual_network = network.get_virtual_network(
    resource_group_name=resource_group.name,
    virtual_network_name="vNet-CyberSolve-Labs",
)
subnet = network.get_subnet(
    resource_group_name=resource_group.name,
    subnet_name="default",
    virtual_network_name=virtual_network.name,
)


def create_networksecuritygroup(nsg_name):
    rules = [
        network.SecurityRuleArgs(
            access=network.SecurityRuleAccess.ALLOW,
            description="Allows inbound RDP",
            destination_address_prefix="*",
            destination_port_range="3389",
            direction=network.SecurityRuleDirection.INBOUND,
            name="inboundRDP",
            priority=1001,
            protocol=network.SecurityRuleProtocol.TCP,
            source_address_prefix="*",
            source_port_range="*",
        )
    ]
    return network.NetworkSecurityGroup(
        nsg_name, resource_group_name=resource_group.name, security_rules=rules
    )


def create_network_interface(svr_name, public_ip_required=False):
    # Create a public IP address if required
    public_ip = None
    if public_ip_required:
        public_ip = network.PublicIPAddress(
            "pip-" + svr_name,
            resource_group_name=resource_group.name,
            sku=network.PublicIPAddressSkuArgs(
                name="Basic",
            ),
            public_ip_allocation_method="Dynamic",
        )
        pulumi.export("-".join(["publicIP", svr_name]), public_ip.ip_address)

    # Create a network interface
    if dc_nic != None:
        network_interface = network.NetworkInterface(
            "nic-" + svr_name,
            network_security_group=network.NetworkSecurityGroupArgs(id=nsg.id),
            resource_group_name=resource_group.name,
            dns_settings=network.NetworkInterfaceDnsSettingsArgs(
                dns_servers=[
                    dc_nic.ip_configurations[0].private_ip_address.apply(
                        lambda private_ip_address: network.get_network_interface(
                            network_interface_name=dc_nic.name,
                            resource_group_name=resource_group.name,
                        )
                        .ip_configurations[0]
                        .private_ip_address
                    )
                ]
            ),
            ip_configurations=[
                network.NetworkInterfaceIPConfigurationArgs(
                    name="ipconfig1",
                    subnet=network.SubnetArgs(
                        id=subnet.id,
                    ),
                    public_ip_address=(
                        network.PublicIPAddressArgs(id=public_ip.id)
                        if public_ip_required
                        else None
                    ),
                    primary=True,
                )
            ],
        )
    else:
        network_interface = network.NetworkInterface(
            "nic-" + svr_name,
            network_security_group=network.NetworkSecurityGroupArgs(id=nsg.id),
            resource_group_name=resource_group.name,
            ip_configurations=[
                network.NetworkInterfaceIPConfigurationArgs(
                    name="ipconfig1",
                    subnet=network.SubnetArgs(
                        id=subnet.id,
                    ),
                    public_ip_address=(
                        network.PublicIPAddressArgs(id=public_ip.id)
                        if public_ip_required
                        else None
                    ),
                    primary=True,
                )
            ],
        )

    return network_interface


def create_virtualmachine(vm_name, network_interface, os_image):
    security_profile = None
    match os_image:
        case "Windows":
            image = "MicrosoftWindowsServer:WindowsServer:2019-Datacenter:latest"
        case "Ubuntu":
            image = "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest"
        case "RHEL":
            image = "erockyenterprisesoftwarefoundationinc1653071250513:rockylinux-9:rockylinux-9:9.0.0"
        case "DC":
            image = "MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition:latest"

    os_image_publisher, os_image_offer, os_image_sku, os_image_version = image.split(
        ":"
    )

    if os_image == "Windows":
        profile = compute.OSProfileArgs(
            computer_name=vm_name,
            admin_username=admin_username,
            admin_password=admin_password,
        )
        storage_profile = compute.StorageProfileArgs(
            os_disk=compute.OSDiskArgs(
                name=f"{vm_name}-osdisk",
                create_option=compute.DiskCreateOption.FROM_IMAGE,
                delete_option=compute.DiskDeleteOptionTypes.DELETE,
            ),
            image_reference=compute.ImageReferenceArgs(
                publisher=os_image_publisher,
                offer=os_image_offer,
                sku=os_image_sku,
                version=os_image_version,
            ),
        )
    elif os_image == "DC":
        profile = None
        storage_profile = compute.StorageProfileArgs(
            os_disk=compute.OSDiskArgs(
                name=f"{vm_name}-osdisk",
                create_option=compute.DiskCreateOption.FROM_IMAGE,
                delete_option=compute.DiskDeleteOptionTypes.DELETE,
            ),
            image_reference=compute.ImageReferenceArgs(
                id="/subscriptions/c10368aa-7348-4c86-b047-33e52b5bd6c5/resourceGroups/rg-CyberSolve-Labs/providers/Microsoft.Compute/galleries/cs_vm_images/images/cs_dc_win2k22"
            ),
        )
        security_profile = compute.SecurityProfileArgs(
            security_type=compute.SecurityTypes.TRUSTED_LAUNCH
        )
    else:
        profile = compute.OSProfileArgs(
            computer_name=vm_name,
            admin_username=admin_username,
            admin_password=admin_password,
        )
        storage_profile = compute.StorageProfileArgs(
            os_disk=compute.OSDiskArgs(
                name=f"{vm_name}-osdisk",
                create_option=compute.DiskCreateOption.FROM_IMAGE,
                delete_option=compute.DiskDeleteOptionTypes.DELETE,
            ),
            image_reference=compute.ImageReferenceArgs(
                publisher=os_image_publisher,
                offer=os_image_offer,
                sku=os_image_sku,
                version=os_image_version,
            ),
        )

    return compute.VirtualMachine(
        "vm-" + vm_name,
        vm_name="vm-" + vm_name,
        resource_group_name=resource_group.name,
        network_profile=compute.NetworkProfileArgs(
            network_interfaces=[
                compute.NetworkInterfaceReferenceArgs(
                    id=network_interface.id,
                    primary=True,
                )
            ]
        ),
        hardware_profile=compute.HardwareProfileArgs(
            vm_size=vm_size,
        ),
        os_profile=profile,
        storage_profile=storage_profile,
        security_profile=security_profile or None,
    )


nsg = create_networksecuritygroup("nsg-" + pulumi.get_stack())

# Build the DC (Required for all labs)
dc_nic = None
dc_nic = create_network_interface(pulumi.get_stack() + "-dc", False)
dc_vm = create_virtualmachine(pulumi.get_stack() + "-dc", dc_nic, "DC")

servers_to_build = [
    {
        "vm_name": "app",
        "pip": True,
        "os": "Windows",
    },
    {
        "vm_name": "lin1",
        "pip": False,
        "os": "Ubuntu",
    },
    {
        "vm_name": "lin2",
        "pip": False,
        "os": "Ubuntu",
    },
]

for svr in servers_to_build:
    svr_name = pulumi.get_stack() + "-" + svr["vm_name"]
    nic = create_network_interface(svr_name, svr["pip"])
    vm = create_virtualmachine(svr_name, nic, svr["os"])

    if svr["os"] == "Windows":
        vm_ext = compute.VirtualMachineExtension(
            "vm_ext-" + svr_name,
            publisher="Microsoft.Compute",
            type="JsonADDomainExtension",
            type_handler_version="1.3",
            settings={
                "Name": "cybersolve.lab",
                "User": "cybersolve\\cs_admin",
                "domainJoinUserName": "cybersolve\\cs_admin",
                "domainFQDN": "cybersolve.lab",
                "Restart": "true",
            },
            protected_settings={
                "Password": "CyberS0lve!!",
                "domainJoinUserPassword": "Cyb3rS0lve!!",
            },
            vm_name=vm.name,
            resource_group_name=resource_group.name,
            vm_extension_name="MyCustomScriptExtension",
            opts=pulumi.ResourceOptions(
                depends_on=[
                    vm,
                    dc_vm,
                ]
            ),
        )

    pulumi.export(
        "Private IP (" + svr["vm_name"] + ")",
        nic.ip_configurations[0].private_ip_address,
    )
    pulumi.export("Username", admin_username)
