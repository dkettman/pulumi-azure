import pulumi
from pulumi_azure_native import resources, network, compute
from pulumi_random import random_string
from pprint import pprint
import pulumi_tls as tls
import base64

# Import the program's configuration settings
config = pulumi.Config()
lab_name = config.get("labName", "default")
vm_size = config.get("vmSize", "Standard_B2s")
os_image = config.get(
    "osImage", "WindowsServer:MicrosoftWindowsServer:2019-Datacenter:latest"
)
admin_username = config.get("adminUsername", "cs_admin")

os_image_publisher, os_image_offer, os_image_sku, os_image_version = os_image.split(":")

# Create an SSH key
ssh_key = tls.PrivateKey(
    "ssh-key",
    algorithm="RSA",
    rsa_bits=4096,
)

# Get common lab resources
resource_group = resources.get_resource_group("rg-cybersolve-labs")
virtual_network = network.get_virtual_network(
    resource_group_name=resource_group.name, virtual_network_name="vNet-CyberSolve-Labs"
)
subnet = network.get_subnet(
    resource_group_name=resource_group.name,
    subnet_name="default",
    virtual_network_name=virtual_network.name,
)


def create_publicip(pip_name):
    return network.PublicIPAddress(
        pip_name,
        public_ip_address_name=pip_name,
        resource_group_name=resource_group.name,
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


def create_network_interface(nic_name, nsg):
    return network.NetworkInterface(
        resource_name=nic_name,
        network_interface_name=nic_name,
        resource_group_name=resource_group.name,
        network_security_group=nsg,
        ip_configurations=[
            network.NetworkInterfaceIPConfigurationArgs(
                name="ipconfig1",
                subnet=network.SubnetArgs(id=subnet.id)
            )
        ]
    )


mynsg = create_networksecuritygroup("mynsg")
# nsg = network.get_network_security_group(
#     network_security_group_name=mynsg, resource_group_name=resource_group
# )
nic = create_network_interface("mynic", mynsg)

# # Create a network interface with the virtual network, IP address, and security group
# network_interface = network.NetworkInterface(
#     "network-interface",
#     resource_group_name=resource_group.name,
#     network_security_group=network.NetworkSecurityGroupArgs(
#         id=security_group.id,
#     ),
#     ip_configurations=[
#         network.NetworkInterfaceIPConfigurationArgs(
#             name=f"{vm_name}-ipconfiguration",
#             private_ip_allocation_method=network.IpAllocationMethod.DYNAMIC,
#             subnet=network.SubnetArgs(
#                 id=virtual_network.subnets.apply(lambda subnets: subnets[0].id),
#             ),
#             public_ip_address=network.PublicIPAddressArgs(
#                 id=public_ip.id,
#             ),
#         ),
#     ],
# )

# # Define a script to be run when the VM starts up
# init_script = f"""#!/bin/bash
#     echo '<!DOCTYPE html>
#     <html lang="en">
#     <head>
#         <meta charset="utf-8">
#         <title>Hello, world!</title>
#     </head>
#     <body>
#         <h1>Hello, world! 👋</h1>
#         <p>Deployed with 💜 by <a href="https://pulumi.com/">Pulumi</a>.</p>
#     </body>
#     </html>' > index.html
#     sudo python3 -m http.server {service_port} &
#     """

# # Create the virtual machine
# vm = compute.VirtualMachine(
#     "vm",
#     resource_group_name=resource_group.name,
#     network_profile=compute.NetworkProfileArgs(
#         network_interfaces=[
#             compute.NetworkInterfaceReferenceArgs(
#                 id=network_interface.id,
#                 primary=True,
#             )
#         ]
#     ),
#     hardware_profile=compute.HardwareProfileArgs(
#         vm_size=vm_size,
#     ),
#     os_profile=compute.OSProfileArgs(
#         computer_name=vm_name,
#         admin_username=admin_username,
#         custom_data=base64.b64encode(bytes(init_script, "utf-8")).decode("utf-8"),
#         linux_configuration=compute.LinuxConfigurationArgs(
#             disable_password_authentication=True,
#             ssh=compute.SshConfigurationArgs(
#                 public_keys=[
#                     compute.SshPublicKeyArgs(
#                         key_data=ssh_key.public_key_openssh,
#                         path=f"/home/{admin_username}/.ssh/authorized_keys",
#                     ),
#                 ],
#             ),
#         ),
#     ),
#     storage_profile=compute.StorageProfileArgs(
#         os_disk=compute.OSDiskArgs(
#             name=f"{vm_name}-osdisk",
#             create_option=compute.DiskCreateOption.FROM_IMAGE,
#         ),
#         image_reference=compute.ImageReferenceArgs(
#             publisher=os_image_publisher,
#             offer=os_image_offer,
#             sku=os_image_sku,
#             version=os_image_version,
#         ),
#     ),
# )

# # Once the machine is created, fetch its IP address and DNS hostname
# vm_address = vm.id.apply(
#     lambda id: network.get_public_ip_address_output(
#         resource_group_name=resource_group.name,
#         public_ip_address_name=public_ip.name,
#     )
# )

# Export the VM's hostname, public IP address, HTTP URL, and SSH private key
pulumi.export("resourceGroup", resource_group.name)
pulumi.export("virtualNetwork", virtual_network.name)
pulumi.export("subnet", subnet.name)
