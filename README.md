<H1>Zero-Touch Provisioning of NGFWv on CSP2100<H1>

# Introduction

The python script which attached here is a simple script (without any function or classes) to orchestrate the NGFWv on CSP2100 using the CSP2100 and Firepower Management Center(FMC) APIs and using the NGFWv Day0 configuration file.

Please note: Some of the code which I used here can be modified with the best options and some of the sections of this code can be functionalized. But that is not the intention of this script. This is to show you how useful the api explorer on providing the details for each supported features with example and how easy to generate the required scripts from the api explorer itslef. 

The Cisco Firepower® NGFW (next-generation firewall) is the industry’s first fully integrated, threat-focused next-gen firewall with unified management. It uniquely provides advanced threat protection before, during, and after attacks

Cisco Firepower NGFWv is available on VMware, KVM, and the Amazon Web Services (AWS) and Microsoft Azure environments for virtual, public, private, and hybrid cloud environments. Organizations employing SDN can rapidly provision and orchestrate flexible network protection with Firepower NGFWv. As well, organizations using NFV can further lower costs utilizing Firepower NGFWv.

Firepower Management center used to manage the critical Cisco network security solutions. It provides complete and unified management over firewalls, application control, intrusion prevention, URL filtering, and advanced malware protection. Easily go from managing a firewall to controlling applications to investigating and remediating malware outbreaks.

The Firepower Management Center natively provides RESTful API support to configure the NGFWv features.
It also has the API Explorer which provides details documentation with examples and you can generate the python script directly from the API explorer portal.

The API Explorer resides on the Firepower Management Center, and can be accessed via the Firepower Management Center at:
https://<management_center_IP_or_name>:<https_port>/api/api-explorer

Cisco Cloud Services Platform 2100 is purpose built platform to quickly and easily deploy virtual network services on it. Now your team can bring up these services at the pace your DevOps and server teams need, even within minutes. This open x86 Linux Kernel-based virtual machine (KVM) software and hardware platform is ideal for colocation and data center network functions virtualization (NFV).

you can quickly deploy any Cisco or third-party network virtual service through a simple, built-in, native web user interface (WebUI), command-line interface (CLI), or representational state transfer (REST) API.

Please read the prerequisite for required hardware, software and other items to run this demo sucessfully. 
Below is the URL to watch the demo video which is published in the youtube. 

https://www.youtube.com/watch?v=fc-JdMsyfpE






