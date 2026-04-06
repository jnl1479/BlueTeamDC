# BlueTeamDC
Powershell script to configure remoting for ansible.
```
$url = "https://raw.githubusercontent.com/ansible/ansible-documentation/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
Invoke-WebRequest -Uri $url -OutFile setup.ps1
.\setup.ps1
```

Powershell commands to remove Windows Defender
```
Uninstall-WindowsFeature -Name Windows-Defender
```
