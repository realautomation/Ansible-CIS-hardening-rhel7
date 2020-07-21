# Ansible-RHEL7-CIS-Benchmark - v1.0 - Latest

## CentOS/RHEL 7.x - CIS Benchmark Hardening Script

This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted.

This Ansible script can be used to harden a CentOS 7 machine to be CIS compliant to meet level 1 or level 2 requirements.

This role will make significant changes to systems and could break the running operations of machines. 

## System Requirements
-----------------------
```
Ansible 2.5+
CentOS/RHEL 7.x+
```

## Installation Steps
-----------------------
```
To install this via the ansible-galaxy command you'll need to run it like this:

ansible-galaxy install -p roles -r requirements.yml

With this in the file requirements.yml:

- src: https://github.com/realautomation/Ansible-CIS-hardening-rhel7.git

```
##Requirements
-------------------

You should carefully read through the tasks to make sure these changes will not break your systems before running this playbook. If you want to do a dry run without changing anything, set the below sections (rhel7cis_section1-6) to false.


## Role and Setting Variables
------------------------------
There are many role variables defined in defaults/main.yml. This list shows the most important.
	
rhel7cis_level1: Level 1 CIS requirements (Default: true)

rhel7cis_level2: Level 2 CIS requirements (Default: false)

rhel7cis_notauto: Run CIS checks that we typically do NOT want to automate due to the high probability of breaking the system (Default: false)

rhel7cis_section1: CIS - General Settings (Section 1) (Default: true)

rhel7cis_section2: CIS - Services settings (Section 2) (Default: true)

rhel7cis_section3: CIS - Network settings (Section 3) (Default: true)

rhel7cis_section4: CIS - Logging and Auditing settings (Section 4) (Default: true)

rhel7cis_section5: CIS - Access, Authentication and Authorization settings (Section 5) (Default: true)

rhel7cis_section6: CIS - System Maintenance settings (Section 6) (Default: true)

##### System Update Settings:
###### 'true' = yum update is enabled | 'false' = yum update is disabled
`rhel7cis_update: (Default: false)`


##### Selinux functions
`rhel7cis_selinux_disable: (Default: false)`

##### SELinux policy
`rhel7cis_selinux_pol: (Default: targeted)`

##### Set this value to 'true' if the machine is joined to AD/LDAP server.
##### Set this value to 'false' if the machine is not joined to AD/LDAP server.
`rhel7cis_ad_ldap_joined_machine: (Default:true)`



##### Service variables:
###### These control whether a server should or should not be allowed to continue to run these services
###### 'true' = Services are enabled | 'false' = Services are disabled

```
rhel7cis_cups_server: (Default: false)
rhel7cis_dhcp_server: (Default: false)
rhel7cis_ldap_server: (Default: false)
rhel7cis_telnet_server: (Default: false)
rhel7cis_nfs_server: (Default: false)
rhel7cis_rpc_server: (Default: false)
rhel7cis_ntalk_server: (Default: false)
rhel7cis_rsyncd_server: (Default: false)
rhel7cis_tftp_server: (Default: false)
rhel7cis_rsh_server: (Default: false)
rhel7cis_nis_server: (Default: false)
rhel7cis_snmp_server: (Default: false)
rhel7cis_squid_server: (Default: false)
rhel7cis_smb_server: (Default: false)
rhel7cis_dovecot_server: (Default: false)
rhel7cis_httpd_server: (Default: false)
rhel7cis_vsftpd_server: (Default: false)
rhel7cis_named_server: (Default: false)
rhel7cis_nfs_rpc_server: (Default: false)
rhel7cis_is_mail_server: (Default: false)
rhel7cis_bind: (Default: false)
rhel7cis_vsftpd: (Default: false)
rhel7cis_httpd: (Default: false)
rhel7cis_dovecot: (Default: false)
rhel7cis_samba: (Default: false)
rhel7cis_squid: (Default: false)
rhel7cis_net_snmp: (Default: false)
rhel7cis_allow_autofs: (Default: false)
```

##### Client application requirements:
```
rhel7cis_openldap_clients_required: (Default: false)
rhel7cis_telnet_required: (Default: false)
rhel7cis_talk_required: (Default: false)
rhel7cis_rsh_required: (Default: false)
rhel7cis_ypbind_required: (Default: false)
```

##### Set to 'true' if X Windows is needed in your environment:
`rhel7cis_xwindows_required: (Default: false)`


##### AIDE:
`rhel7cis_config_aide: (Default: true)`

###### AIDE cron settings:
```
rhel7cis_aide_cron:
  cron_user: root
  cron_file: /etc/crontab
  aide_job: '/usr/sbin/aide --check'
  aide_minute: 0
  aide_hour: 5
  aide_day: '*'
  aide_month: '*'
  aide_weekday: '*'
```


##### Time Synchronization - Use chrony or ntp(d)
```
rhel7cis_time_synchronization: (Default: chrony)

rhel7cis_time_synchronization_servers:
    - 0.pool.ntp.org
    - 1.pool.ntp.org
    - 2.pool.ntp.org
    - 3.pool.ntp.org
```

##### System network parameters (host only OR host and router)
###### if host only = false OR host and router = true
`rhel7cis_is_router: (Default: false)

##### /etc/host.allow Settings:
```
rhel7cis_enable_hosts_allow: (Default: false)
rhel7cis_host_allow:
    - "10.0.0.0/255.0.0.0"
    - "172.16.0.0/255.240.0.0"
    - "192.168.0.0/255.255.0.0"
```

##### Firewall Settings:
###### Selection of firewall package to use below | (default: firewalld)
```
 Section 3.6.1 | Ensure iptables is installed
rhel7cis_firewall: (Default: firewalld)

 Section 3.6.2 | Ensure default deny firewall policy
rhel7cis_default_deny_firewall: (Default: false)

 Section 3.6.3 | Ensure loopback traffic is configured
rhel7cis_loopback_traffic_config: (Default: true)

 Section 3.6.4 | Ensure outbound and established connections are configured
rhel7cis_firewall_outbound_rule: (Default: false)

```


##### System Accounting and Logging settings:
```
rhel7cis_max_log_file: (Default: 10)
rhel7cis_space_left_action: (Default:email)
rhel7cis_action_mail_acct: (Default:root)
rhel7cis_admin_space_left_action: (Default:halt)
rhel7cis_enable_auditd: (Default:true)
rhel7cis_sudolog: (Default:/var/log/secure)
rhel7cis_log_server: (Default: true)

```


##### System auditing settings | Select rsyslog or syslog_ng from the settings below
###### rsyslog settings are sections 4.2.1.x
###### syslog_ng settings are sections 4.2.2.x
```
 Section 4.2.1.x | rsyslog settings
 IF using rsyslog, set to true and loghost_address should be reflected here
rhel7cis_rsyslog: (Default: true)

Change the loghost address as per your environment
rhel7cis_rsyslog_loghost_address: 10.0.0.0

 Section 4.2.2.x | syslog_ng settings
 IF using syslog_ng, set to true and loghost_address should be reflected here
rhel7cis_syslog_ng: (Default: false)

Change the loghost address as per your environment
rhel7cis_syslog_ng_loghost_address: 10.0.0.0
```


##### SSH Settings:
```
 Section 5.2.2 | Ensure SSH Protocol is set to 2
rhel7cis_ssh_protocol_value: (Default: 2)

 Section 5.2.3 | Ensure SSH LogLevel is set to INFO
rhel7cis_ssh_loglevel: (Default: INFO)

 Section 5.2.4 | Ensure SSH X11 forwarding is disabled
rhel7cis_ssh_x11_forwarding: (Default: no)

 Section 5.2.5 | Ensure SSH MaxAuthTries is set to 4 or less
rhel7cis_ssh_maxAuthTries_value: (Default: 4)

 Section 5.2.6 | Ensure SSH IgnoreRhosts is enabled
rhel7cis_ssh_ignoreRhosts: (Default: yes)

 Section 5.2.7 | Ensure SSH HostbasedAuthentication is disabled
rhel7cis_ssh_hostbasedauthentication: (Default: no)

 Section 5.2.8 | Ensure SSH root login is disabled
rhel7cis_permit_ssh_root_login_disabled: (Default: true)
rhel7cis_ssh_root_login: (Default: no)

 Section 5.2.9 | Ensure SSH PermitEmptyPasswords is disabled
rhel7cis_ssh_permitEmptyPassword: (Default: no)

 Section 5.2.10 | Ensure SSH PermitUserEnvironment is disabled
rhel7cis_ssh_permitUserEnvironment: (Default: no)

 Section 5.2.11 | Ensure only strong MAC algorithms are used
rhel7cis_ssh_mac_algorithms: (Default: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,
                              umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com)
							  
 Section 5.2.12 | Ensure SSH Idle Timeout Interval is configured							  
rhel7cis_ssh_clientAliveInterval: (Default: 300)
rhel7cis_ssh_clientAliveCountMax: (Default: 0)

 Section 5.2.13 | Ensure SSH LoginGraceTime is set to one minute or less
rhel7cis_ssh_loginGraceTime: (Default: 60)

 Section 5.2.14 | Ensure SSH access is limited
rhel7cis_ssh_access_limited: (Defaul: true)
rhel7cis_sshd: (Default: allowusers: root, allowgroups: root)
```
 
##### PAM Settings:
```						
 Section 5.3.1 | Ensure password creation requirements are configured
rhel7cis_password_creation_requirements: (Default: true)
rhel7cis_pwquality_minlen: (Default: 14)
rhel7cis_pwquality_dcredit: (Default: -1)
rhel7cis_pwquality_ucredit: (Default: -1)
rhel7cis_pwquality_ocredit: (Default: -1)
rhel7cis_pwquality_lcredit: (Default: -1)

 Section 5.3.2 | Ensure lockout for failed password attempts is configured
rhel7cis_pwfailed_attempts: (Default: 5)
rhel7cis_pwunlock_time: (Default: 900)

 Section 5.3.3 | Ensure password reuse is limited
rhel7cis_pwretry_number:(Default: 3)
rhel7cis_pwreuse_number: (Default: 5)
```
##### User Accounts and Environment Settings:
```	
 Section 5.4.1.1 | Ensure password expiration is 365 days or less
rhel7cis_password_expiration: (Default: true)
rhel7_pass_max_days: (Default: 90)

 Section 5.4.1.2 | Ensure minimum days between password changes is 7 or more
rhel7cis_password_minimum_days_password_change: (Default: true)
rhel7_pass_min_days: (Default: 7)

 Section 5.4.1.3 | Ensure password expiration warning days is 7 or more
rhel7cis_password_expiration_warning: (Default: true)
rhel7_pass_warn_days: (Default: 7)

 Section 5.4.1.4 | Ensure inactive password lock is 30 days or less
rhel7cis_inactive_password_lock: (Default: true)
rhel7cis_inactive_pass_lck: (Default: 30)

 Section 5.4.2 | Ensure system accounts are non-login
rhel7cis_ensure_system_accounts_are_non_login: (Default: true)
rhel7cis_rule_5_4_2_min_uid: (Default: 1000)

 Section 5.4.4 | Ensure default user umask is 027 or more restrictive
rhel7cis_modify_default_user_umask: (Default: true)
rhel7cis_umask_default: (Default: 027)
rhel7cis_umask_shell_files: (Default: /etc/bashrc, /etc/profile)

 Section 5.6 Ensure access to the su command is restricted
rhel7cis_access_su_restricted: (Default: true)
rhel7cis_wheel_group_members: (Default: root)

```

##### User and Group Settings
```	
 Section 6.2.8 | Ensure users' home directory permissions are 750 or more restrictive
rhel7cis_modify_user_homes: (Default: true)

 Section 6.2.11 | Ensure no users have .forward files
rhel7cis_modify_dot_forward_files: (Default: true)

 Section 6.2.12 | Ensure no users have .netrc files
rhel7cis_modify_dot_netrc_files: (Default: true)

 Section 6.2.14 | Ensure no users have .rhosts files
rhel7cis_modify_dot_rhosts_files: (Default: true)

```

 



