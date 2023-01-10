# PARALLEL TEST BASE MODULE
#
# Copyright 2023 SUSE LLC
# SPDX-License-Identifier: FSFAP
# Maintainer: Wayne Chen <wchen@suse.com>, qe-virt <qe-virt@suse.de>
package parallel_test_base;

use base "opensusebasetest";
use strict;
use warnings;
use POSIX 'strftime';
use DateTime;
use File::Basename;
use testapi;
use Data::Dumper;
use XML::Writer;
use IO::File;
use virt_utils qw(collect_host_and_guest_logs cleanup_host_and_guest_logs enable_debug_logging);
use Utils::Architectures;
use virt_autotest::utils qw(is_kvm_host is_xen_host check_host_health check_guest_health is_fv_guest is_pv_guest add_guest_to_hosts parse_subnet_address_ipv4 check_port_state);
use utils qw(zypper_call systemctl script_retry);
use upload_system_log;
use XML::LibXML;
use Tie::IxHash;
use version_utils qw(is_sle get_os_release);
use lockapi;
use mmapi;
use Carp;
use prepare_transactional_server 'install_additional_pkgs'; 
use multi_machine_job_base 'setup_passwordless_ssh_login';
use Utils::Systemd;
use List::MoreUtils qw(firstidx);
use List::Util 'first';
use ipmi_backend_utils qw(reconnect_when_ssh_console_broken);

our $AUTOLOAD;
our %guest_matrix = ();
tie %guest_matrix, 'Tie::IxHash';
our %guest_network_matrix = ();
tie %guest_network_matrix, 'Tie::IxHash';
our %guest_migration_matrix = ();
tie %guest_migration_matrix, 'Tie::IxHash';
our %test_result = ();
tie %test_result, 'Tie::IxHash';
%guest_network_matrix = (
	                 nat => {
		                   device => 'virbr11', 
		                   ipaddr => '192.168.124.1',
				   netmask => '255.255.255.0',
				   masklen => '24',
				   startaddr => '192.168.124.2',
				   endaddr => '192.168.124.254'
				  },
		         route => {
				    device => 'virbr12',
				    ipaddr => '192.168.125.1',
				    netmask => '255.255.255.0',
				    masklen => '24',
                                    startaddr => '192.168.125.2',
				    endaddr => '192.168.125.254'
				   },
			 host => {
				  device => 'br0'
				 },
		         bridge => {
				    device => 'br123',
				    ipaddr => '192.168.123.1',
				    netmask => '255.255.255.0',
				    masklen => '24',
				    startaddr => '192.168.123.2',
				    endaddr => '192.168.123.254'
				   }
			);

%guest_migration_matrix = (
	                   kvm => {
				   live_native => 'virsh --connect=srcuri --debug=0 migrate --verbose --live --unsafe guest dsturi',
		                   live_native_p2p => 'virsh --connect=srcuri --debug=0 migrate --verbose --live --p2p --persistent --change-protection --unsafe --compressed --abort-on-error --undefinesource guest dsturi',
                                   live_tunnel_p2p => 'virsh --connect=srcuri --debug=0 migrate --verbose --live --p2p --tunnelled --persistent --change-protection --unsafe --compressed --abort-on-error --undefinesource guest dsturi',
                                   live_native_p2p_auto_postcopy => 'virsh --connect=srcuri --debug=0 migrate --verbose --live --p2p --persistent --change-protection --unsafe --compressed --abort-on-error --postcopy --postcopy-after-precopy --undefinesource guest dsturi',
                                   live_native_p2p_manual_postcopy => 'virsh --connect=srcuri --debug=0 migrate --verbose --live --p2p --persistent --change-protection --unsafe --compressed --abort-on-error --postcopy --undefinesource guest dsturi',
                                   offline_native_p2p => 'virsh --connect=srcuri --debug=0 migrate --verbose --offline --p2p --persistent --unsafe --undefinesource guest dsturi',
			          },
                           xen => {
				   xl_online => 'xl -vvv migrate guest dsturi',
                                   virsh_online => 'virsh --connect=srcuri --debug=0 xmigrate --verbose --undefinesource guest dsturi',
                                   virsh_live => 'virsh --connect=srcuri --debug=0 migrate --verbose --live --undefinesource guest dsturi',
			          }
			  );

sub run_test {
    my $self =shift;

    $self->set_test_run_progress;
    croak("Please overload this subroutine in children modules to run desired tests");
}       

sub pre_run_test {
    my $self = shift;

    $self->set_test_run_progress;
    check_host_health;
    cleanup_host_and_guest_logs;
}

sub post_run_test {
    my $self = shift;

    $self->set_test_run_progress;    
    my @_guest_migration_test = split(/,/, get_required_var('GUEST_MIGRATION_TESTS'));
    my $_full_test_matrix = is_kvm_host ? $parallel_test_base::guest_migration_matrix{kvm} : $parallel_test_base::guest_migration_matrix{xen};

    print "GUEST MIGRATION TEST RESULT AFTER FINISH:", Dumper(\%test_result);
    foreach my $_guest (keys %test_result) {
        foreach my $_test (keys %{$test_result{$_guest}}) {
	    if ($test_result{$_guest}{$_test}{status} ne 'PASSED') {
	        set_var('TEST_RUN_RESULT', 'FAILED');
		bmwqemu::save_vars();
                bmwqemu::load_vars();
	        croak("Test run failed because certain test case did not pass");
	    }
        }
    }
    $self->create_junit_log;
    set_var('TEST_RUN_RESULT', 'PASSED');
    bmwqemu::save_vars();
    bmwqemu::load_vars();
}   

sub run {
    my ($self) = @_; 

    $self->set_test_run_progress;
    $self->pre_run_test;
    $self->{"start_run"} = time();
    $self->run_test;
    $self->{"stop_run"} = time();
    $self->post_run_test;
}

sub get_parallel_role {
    my $self = shift;

    return get_var('PARALLEL_WITH', '') ? 'children' : 'parent';
}

sub create_barrier {
    my ($self, %args) = @_;
    $args{signal} //= '';
    croak("Signal to be created must be given") if (!$args{signal});

    foreach my $_signal (split(/ /, $args{signal})) {
        barrier_create($_signal, 2);
	record_info("$_signal(x2) barrier created");
    }
}

sub set_test_run_progress {
    my $self = shift;

    set_var('TEST_RUN_PROGRESS',  (caller(1))[3]); 
    bmwqemu::save_vars();
    bmwqemu::load_vars();
}

#sub cleanup_development_only {
#    my $self = shift;
#
#    foreach my $_guest (split(/\n/, script_output("virsh list --all --name | grep -v Domain-0"))) {
#        script_run("virsh destroy $_guest");
#	script_run("virsh undefine $_guest || virsh undefine $_guest --keep-nvram");
#    }
#
#    foreach my $_network (split(/\n/, script_output("virsh net-list --all --name | grep -v default"))) {
#        script_run("virsh net-destroy $_network");
#        script_run("virsh net-undefine $_network");
#    }
#
#    script_run("rm -f -r /var/lib/libvirt/images/*", timeout => 300);
#    script_run("cp /var/lib/libvirt/guest_sles* /var/lib/libvirt/images/", timeout => 300);
#}

sub do_local_initialization {
    my $self = shift;
    $self->set_test_run_progress;

    record_info("Local initialization");
    my $_localip = script_output("hostname -i");
    $_localip eq '127.0.0.1' ? set_var('LOCAL_IPADDR', (split(/ /, script_output("hostname -I")))[0]) : set_var('LOCAL_IPADDR', $_localip);
    my $_localfqdn = script_output("hostname -f");
    $_localfqdn eq '' ? set_var('LOCAL_FQDN', (split(/ /, script_output("hostname -A")))[0]) : set_var('LOCAL_FQDN', $_localfqdn);
    save_screenshot;
    bmwqemu::save_vars();
    bmwqemu::load_vars();
}

sub do_peer_initialization {
    my $self = shift;
    $self->set_test_run_progress;

    record_info("Peer initialization");
    my $_role = $self->get_parallel_role;
    my ($_peer_info, $_peer_vars) = $self->get_peer_info(role => $_role);
    set_var('PEER_IPADDR', $_peer_vars->{'LOCAL_IPADDR'});
    set_var('PEER_FQDN', $_peer_vars->{'LOCAL_IPADDR'});
    bmwqemu::save_vars();
    bmwqemu::load_vars();
    $self->config_ssh_pubkey_auth(addr => get_required_var('PEER_IPADDR'));
}

sub get_peer_info {
    my $self = shift;

    my $_peer = '';
    my $_peerid = '';
    my $_role = $self->get_parallel_role;
    if ($_role eq 'parent') {
        $_peer = get_children();
        $_peerid = (keys %$_peer)[0];
    }
    elsif ($_role eq 'children') {
        $_peer = get_parents();
        $_peerid = $_peer->[0];
    }

    my $_peerinfo = get_job_info($_peerid);
    my $_peervars = get_job_autoinst_vars($_peerid);
    print "Peer Job Info:", Dumper($_peerinfo);
    print "Peer Job Vars:", Dumper($_peervars);
    return ($_peerinfo, $_peervars);
}

sub config_ssh_pubkey_auth {
    my ($self, %args) = @_;
    $args{addr} //= '';
    $args{overwrite} //= 1;
    $args{host} //= 1;
    $args{die} //= 0;
    croak("The address of ssh connnection must be given") if (!$args{addr});

    assert_script_run("clear && ssh-keygen -b 2048 -t rsa -q -N \"\" -f ~/.ssh/id_rsa <<< y") if ($args{overwrite} == 1);
    my $_ret = 0;
    foreach my $_addr (split(/ /, $args{addr})) {
	record_info("Config $_addr SSH PubKey auth");
        next if (script_run("timeout --kill-after=3 --signal=9 15 ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_addr ls") == 0);
        enter_cmd("clear", wait_still_screen => 3);
        enter_cmd("ssh-copy-id -f -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa.pub root\@$_addr", wait_still_screen => 3);
        if ($args{host} == 1) {
            susedistribution::handle_password_prompt;
        }
        else {
           check_screen("password-prompt", 60);
           enter_cmd("novell", wait_screen_change => 50, max_interval => 1);
           wait_still_screen(10);
        }
        my $_temp = 1;
        $_temp = script_run("timeout --kill-after=3 --signal=9 15 ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_addr ls");
        $_ret |= $_temp;
        record_info("Guest $_addr SSH PubKeyAuth failed", "Can not establish ssh connection to guest $_addr using Public Key Authentication", result => 'fail') if ($_temp != 0);
    }
    croak("SSH public key authentication setup failed for certain system") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

sub check_host_architecture {
    my ($self, %args) = @_;

    record_info("Check host architecture");
    my $_localip = get_var('LOCAL_IPADDR');
    my $_localarch = script_output("uname -i");
    my $_peerip = get_var('PEER_IPADDR');
    my $_peerarch = script_output("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_peerip uname -i");
    save_screenshot;
    croak("Architecture $_localarch on $_localip does not match $_peerarch on $_peerip") if ($_localarch ne $_peerarch);
}

sub check_host_os {
    my ($self, %args) = @_;
    $args{role} //= 'src';

    record_info("Check host os");
    my $_ret = 0;
    my $_localip = get_var('LOCAL_IPADDR');
    my $_peerip = get_var('PEER_IPADDR');
    if (is_sle) {
        my ($_localosver, $_localossp,) = get_os_release;
        my ($_peerosver, $_peerossp,) = get_os_release("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_peerip");
        print "LOCAL OS $_localosver-sp$_localossp PEER OS $_peerosver-sp$_peerossp\n";
   	save_screenshot;
        unless (($_peerosver > $_localosver) or ($_peerosver == $_localosver and $_peerossp >= $_localossp)) {
            $_ret = 1;
            if ($args{role} eq 'src') {
                croak("Destination os $_peerosver-sp$_peerossp falls behind source os $_localosver-sp$_localossp");
	    }
	    elsif ($args{role} eq 'dst') {
                record_info("Source os $_peerosver-sp$_peerossp  falls behind destination os $_localosver-sp$_localossp");
	    }
        }
    }
    return $_ret;
}

sub check_host_virtualization {
    my $self = shift;

    record_info("Check host virtualization");
    if (is_kvm_host) {
        assert_script_run("lsmod | grep kvm");
    }
    elsif (is_xen_host) {
        assert_script_run("lsmod | grep xen");
    }
    
    if (script_run("systemctl is-active libvirtd") != 0) {
        systemctl("stop libvirtd", ignore_failure => 1); 
        systemctl("start libvirtd"); 
        systemctl("is-active libvirtd"); 
    }
    save_screenshot;
}

sub check_host_network {
    my $self = shift;

    record_info("Check host network");
    my $_localgw = script_output("ip route show default | awk \'{print \$3}\'");
    my $_localip = get_var('LOCAL_IPADDR');
    my $_peerip = get_var('PEER_IPADDR');
    my $_peergw = script_output("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_peerip ip route show default | awk \'{print \$3}\'");
    save_screenshot;
    croak("$_localip and $_peerip hosts are not in the same subnet") unless ($_localgw eq $_peergw);
}

#this needs to be tested.
sub check_host_package {
    my ($self, %args) = @_;
    $args{package} //= '';

    record_info("Check host package");
    zypper_call("--gpg-auto-import-keys ref");
    is_kvm_host ? zypper_call("in -t pattern kvm_tools") : zypper_call("in -t pattern xen_tools");
    zypper_call("in nmap libguestfs0 guestfs-tools");
    zypper_call("in $args{package}") if (!$args{package});
}

sub check_host_uid  {
    my $self = shift;

    my %_user = (qemu => 996);
    my $_local =  get_var('LOCAL_IPADDR');
    my $_peer =  get_var('PEER_IPADDR');
    my $_localuid = '';
    my $_peeruid = '';
    foreach my $_single_user (keys %_user) {
	record_info("Check $_single_user uid on host");
        $_localuid = script_output("id -u $_single_user");
        $_peeruid = script_output("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_peer id -u $_single_user");
        if ($_localuid != $_peeruid) {
            my $_ret = script_run("usermod -u $_user{$_single_user} $_single_user");
            croak("$_single_user UID modification failed on $_local") if ($_ret != 0 and $_ret != 12);
            $_ret = script_run("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_peer usermode -u $_user{$_single_user} $_single_user");
            croak("$_single_user UID modification failed on $_peer") if ($_ret != 0 and $_ret != 12);
        }
	save_screenshot;
    }
}

sub check_host_gid {
    my $self = shift;

    my %_group = (qemu => 999,
                  kvm => 998,
                  libvirt => 997
                 );
    my $_local =  get_var('LOCAL_IPADDR');
    my $_peer =  get_var('PEER_IPADDR');
    my $_localgid = '';
    my $_peergid = '';
    foreach my $_single_group (keys %_group) {
	record_info("Check $_single_group gid on host");
        $_localgid = script_output("grep ^$_single_group /etc/group|cut -d \":\" -f 3");
        $_peergid = script_output("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_peer grep ^$_single_group /etc/group|cut -d \":\" -f 3");
	save_screenshot;
        if ($_localgid != $_peergid) {
            my $_ret = script_run("groupmod -g $_group{$_single_group} $_single_group");
	    save_screenshot;
            croak("$_single_group GID modification failed on $_local") if ($_ret != 0);
            $_ret = script_run("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_peer groupmod -g $_group{$_single_group} $_single_group");
	    save_screenshot;
            croak("$_single_group GID modification failed on $_peer") if ($_ret != 0);
        }
    }
}

sub config_host_shared_storage {
    my ($self, %args) = @_;
    $args{type} //= 'nfs';
    $args{path} //= '/var/lib/libvirt/images';
    $args{role} //= 'server';
    $args{mount} //= '/var/lib/libvirt/images';

    record_info("Configure host shared storage");
    if ($args{type} eq 'nfs') {
       if ($args{role} eq 'server') {
	   my $_temppath = $args{path};
	   $_temppath =~ s/\//\\\//g;
           assert_script_run("sed -i \'/^.*$_temppath.*\$/d\' /etc/exports");
           assert_script_run("echo \"$args{path} *(rw,sync,no_root_squash,no_subtree_check)\" >> /etc/exports");
           assert_script_run("exportfs -a");
           systemctl('restart nfs-server.service');
           systemctl('status nfs-server.service');
           assert_script_run("touch $args{path}/nfsok");
           save_screenshot;
       }
       else {
           my $_nfsserver = get_var('PEER_IPADDR');
	   script_run("umount $args{mount} || umount -f -l $args{mount}");
           assert_script_run("mount -t nfs $_nfsserver:$args{path} $args{mount}");
           assert_script_run("cd ~ && ls -lah $args{mount}/nfsok");
           save_screenshot;
       }
    }
}

sub config_host_security {
    my $self = shift;

    record_info("Config host security");
    my @_security_service = ('SuSEFirewall2', 'firewalld', 'apparmor');
    foreach my $_ss (@_security_service) {
        if (script_run("systemctl is-enabled $_ss") == 0) {
            systemctl("stop $_ss");
            systemctl("disable $_ss");
            save_screenshot;
        }
    }

    if (script_run("ls /etc/selinux/config") == 0) {
        assert_script_run("sed -i -r \'s/^SELINUX=.*\$/SELINUX=disabled/g\' /etc/selinux/config");
    }

    script_run("iptables -P INPUT ACCEPT;
iptables -P FORWARD ACCEPT;
iptables -P OUTPUT ACCEPT;
iptables -t nat -F;
iptables -F;
iptables -X;
sysctl -w net.ipv4.ip_forward=1;
sysctl -w net.ipv4.conf.all.forwarding=1;
sysctl -w net.ipv6.conf.all.forwarding=1"
);
    save_screenshot;
}

sub construct_uri {
    my ($self, %args) = @_;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    $args{driver} = is_kvm_host ? "qemu" : "xen" if (!$args{driver});

    my $uri = "";
    if ($args{host} eq 'localhost') {
        $uri = "$args{driver}:///$args{path}";
	return $uri;
    }
    else {
        $uri = $args{transport} ? "$args{driver}+$args{transport}://" : "$args{driver}://";
        $uri .= "$args{user}@" if ($args{user});
        $uri .= $args{host};
        $uri .= ":$args{port}" if ($args{port});
        $uri .= "/";
        $uri .= $args{path} if ($args{path});
        $uri .= "?$args{extra}" if ($args{extra});
    }
    return $uri;
}

sub guest_under_test {
    my ($self, %args) = @_;
    $args{role} //= '';
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    $self->set_test_run_progress;
    croak("Role used to differentiate migration source from destination must be given") if (!$args{role});
   
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra}); 
    if ($args{role} eq 'src') { 
        my $_guest_under_test = get_var('GUEST_LIST', '');
        if (!$_guest_under_test) { 
            $_guest_under_test = join(" ", split(/\n/, script_output("virsh $uri list --all --name | grep -v Domain-0")));
        }    
        else {
            $_guest_under_test = join(" ", split(/,/, $_guest_under_test));
        } 
        set_var('GUEST_UNDER_TEST', $_guest_under_test);
        bmwqemu::save_vars();
        bmwqemu::load_vars();
    }
    elsif ($args{role} eq 'dst') {
        my ($_peer_info, $_peer_vars) = $self->get_peer_info(role => $self->get_parallel_role);
        set_var('GUEST_UNDER_TEST', $_peer_vars->{'GUEST_UNDER_TEST'});
        bmwqemu::save_vars();
        bmwqemu::load_vars();
    }

    foreach my $_guest (split(/ /, get_required_var('GUEST_UNDER_TEST'))) {
        %{$guest_matrix{$_guest}} = ();
	$guest_matrix{$_guest}{macaddr} = '';
	$guest_matrix{$_guest}{ipaddr} = '';
	$guest_matrix{$_guest}{nettype} = '';
	$guest_matrix{$_guest}{netname} = '';
	$guest_matrix{$_guest}{netmode} = '';
    }

    print "GUEST MATRIX AFTER INITIALIZATION:", Dumper(\%guest_matrix);
    return get_required_var('GUEST_UNDER_TEST');
}

sub initialize_test_result {
    my $self = shift;

    $self->set_test_run_progress;
    my @_guest_migration_test = split(/,/, get_var('GUEST_MIGRATION_TESTS'));
    my $_full_test_matrix = is_kvm_host ? $parallel_test_base::guest_migration_matrix{kvm} : $parallel_test_base::guest_migration_matrix{xen};
    my $_localip = get_required_var('LOCAL_IPADDR');
    my $_peerip = get_required_var('PEER_IPADDR');
    my $_localuri = $self->construct_uri;
    my $_peeruri = $self->construct_uri(host => $_peerip);

    foreach my $_guest (keys %parallel_test_base::guest_matrix) {
        while (my ($_testindex, $_test) = each(@_guest_migration_test)) {
            my $_command = $_full_test_matrix->{$_test};
            $_command =~ s/guest/$_guest/g;
            $_command =~ s/srcuri/$_localuri/g;
            $_command =~ s/dsturi/$_peeruri/g;
            $test_result{$_guest}{$_command}{status} = 'FAILED';
            $test_result{$_guest}{$_command}{test_time} = strftime("\%H:\%M:\%S", gmtime(0));
            $test_result{$_guest}{$_command}{shortname} = $_test;
            print "GUEST MIGRATION TEST RESULT AFTER INITIALIZATION:", Dumper(\%test_result);
        }
    }
    set_var('TEST_RUN_RESULT', '');
    bmwqemu::save_vars();
    bmwqemu::load_vars();
}

#this needs to be tested
sub save_guest_asset {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{xmldir} //= '/var/lib/libvirt/images';
    $args{die} //= 0;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be saved must be given") if (!$args{guest});

    my $_ret = 0;
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    foreach my $_guest (split(/ /, $args{guest})) {
	my $_temp = 1;
	$_temp = script_run("virsh $uri dumpxml $_guest > $args{xmldir}/$_guest.xml");
	$_ret |= $_temp;
	record_info("Guest $_guest asset saving failed", "Failed to save guest $_guest asset", result => 'fail') if ($_temp != 0);
    }
    save_screenshot;
    croak("Guest asset saving for certain guest failed") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

sub restore_guest_asset {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{xmldir} //= '/var/lib/libvirt/images';
    $args{die} //= 0;
    croak("Guest to be restored must be given") if (!$args{guest});

    my $_ret = 0;
    foreach my $_guest (split(/ /, $args{guest})) {
	my $_temp = 1;
        my $_guest_disk_downloaded = script_output("find $args{xmldir} -type f \\( -iname \"*$_guest*disk\" -o -iname \"*$_guest*raw\" -o -iname \"*$_guest*qcow2\" \\) | head -1", proceed_on_failure => 1);
        my $_guest_config = script_output("find $args{xmldir} -type f -iname \"*$_guest*xml\" | head -1", proceed_on_failure => 1);
	my $_guest_disk_original = script_output("xmlstarlet sel -T -t -v \"//devices/disk/source/\@file\" $_guest_config", proceed_on_failure => 1);
	$_temp = script_run("nice ionice qemu-img convert -p -f qcow2 $_guest_disk_downloaded -O qcow2 $_guest_disk_original && rm -f -r $_guest_disk_downloaded", timeout => 180);
	$_temp |= script_run("mv $_guest_config $args{xmldir}/$_guest.xml");
	$_ret |= $_temp;
        save_screenshot;
        record_info("Guest $_guest asset restoring failed", "Failed to restoring guest $_guest asset", result => 'fail') if ($_temp != 0);
    }
    croak("Guest asset restoring for certain guest failed") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

#needs test xen
sub create_guest {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{virttool} //= 'virsh';
    $args{xmldir} //= '/var/lib/libvirt/images';
    $args{xldir} //= '/var/lib/libvirt/images';
    $args{die} //= 0;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be created must be given") if (!$args{guest});

    my $_ret = 0;
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    foreach my $_guest (split(/ /, $args{guest})) {
        my $_temp = 1;
        $_temp = $args{virttool} eq 'xl' ? script_run("virsh $uri domxml-to-native --xml $args{xmldir}/$_guest.xml --format xen-xl > $args{xldir}/$_guest.cfg") : 0;
	$self->remove_guest(guest => $_guest);
	if ($args{virttool} eq 'virsh') {
            $_temp |= script_run("virsh $uri define --file $args{xmldir}/$_guest.xml --validate");
            record_info("Failed to define guest $_guest from $args{xmldir}/$_guest.xml", "Failed to define guest $_guest using virsh define --file $args{xmldir}/$_guest.xml --validate", result => 'fail') if ($_temp != 0);
	}
	elsif ($args{virttool} eq 'xl') {
            $_temp |= script_run("xl -vvv create $args{xldir}/$_guest.cfg");
            record_info("Guest $_guest creating failed", "Failed to create guest $_guest using xl -vvv create $args{xldir}/$_guest.cfg", result => 'fail') if ($_temp != 0);
	}
	$_ret |= $_temp;
        save_screenshot;
    }     
    croak("Failed to define all guests") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

#needs test xen
sub start_guest {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{virttool} //= 'virsh';
    $args{die} //= 0;
    $args{wait} //= 1;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be started must be given") if (!$args{guest});

    my @_guest_under_test = split(/ /, get_required_var('GUEST_UNDER_TEST'));
    my @_guest_macaddr = split(/ /, get_var('GUEST_UNDER_TEST_MACADDR', ''));
    my $_ret = 0;
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    foreach my $_guest (split(/ /, $args{guest})) {
        my $_temp = $args{virttool} eq 'virsh' ? 1 : 0;
        $_temp = script_run("virsh $uri start $_guest") if ($args{virttool} eq 'virsh');
	$_temp |= $self->wait_guest(guest => $_guest) if ($args{wait} == 1);
	$_ret |= $_temp;
        save_screenshot;
	record_info("Guest $_guest starting failed", "Failed to start guest $_guest by using $args{virttool} ($uri) start/create $_guest", result => 'fail') if ($_temp != 0);
    }
    croak("Failed to start all guests") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

#needs test xen
sub wait_guest {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{role} //= 'src';
    $args{die} //= 0;
    croak("Guest to wait for must be given") if (!$args{guest});
 
    my $_ret = 0; 
    if ($args{role} eq 'src') { 
        my @_guest_under_test = split(/ /, get_required_var('GUEST_UNDER_TEST'));
        foreach my $_guest (split(/ /, $args{guest})) {
	    my $_temp = 1;
            $self->check_guest_network_address(guest => $_guest);
            add_guest_to_hosts($_guest, $guest_matrix{$_guest}{ipaddr});
	    $_temp = $self->wait_guest_ssh(guest => $_guest);
	    $_ret |= $_temp;
            save_screenshot;
	    record_info("Guest $_guest waiting failed", "Failed to wait guest up and running", result => 'fail') if ($_temp != 0); 
        } 
    }
    elsif ($args{role} eq 'dst') {
        foreach my $_guest (split(/ /, $args{guest})) {
            add_guest_to_hosts($_guest, $guest_matrix{$_guest}{ipaddr});
	    my $_temp = 1;
	    $_temp = $self->wait_guest_ssh(guest => $_guest);
	    $_ret |= $_temp; 
            save_screenshot;
        }
    }
    croak("Waiting for guest up and running failed for certain guest") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

sub wait_guest_ssh {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{retry} //= 60;
    $args{die} //= 0;
    croak("Guest to be waited for must be given") if (!$args{guest});

    my $_ret = 0;
    foreach my $_guest (split(/ /, $args{guest})) {
        my $_temp = 1;
        $_temp = script_retry("nc -zvD $_guest 22", delay => 1, retry => $args{retry}, opts => '--kill-after=1 --signal=9', die => 0);
	$_ret |= $_temp;
        save_screenshot;
	record_info("Guest $_guest ssh failed", "Failed to detect open port 22 on guest $_guest", result => 'fail') if ($_temp != 0);
    }
    croak("ssh connection failed for certain guest") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

sub initialize_guest_matrix {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{role} //= '';
    croak("Role used to differentiate migration source from destination must be given") if (!$args{role});
    $args{guest} = get_required_var('GUEST_UNDER_TEST') if (!$args{guest});

    if ($args{role} eq 'src') {
        my @_guest_ipaddr = split(/ /, get_var('GUEST_UNDER_TEST_IPADDR', ''));
        my @_guest_macaddr = split(/ /, get_var('GUEST_UNDER_TEST_MACADDR', ''));
        my @_guest_nettype = split(/ /, get_var('GUEST_UNDER_TEST_NETTYPE', ''));
        my @_guest_netname = split(/ /, get_var('GUEST_UNDER_TEST_NETNAME', ''));
        my @_guest_netmode = split(/ /, get_var('GUEST_UNDER_TEST_NETMODE', ''));
            
	$self->fill_up_array(ref => \@_guest_ipaddr, guest => $args{guest}, setting => 'GUEST_UNDER_TEST_IPADDR');
        $self->fill_up_array(ref => \@_guest_macaddr, guest => $args{guest}, setting => 'GUEST_UNDER_TEST_MACADDR');
        $self->fill_up_array(ref => \@_guest_nettype, guest => $args{guest}, setting => 'GUEST_UNDER_TEST_NETTYPE');
        $self->fill_up_array(ref => \@_guest_netname, guest => $args{guest}, setting => 'GUEST_UNDER_TEST_NETNAME');
        $self->fill_up_array(ref => \@_guest_netmode, guest => $args{guest}, setting => 'GUEST_UNDER_TEST_NETMODE');

        print "GUEST IPADDR ARRAY: @_guest_ipaddr\n";
        print "GUEST MACADDR ARRAY: @_guest_macaddr\n";
        print "GUEST NETTYPE ARRAY: @_guest_nettype\n";
        print "GUEST NETNAME ARRAY: @_guest_netname\n";
        print "GUEST NETMODE ARRAY: @_guest_netmode\n";

        set_var('GUEST_UNDER_TEST_IPADDR', join(" ", @_guest_ipaddr));
        set_var('GUEST_UNDER_TEST_MACADDR', join(" ", @_guest_macaddr));
        set_var('GUEST_UNDER_TEST_NETTYPE', join(" ", @_guest_nettype));
        set_var('GUEST_UNDER_TEST_NETNAME', join(" ", @_guest_netname));
        set_var('GUEST_UNDER_TEST_NETMODE', join(" ", @_guest_netmode));
        bmwqemu::save_vars();
        bmwqemu::load_vars();
    }
    elsif ($args{role} eq 'dst') {
        my ($_peer_info, $_peer_vars) = $self->get_peer_info(role => $self->get_parallel_role);
        set_var('GUEST_UNDER_TEST_MACADDR', $_peer_vars->{'GUEST_UNDER_TEST_MACADDR'});
        set_var('GUEST_UNDER_TEST_IPADDR', $_peer_vars->{'GUEST_UNDER_TEST_IPADDR'});
        set_var('GUEST_UNDER_TEST_NETTYPE', $_peer_vars->{'GUEST_UNDER_TEST_NETTYPE'});
        set_var('GUEST_UNDER_TEST_NETNAME', $_peer_vars->{'GUEST_UNDER_TEST_NETNAME'});
        set_var('GUEST_UNDER_TEST_NETMODE', $_peer_vars->{'GUEST_UNDER_TEST_NETMODE'});
        bmwqemu::save_vars();
        bmwqemu::load_vars();
        my @_guest_under_test = split(/ /, $args{guest});
        while (my ($_index, $_element) = each(@_guest_under_test)) {
            %{$guest_matrix{$_element}} = ();
            $guest_matrix{$_element}{macaddr} = (split(/ /, get_required_var('GUEST_UNDER_TEST_MACADDR')))[$_index];
            $guest_matrix{$_element}{ipaddr} = (split(/ /, get_required_var('GUEST_UNDER_TEST_IPADDR')))[$_index];
            $guest_matrix{$_element}{nettype} = (split(/ /, get_required_var('GUEST_UNDER_TEST_NETTYPE')))[$_index];
            $guest_matrix{$_element}{netname} = (split(/ /, get_required_var('GUEST_UNDER_TEST_NETNAME')))[$_index];
            $guest_matrix{$_element}{netmode} = (split(/ /, get_required_var('GUEST_UNDER_TEST_NETMODE')))[$_index];
        }
    }
    print "GUEST MATRIX AFTER INITIALIZATION:", Dumper(\%guest_matrix);
}

sub fill_up_array {
    my ($self, %args) = @_;
    $args{ref} //= '';
    $args{guest} //= '';
    $args{setting} //= '';
    croak("Reference of array to be filled up must be given") if (!$args{ref});
    croak("Guest associated must be given") if (!$args{guest});
    croak("Setting to be referenced must be given") if (!$args{setting});

    my @_guest_under_test = split(/ /, get_required_var('GUEST_UNDER_TEST'));
    my $_guest_setting = lc ((split(/_/, $args{setting}))[-1]);
    foreach my $_guest (split(/ /, $args{guest})) {
        if (get_var($args{setting}, '')) {
	    print "IN THIS BRANCH\n";
            my $_index = firstidx { $_ eq $_guest } @_guest_under_test;
            print "FIRSTINDEX IS $_index\n";
	    $args{ref}[$_index] = $guest_matrix{$_guest}{$_guest_setting};
        }
        else {
	    print "IN THAT BRANCH\n";
            push(@{$args{ref}}, $guest_matrix{$_guest}{$_guest_setting});
        }
    }

    print "$args{setting} ARRAY: @{$args{ref}}\n";
}

sub remove_guest {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{die} //= 0;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be removed must be given") if (!$args{guest});
 
    my $_ret = 0;
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    foreach my $_guest (split(/ /, $args{guest})) {
        my $_temp = 1;
        script_run("xl -vvv destroy $_guest");
        script_run("virsh $uri destroy $_guest");
        $_temp = script_run("virsh $uri list --all | grep $_guest") == 0 ? script_run("virsh $uri undefine $_guest || virsh $uri undefine $_guest --keep-nvram") : 0;
	$_ret |= $_temp;
        save_screenshot;
	record_info("Guest $_guest removing failed", "Failed to remove guest $_guest", result => 'fail') if ($_temp != 0);
    }
    croak("Failed to remove all guests") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

#needs test xen
sub shutdown_guest {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{virttool} //= 'virsh';
    $args{die} //= 0;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be shut down must be given") if (!$args{guest});


    my $_ret = 0;
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    foreach my $_guest (split(/ /, $args{guest})) {
        my $_temp = 1;
	if ($args{virttool} eq 'virsh') {
            script_retry("virsh $uri shutdown $_guest", retry => 12, delay => 10, die => 0);
            if (script_retry("virsh $uri list  --state-shutoff | grep $_guest", retry => 12, delay => 10, die => 0) != 0) {
                script_run("virsh $uri destroy $_guest");
                $_temp = script_retry("virsh $uri list  --state-shutoff | grep $_guest", retry => 12, delay => 10, die => 0);
            }
	    else {
		$_temp = 0;
	    }
        }
	elsif ($args{virttool} eq 'xl') {
            script_retry("xl -vvv shutdown $_guest", retry => 12, delay => 10, die => 0);
            $_temp = script_retry("xl -vvv list | grep \"$_guest.*---s-- \"", retry => 12, delay => 10, die => 0);
        }
        $_ret |= $_temp;
        save_screenshot;
        record_info("Failed to stop guest $_guest", "Guest $_guest can not be stopped using $args{virttool} shutdown or destroy", result => 'fail') if ($_temp != 0);
    }
    croak("Failed to stop all guests") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

sub config_guest_clock {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{xmldir} //= '/var/lib/libvirt/images';
    $args{die} //= 0;
    croak("Guest to be configured must be given") if (!$args{guest});

    my $_ret = 0;
    foreach my $_guest (split(/ /, $args{guest})) {
	record_info("Config $_guest clock");
        my $_temp = 1;
	script_run("cp $args{xmldir}/$_guest.xml $args{xmldir}/$_guest.xml.backup");
        $_temp = script_run("xmlstarlet ed --inplace --delete \"/domain/clock\" $args{xmldir}/$_guest.xml");
	$_temp |= script_run("xmlstarlet ed --inplace --subnode \"/domain\" --type elem -n clock -v \"\" $args{xmldir}/$_guest.xml");
        $_temp |= script_run("xmlstarlet ed --inplace --insert \"/domain/clock\" --type attr -n offset -v utc $args{xmldir}/$_guest.xml");
	my $_clock = is_kvm_host ? "kvm-clock" : "tsc"; 
        $_temp |= script_run("xmlstarlet ed --inplace --insert \"/domain/clock/timer\" --type attr -n name -v $_clock --insert \"/domain/clock/timer\" --type attr -n present -v yes $args{xmldir}/$_guest.xml");
	$_ret |= $_temp;
        if ($_temp != 0) {
            script_run("mv $args{xmldir}/$_guest.xml.backup $args{xmldir}/$_guest.xml");
	    record_info("Guest $_guest clock config failed", "Failed to configure guest $_guest clock settings", result => 'fail');
        }
	save_screenshot;
    }
    croak("Clock configuration failed for certain guest") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

sub config_guest_storage {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{xmldir} //= '/var/lib/libvirt/images';
    $args{die} //= 0;
    croak("Guest to be configured must be given") if (!$args{guest});

    my $_ret = 0;
    foreach my $_guest (split(/ /, $args{guest})) {
	record_info("Config $_guest storage");
        my $_temp = 1;
	$_temp = script_run("cp $args{xmldir}/$_guest.xml $args{xmldir}/$_guest.xml.backup");
        $_temp |= script_run("xmlstarlet ed --inplace --delete \"/domain/devices/disk/driver/\@cache\" $args{xmldir}/$_guest.xml");
        $_temp |= script_run("xmlstarlet ed --inplace --insert \"/domain/devices/disk/driver[\@name=\'qemu\']\" --type attr -n cache -v none $args{xmldir}/$_guest.xml");
	$_ret |= $_temp;
        if ($_temp != 0) {
            script_run("mv $args{xmldir}/$_guest.xml.backup $args{xmldir}/$_guest.xml");
	    record_info("Guest $_guest storage config failed", "Failed to configure guest $_guest storage settings", result => 'fail');
        }	
        save_screenshot;
    }
    croak("Storage configuration failed for certain guest") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

sub config_guest_console {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{xmldir} //= '/var/lib/libvirt/images';
    $args{die} //= 0;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be configured must be given") if (!$args{guest});

    my $_host_console = '';
    my $_guest_console = '';
    if (is_kvm_host) {
        $_host_console=script_output("dmesg | grep -i \"console.*enabled\" | grep -ioE \"tty[A-Z]{1,}\" | head -1", proceed_on_failure => 1);
        $_guest_console = $_host_console ? $_host_console . 0 : 'ttyS0';
    }

    my $_ret = 0;
    my $_guest_device = '';
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    foreach my $_guest (split(/ /, $args{guest})) {
	record_info("Config $_guest console");
	my $_temp = 1;
        $_guest_console = (is_fv_guest($_guest) ? 'ttyS0' : 'hvc0') if (is_xen_host);
	script_run("virsh $uri destroy $_guest");
	print "$_temp\n";
        $_temp = script_retry("! virsh $uri list --all | grep $_guest | grep running", delay => 1, retry => 5, die => 0);
	print "$_temp\n";
        foreach my $_dev (split(/\/n/, script_output("virt-filesystems -d $_guest | grep -ioE \"^/dev.*[^@].*\$\"", proceed_on_failure => 1))) {
            if (script_run("virt-ls -d $_guest -m $_dev / | grep -ioE \"^boot\$\"") == 0) {
                $_guest_device = $_dev;
                last;
            }
        }
        $_temp |= script_run("virt-edit -d $_guest -m $_guest_device /boot/grub2/grub.cfg -e \"s/\$/ console=tty console=$_guest_console,115200/ if /.*(linux|kernel).*\\\/boot\\\/(vmlinuz|image).*\$/i\"");
	print "$_temp\n";
        $_ret |= $_temp;
	print "$_temp\n";
	print "$_ret\n";
	save_screenshot;
	record_info("Guest $_guest console config failed", "Failed to configure console $_guest_device for guest $_guest", result => 'fail') if ($_temp != 0);
    }
    croak("Console configuration failed for certain guest") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

sub show_guest {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{die} //= 1;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';

    my $_ret = 0;
    my $_uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    if (!$args{guest}) {
        $_ret = script_run("virsh $_uri list --all");
        $_ret |= script_run("xl -vvv list") if (is_xen_host);
	save_screenshot;
	record_info("Listing guests failed", "Failed to list all guests available on host", result => 'fail') if ($_ret != 0);
    }
    else {
        foreach my $_guest (split(/ /, $args{guest})) {
	    my $_temp = 1;
	    $_temp = script_run("virsh $_uri list --all | grep $_guest");
            $_ret |= $_temp;
            save_screenshot;	    
            record_info("Guest $_guest listing failed", "Failed to list guest $_guest", result => 'fail') if ($_temp != 0);
        }
    }
    croak("Certain guest listing failed") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

sub check_guest_state {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be checked must be given") if (!$args{guest});

    my $_uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    my $_state = "";
    $_state = script_output("virsh $_uri list --all | grep $args{guest} | awk \'{print \$3\$4}\'", proceed_on_failure => 1); 
    return $_state; 
}

sub check_guest_persistence {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= ''; 
    croak("Guest to be checked must be given") if (!$args{guest});

    my $_uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    my $_persistence = "";
    $_persistence = script_output("virsh dominfo --domain $args{guest} | grep Persistent | awk \'{print \$2}\'", proceed_on_failure => 1);
    return $_persistence;
}

#needs test br0 and vnet
sub check_guest_network_config {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{xmldir} //= '/var/lib/libvirt/images';
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be checked must be given") if (!$args{guest});

    my $_guest_network_type = '';
    my $_guest_network_name = '';
    my $_guest_network_mode = '';
    my $_guest_network_ipaddr = '';
    my $_guest_network_macaddr = '';
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    foreach my $_guest (split(/ /, $args{guest})) {
        $guest_matrix{$_guest}{macaddr} = script_output("virsh $uri domiflist $_guest | grep -oE \"[[:xdigit:]]{2}(:[[:xdigit:]]{2}){5}\"", proceed_on_failure => 1);
        $guest_matrix{$_guest}{nettype} = script_output("xmlstarlet sel -T -t -v \"//devices/interface/\@type\" $args{xmldir}/$_guest.xml", proceed_on_failure => 1);
	if ($guest_matrix{$_guest}{nettype} eq 'network' or $guest_matrix{$_guest}{nettype} eq 'bridge') {
            $guest_matrix{$_guest}{netname} = script_output("xmlstarlet sel -T -t -v \"//devices/interface/source/\@$guest_matrix{$_guest}{nettype}\" $args{xmldir}/$_guest.xml", proceed_on_failure => 1);
	    if ($guest_matrix{$_guest}{nettype} eq 'network') {
                $guest_matrix{$_guest}{netmode} = (split(/_/, $guest_matrix{$_guest}{netname}))[1];
                $guest_matrix{$_guest}{netmode} = 'bridge' if ($guest_matrix{$_guest}{netname} eq 'br0');
	    }
	    if ($guest_matrix{$_guest}{nettype} eq 'bridge') {
		$guest_matrix{$_guest}{netmode} = script_output("xmlstarlet sel -T -t -v \"//devices/interface/model/\@type\" $args{xmldir}/$_guest.xml", proceed_on_failure => 1);
	    }
	}
        save_screenshot;
    }
}

#needs test br0 and vnet
sub check_guest_network_address {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be checked must be given") if (!$args{guest});

    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    foreach my $_guest (split(/ /, $args{guest})) {
        if ($guest_matrix{$_guest}{nettype} eq 'network') {
            if ($guest_matrix{$_guest}{netmode} eq 'host') {
                my $_br0_network = script_output("ip route show all | grep -v default | grep br0 | awk \'{print \$1}\'", die => 0, proceed_on_failure => 1);
		script_retry("nmap -sP $_br0_network | grep -i $guest_matrix{$_guest}{macaddr}", retry => 30, delay => 10, die => 0);
                $guest_matrix{$_guest}{ipaddr} = script_output("nmap -sP $_br0_network | grep -i $guest_matrix{$_guest}{macaddr} -B2 | grep -oE \"([0-9]{1,3}[\.]){3}[0-9]{1,3}\"", proceed_on_failure => 1);
            }
	    else {
                script_retry("virsh $uri net-dhcp-leases --network $guest_matrix{$_guest}{netname} | grep -ioE \"$guest_matrix{$_guest}{macaddr}.*([0-9]{1,3}[\.]){3}[0-9]{1,3}\"", retry => 30, delay => 10, die => 0);
                $guest_matrix{$_guest}{ipaddr} = script_output("virsh $uri net-dhcp-leases --network $guest_matrix{$_guest}{netname} | grep -i $guest_matrix{$_guest}{macaddr} | awk \'{print \$5}\'", proceed_on_failure => 1);
	        $guest_matrix{$_guest}{ipaddr} = (split(/\//, $guest_matrix{$_guest}{ipaddr}))[0];
		save_screenshot;
	    }
        }
        elsif ($guest_matrix{$_guest}{nettype} eq 'bridge') {
            if ($guest_matrix{$_guest}{netname} eq 'br0') {
		my $_br0_network = script_output("ip route show all | grep -v default | grep br0 | awk \'{print \$1}\'", die => 0, proceed_on_failure => 1);
		script_retry("nmap -sP $_br0_network | grep -i $guest_matrix{$_guest}{macaddr}", retry => 30, delay => 10, die => 0);
		$guest_matrix{$_guest}{ipaddr} = script_output("nmap -sP $_br0_network | grep -i $guest_matrix{$_guest}{macaddr} -B2 | grep -oE \"([0-9]{1,3}[\.]){3}[0-9]{1,3}\"", proceed_on_failure => 1);
            }
            else {
                script_retry("journalctl --no-pager -n 50 | grep -i \"DHCPACK.*$guest_matrix{$_guest}{netname}.*$guest_matrix{$_guest}{macaddr}\" | tail -1 | grep -oE \"([0-9]{1,3}[\.]){3}[0-9]{1,3}\"", retry => 30, delay => 10, die => 0);
                $guest_matrix{$_guest}{ipaddr} = script_output("journalctl --no-pager -n 50 | grep -i \"DHCPACK.*$guest_matrix{$_guest}{netname}.*$guest_matrix{$_guest}{macaddr}\" | tail -1 | grep -oE \"([0-9]{1,3}[\.]){3}[0-9]{1,3}\"", proceed_on_failure => 1);
            }
        }
        save_screenshot;
    }
}

=head2 create_guest_network

Create network, type of which is either network or bridge, to be used with guest.
In order to make this work consistent, data in hash structure guest_network_matrix
will be used for network creating, and the network name should begin with "vnet_"
followed by "nat", "route" or "host" if network type is "network", or be "br0" or 
"br123" if network type is "bridge". Main arguments are guest to be served, xmldir
in which network xml config will be stored and whether die (1) or not (0) if any 
error.This subroutine also calls construct_uri to determine the desired URI to be 
connected if the interested party is not localhost. Please refer to subroutine 
construct_uri for the arguments related.
=cut

#needs test br0 and vnet
sub create_guest_network {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{xmldir} //= '/var/lib/libvirt/images';
    $args{die} //= 0;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    $args{guest} = get_required_var('GUEST_UNDER_TEST') if (!$args{guest});

    my $_ret = 0;
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    my @_guest_network_configured = ();
    foreach my $_guest (split(/ /, $args{guest})) {
	next if grep(/^$guest_matrix{$_guest}{netname}$/, @_guest_network_configured);
	my $_temp = 1;
        my $_device = $guest_network_matrix{$guest_matrix{$_guest}{netmode}}{device};
        my $_ipaddr = $guest_network_matrix{$guest_matrix{$_guest}{netmode}}{ipaddr};
        my $_netmask = $guest_network_matrix{$guest_matrix{$_guest}{netmode}}{netmask};
        my $_masklen = $guest_network_matrix{$guest_matrix{$_guest}{netmode}}{masklen};
        my $_startaddr = $guest_network_matrix{$guest_matrix{$_guest}{netmode}}{startaddr};
        my $_endaddr = $guest_network_matrix{$guest_matrix{$_guest}{netmode}}{endaddr};
        if ($guest_matrix{$_guest}{nettype} eq 'network') {
            script_run("virsh $uri net-destroy $guest_matrix{$_guest}{netname}");
	    if ($guest_matrix{$_guest}{netname} ne 'default') {
	        script_run("virsh $uri net-undefine $guest_matrix{$_guest}{netname}");
		my $_forward_mode = $guest_matrix{$_guest}{netmode} eq 'host' ? 'bridge' : $guest_matrix{$_guest}{netmode};
                type_string("cat > $args{xmldir}/$guest_matrix{$_guest}{netname}.xml <<EOF
<network>
  <name>$guest_matrix{$_guest}{netname}</name>
  <bridge name=\"$_device\"/>
EOF
");
            if ($guest_matrix{$_guest}{netmode} eq 'nat') {
                type_string("cat >> $args{xmldir}/$guest_matrix{$_guest}{netname}.xml <<EOF
  <forward mode=\"$_forward_mode\">
    <nat>
      <port start=\"20232\" end=\"65535\"/>
    </nat>
  </forward>
EOF
");         
            }
	    else {
	        type_string("cat >> $args{xmldir}/$guest_matrix{$_guest}{netname}.xml <<EOF
  <forward mode=\"$_forward_mode\"/>
EOF
");
            }
                type_string("cat >> $args{xmldir}/$guest_matrix{$_guest}{netname}.xml <<EOF
  <ip address=\"$_ipaddr\" netmask=\"$_netmask\">
    <dhcp>
      <range start=\"$_startaddr\" end=\"$_endaddr\">
        <lease expiry=\"8\" unit=\"hours\"/>
      </range>
    </dhcp>
  </ip>
EOF
") if ($guest_matrix{$_guest}{netmode} ne 'host');
                type_string("cat >> $args{xmldir}/$guest_matrix{$_guest}{netname}.xml <<EOF
</network>
EOF
");
                $_temp = script_run("virsh $uri net-define $args{xmldir}/$guest_matrix{$_guest}{netname}.xml");
	    }
            else {
	        $_temp = 0;
            }		
            $_temp |= script_run("virsh $uri net-start $guest_matrix{$_guest}{netname}");
	    $_temp |= script_run("iptables --append FORWARD --in-interface $_device -j ACCEPT") if ($_device ne 'br0'); 
            if (script_run("virsh $uri net-list | grep $guest_matrix{$_guest}{netname}.*active") != 0) {
                record_info("Network $guest_matrix{$_guest}{netname} creation failed", script_output("virsh $uri list --all; virsh $uri net-dumpxml $guest_matrix{$_guest}{netname};ip route show all", proceed_on_failure => 1), result => 'fail');
		$_temp |= 1;
	    }
        }
	elsif ($guest_matrix{$_guest}{nettype} eq 'bridge') {
            my @_defintfs = split(/\n/, script_output("ip route show default | grep -i dhcp | awk \'{print \$5}\'", proceed_on_failure => 1));
            while (my ($_intfidx, $_defintf) =  each(@_defintfs)) {
                if ($_intfidx == 0) {
                    $_temp = script_run("iptables --table nat --append POSTROUTING --out-interface $_defintf -j MASQUERADE");
		}
		else {
                    $_temp |= script_run("iptables --table nat --append POSTROUTING --out-interface $_defintf -j MASQUERADE");
		}
            }
            if ($guest_matrix{$_guest}{netname} ne 'br0') {
	        if (script_run("ip route show all | grep $guest_matrix{$_guest}{netname}") != 0) {
                    script_run("ip -d addr del $_ipaddr/$_masklen dev $guest_matrix{$_guest}{netname}; ip -d link set dev $guest_matrix{$_guest}{netname} down; ip -d link del dev $guest_matrix{$_guest}{netname}");
                    $_temp |= script_retry("ip -d link add $guest_matrix{$_guest}{netname} type $guest_matrix{$_guest}{nettype}; ip -d addr flush dev $guest_matrix{$_guest}{netname}", retry => 3, die => 0);
		    $_temp |= script_retry("ip -d addr add $_ipaddr/$_masklen dev $guest_matrix{$_guest}{netname} && ip -d link set $guest_matrix{$_guest}{netname} up", retry => 3, die => 0);
                    $_temp |= script_run("iptables --append FORWARD --in-interface $guest_matrix{$_guest}{netname} -j ACCEPT");
		    if (!grep(/^$guest_matrix{$_guest}{netname}$/, split(/\n/, script_output("ip route show | grep -v default | awk \'{print \$3}\'", proceed_on_failure => 1)))) {
                        record_info("Network $guest_matrix{$_guest}{netname} creation failed", script_output("ip addr show all;ip route show all", proceed_on_failure => 1), result => 'fail');
		        $_temp |= 1;
		    }
	        }
                my $_dnsmasq_command = "/usr/sbin/dnsmasq --bind-dynamic --listen-address=$_ipaddr --dhcp-range=$_startaddr,$_endaddr,$_netmask,8h --interface=br123 --dhcp-authoritative --no-negcache --dhcp-option=option:router,$_ipaddr --log-queries --log-dhcp --dhcp-sequential-ip --dhcp-client-update --no-daemon";
                if (!script_output("ps ax | grep -i \"$_dnsmasq_command\" | grep -v grep | awk \'{print \$1}\'", proceed_on_failure => 1)) {
                    $_temp |= script_run("((nohup $_dnsmasq_command) &)");
                    if (!script_output("ps ax | grep -i \"$_dnsmasq_command\" | grep -v grep | awk \'{print \$1}\'", proceed_on_failure => 1)) {
                        record_info("DHCP service failed on $guest_matrix{$_guest}{netname}", "Command to start DHCP service is $_dnsmasq_command", result => 'fail');
                        $_temp |= 1;
		    }
                }
            }
	}
	push (@_guest_network_configured, $guest_matrix{$_guest}{netname});
	$_ret |= $_temp;
        save_screenshot;
    }
    record_info("Guest network configuration done", script_output("ip addr show;ip route show all; virsh $uri net-list --all;ps axu | grep dnsmasq", proceed_on_failure => 1));
    croak("Guest network creation failed for certain guest") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

=head2 test_guest_network

Test networking accessibility of guest. All guests should can be reached on host
and can reach outside from inside. The only guest that can be reached from outside
host is the one uses host bridge network. Main arguments are guest to be tested and 
whether die (1) or not (0) if any error. This subroutine also calls construct_uri 
to determine the desired URI to be connected if the interested party is not localhost. 
Please refer to subroutine construct_uri for the arguments related.
=cut

#needs to complete and thorough test  test $guest_matrix{$_guest}{netname} =~ /vnet_host/i)
sub test_guest_network {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{die} //= 0;
    croak("Guest to be tested must be given") if (!$args{guest});

    my $_ret = 0;
    foreach my $_guest (split(/ /, $args{guest})) {
        record_info("Test $_guest network");
        my $_temp = 1;
        $_temp = script_run("timeout --kill-after=3 --signal=9 20 ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_guest ping -c5 openqa.suse.de");
	$_temp |= script_run("timeout --kill-after=3 --signal=9 20 ping -c5 $guest_matrix{$_guest}{ipaddr}");
        $_temp |= 1 if (($guest_matrix{$_guest}{netname} eq 'br0' or $guest_matrix{$_guest}{netname} =~ /vnet_host/i) and check_port_state($guest_matrix{$_guest}{ipaddr}, 22, 3) == 0);
	$_ret |= $_temp;
        save_screenshot;
	record_info("Guest $_guest network connectivity failed", "Network connectivity testing failed for guest $_guest", result => 'fail') if ($_temp != 0);
    }
    croak("Network connectivity testing failed for certain guest") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

=head2 test_guest_storage

Test whether writing into guest disk is successful and return the result. Main 
arguments are guest to be tested and whether die (1) or not (0) if any error. 
This subroutine also calls construct_uri to determine the desired URI to be 
connected if the interested party is not localhost. Please refer to subroutine 
construct_uri for the arguments related.
=cut

#needs through test
sub test_guest_storage {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{die} //= 0;
    croak("Guest to be tested must be given") if (!$args{guest});

    my $_ret = 0;
    foreach my $_guest (split(/ /, $args{guest})) {
        record_info("Test $_guest storage");
        my $_temp = 1 ;
        $_temp = script_run("timeout --kill-after=3 --signal=9 20 ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root\@$_guest echo MIGRATION > /tmp/test_guest_storage && rm -f -r /tmp/test_guest_storage");
        $_ret |= $_temp;
        save_screenshot;
	record_info("Guest $_guest storage access failed", "Storage read/write testing failed for guest $_guest") if ($_temp != 0);
    }  
    croak("Storage accessbility testing failed for certain guest") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

#needs test xen
=head2 do_guest_administration

Perform basic administration on guest and return overall result. Main arguments
are guest to be manipulated and whether die (1) or not (0) if any error. This 
subroutine also calls construct_uri to determine the desired URI to be connected 
if the interested party is not localhost. Please refer to subroutine construct_uri 
for the arguments related.
=cut

sub do_guest_administration {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{die} //= 0;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest to be administered must be given") if (!$args{guest});

    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    my @_administration = ("virsh $uri destroy guest",
	                   "virsh $uri start guest", 
                           "virsh $uri list | grep guest.*running", 
                           "virsh $uri save guest /tmp/guest_administration.chckpnt", 
                           "virsh $uri restore /tmp/guest_administration.chckpnt", 
                           "virsh $uri dumpxml guest > /tmp/guest_administration.xml", 
			   "virsh $uri domxml-to-native --format native-format /tmp/guest_administration.xml > /tmp/guest_administration.cfg",
                           "virsh $uri shutdown guest",
                           "virsh $uri undefine guest --managed-save || virsh $uri undefine guest --keep-nvram --managed-save", 
                           "virsh $uri define --validate --file /tmp/guest_administration.xml", 
			   "virsh $uri list --all",
                           "virsh $uri start guest");

    my @_administration_xen = ("xl -vvv list | grep guest", 
	                       "xl -vvv save guest /tmp/guest_administration.chckpnt", 
			       "xl -vvv restore /tmp/guest_administration.chckpnt", 
			       "xl -vvv shutdown -F guest", 
			       "xl -vvv create /tmp/guest_administration.cfg");
    my $_native_format = "qemu-argv";
    if (is_xen_host) {
        push(@_administration, @_administration_xen);
	$_native_format = "xen-xl";
    }

    my $_ret = 0;
    foreach my $_guest (split(/ /, $args{guest})) {
        record_info("Do $_guest administration");
	my $_temp1 = 0;
	my @_guest_administration = ();
	foreach my $_operation (@_administration) {
	    my $_temp2 = 1;
            $_operation =~ s/guest/$_guest/g;
	    $_operation =~ s/native-format/$_native_format/g if ($_operation =~ /domxml-to-native/i);
	    push(@_guest_administration, $_operation);
	    $_temp2 = script_run($_operation);
	    $_temp1 |= $_temp2;
	    if ($_temp2 != 0) {
                save_screenshot;
	        record_info("Guest $_guest administration failed", "Administraton operation is $_operation", result => 'fail');
            }
	}
	record_info("Guest $_guest administration failed", "Administraton operation is:\n" . join("\n", @_guest_administration), result => 'fail') if ($_temp1 != 0);
	$_ret |= $_temp1;
    }
    croak("Administration failed on certain guest") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

=head2 virsh_migrate_manual_postcopy

Perform manual postcopy guest migration which needs an extra command to be executed
alongside main migration command. The return value of this extra command indicates
whether it is a successful manual postcopy guest migration. Main arguments are guest
to be migrated, main migraiton command and whether die (1) or not (0) if any error.
This subroutine also calls construct_uri to determine the desired URI to be connected
if the interested party is not localhost. Please refer to subroutine construct_uri 
for the arguments related. 
=cut

sub virsh_migrate_manual_postcopy {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{command} //= '';
    $args{die} //= 0;
    $args{driver} //= '';
    $args{transport} //= 'ssh';
    $args{user} //= '';
    $args{host} //= 'localhost';
    $args{port} //= '';
    $args{path} //= 'system';
    $args{extra} //= '';
    croak("Guest and command to be executed must be given") if (!$args{guest} or !$args{command});

    my $_ret = 1;
    $_ret = script_run("(nohup sleep 10 && $args{command} &)");
    my $uri = "--connect=" . $self->construct_uri(driver => $args{driver}, transport => $args{transport}, user => $args{user}, host => $args{host}, port => $args{port}, path => $args{path}, extra => $args{extra});
    if (script_retry("ps ax | grep migrate | grep -v grep", retry => 5, delay => 1, die => 0) == 0) {
        $_ret |= script_run("virsh $uri --debug=0 migrate-postcopy $args{guest}");
    }
    else {
	$_ret |= 1;
    }
    save_screenshot;
    croak("Guest $args{guest} manual postcopy migration failed") if ($_ret != 0 and $args{die} == 1);
    return $_ret;
}

=head2 create_junit_log

Create xml file to be parsed by parse_junit_log by using XML::LibXML. The data
source is a hash structure like test_result which stores test results and some
other side information like product and time. 
=cut

sub create_junit_log {
    my $self = shift;

    my $_start_time = $self->{start_run};
    my $_stop_time = $self->{stop_run};
    $self->{test_time} = strftime("\%H:\%M:\%S", gmtime($_stop_time - $_start_time));
    $self->{product_tested_on} = script_output("cat /etc/issue | grep -io -e \"SUSE.*\$(arch))\" -e \"openSUSE.*[0-9]\"", proceed_on_failure => 1);
    $self->{product_name} = ref($self);
    $self->{package_name} = ref($self);

    my %_result = %{\%test_result};
    my @_overall_status = ('pass', 'fail', 'skip', 'softfail', 'timeout', 'unknown');
    foreach my $_guest (keys %_result) {
        foreach my $_test (keys %{$_result{$_guest}}) {
            my $_status = $_result{$_guest}{$_test}{status};
            my $_statustag = first { $_status =~ /^$_/i } @_overall_status;
            $self->{$_statustag . "_num"} += 1;
        }
    }

    my $_count = 0;
    foreach my $_status (@_overall_status) {
        $self->{$_status . "_num"} = 0 if (!defined $self->{$_status . "_num"});
        $_count += $self->{$_status . "_num"};
    }

    my $_dom = XML::LibXML::Document->createDocument('1.0', 'UTF-8');
    my %_attribute = ();
    tie %_attribute, 'Tie::IxHash';
    %_attribute = (
        id => "0",
        error => "n/a",
        failures => $self->{fail_num},
        softfailures => $self->{softfail_num},
        name => $self->{product_name},
        skipped => $self->{skip_num},
        tests => $_count,
        time => $self->{test_time}
    );
    my @_attributes = (\%_attribute);
    my @_eles = ('testsuites');
    my ($_testsuites, ) = $self->create_junit_element(xmldoc => \$_dom, eles => \@_eles, attrs => \@_attributes);

    %_attribute = (
        id => "0",
        error => "n/a",
        failures => $self->{fail_num},
        softfailures => $self->{softfail_num},
        hostname => get_required_var('LOCAL_FQDN'),
        name => $self->{product_tested_on},
        package => $self->{package_name},
        skipped => $self->{skip_num},
        tests => $_count,
        time => $self->{test_time},
        timestamp => DateTime->now
    );
    @_attributes = (\%_attribute);
    @_eles = ('testsuite');
    my ($_testsuite, ) = $self->create_junit_element(xmldoc => \$_dom, parent => \$_testsuites, eles => \@_eles, attrs => \@_attributes);

    foreach my $_guest (keys %_result) {
        my %_test2junit_status = (passed => "success", failed => "failure", skipped => "skipped", softfailed => "softfail", timeout => "timeout_exceeded", unknown => "unknown");
        foreach my $_test (keys %{$_result{$_guest}}) {
                my $_test_status = $_result{$_guest}{$_test}{status};
                $_result{$_guest}{$_test}{status} = $_test2junit_status{first { /^$_test_status/i } (keys %_test2junit_status)};
                $_result{$_guest}{$_test}{guest} = $_guest;
                %_attribute = (
                    classname => $_result{$_guest}{$_test}{shortname},
                    name => $_test,
                    status => $_result{$_guest}{$_test}{status},
                    time => ($_result{$_guest}{$_test}{test_time} ? $_result{$_guest}{$_test}{test_time} : 'n/a')
                );
                @_attributes = (\%_attribute);
                @_eles = ('testcase');
                my ($_testcase, ) = $self->create_junit_element(xmldoc => \$_dom, parent => \$_testsuite, eles => \@_eles, attrs => \@_attributes);
                my @_eles = ('system-err', 'system-out', 'failure');
                my @_texts = (
                    ($_result{$_guest}{$_test}{error} ? $_result{$_guest}{$_test}{error} : 'n/a'),
                    ($_result{$_guest}{$_test}{output} ? $_result{$_guest}{$_test}{output} : 'n/a') . " time cost: $_result{$_guest}{$_test}{test_time}",
                    ($_result{$_guest}{$_test}{status} eq 'success' ? '' : "affected subject: $_result{$_guest}{$_test}{guest}")
                );
                $self->create_junit_element(xmldoc => \$_dom, parent => \$_testcase, eles => \@_eles, texts => \@_texts);
        }
    }

    $_dom->setDocumentElement($_testsuites);
    type_string("cat > /tmp/output.xml <<EOF\n" .
$_dom->toString(1) . "\nEOF\n");
    script_run("cat /tmp/output.xml && chmod 777 /tmp/output.xml");
    save_screenshot;
    parse_junit_log("/tmp/output.xml");

}

=head2 create_junit_element

Create xml elements that may have attributes, text or child and return array 
of created elements. Accepted arguments are references to xml doc object, parent 
of element to be created, array of elements to be created, array of attributes of 
elements and array of texts of elements. The order in which elements appear in 
array of elements to be created should be the same as those respective attributes 
and texts in their arrays.
=cut

sub create_junit_element {
    my ($self, %args) = @_;
    $args{xmldoc} //= "";
    $args{parent} //= "";
    $args{eles} //= ();
    $args{attrs} //= ();
    $args{texts} //= ();
    croak("JUnit xml object must be given") if (!$args{xmldoc});

    my $_index = 0;
    my @_eles = ();
    foreach my $_ele (@{$args{eles}}) {
       my $_element = ${$args{xmldoc}}->createElement($_ele);
       push(@_eles, $_element);
       if ($args{attrs}) {
           tie my %_attrs, 'Tie::IxHash';
           %_attrs = %{$args{attrs}->[$_index]};
           foreach my $_attr (keys %_attrs) {
               print "$_ele,$_attr,$_attrs{$_attr}\n";
               $_element->setAttribute("$_attr" => "$_attrs{$_attr}");
           }
       }
       $_element->appendText($args{texts}->[$_index]) if ($args{texts});
       ${$args{parent}}->appendChild($_element) if ($args{parent});
       $_index += 1;
    }
    return @_eles;
}

=head2 check_peer_test_run

Check progress of test run of peer job. This subroutine is called to verify whether
peer job is destined to fail or not and return its test run result. This is usually
called by paired job that is already in post_fail_hook to wait for peer job if it 
already failed or is about to fail, so the peer job can finish operations instead of
being cancelled due to paired job fails and terminates. This can be achieved simply
by barrier_wait on certain lock by both jobs if the peer fails as well. There are 
situations in which peer job needs to move pass current running subroutines like,
do_guest_migration or post_run_test, before entering into post_fail_hook, so it is
necessary to wait a period before having the final resolution. But if peer job still
remains any earlier steps, it is not meaningful to wait anymore because locks ahead.
=cut

sub check_peer_test_run {
    my $self = shift;

    my $_role = $self->get_parallel_role;
    my ($_peer_info, $_peer_vars) = $self->get_peer_info(role => $_role);
    my $_peer_test_run_result = '';
    diag("LATEST PEER TEST RUN PROGRESS: $_peer_vars->{'TEST_RUN_PROGRESS'} LATEST PEER TEST RUN RESULT: $_peer_vars->{'TEST_RUN_RESULT'}");
    my $_wait_start_time = time();
    while (defined $_peer_vars->{'TEST_RUN_PROGRESS'} and $_peer_vars->{'TEST_RUN_PROGRESS'} =~ /do_guest_migration|post_run_test/i) {
	last if ($_peer_vars->{'TEST_RUN_PROGRESS'} =~ /do_guest_migration/i and time() - $_wait_start_time > 1800);
        if ($_peer_vars->{'TEST_RUN_PROGRESS'} =~ /post_run_test/i and defined $_peer_vars->{'TEST_RUN_RESULT'}) {
            $_peer_test_run_result = $_peer_vars->{'TEST_RUN_RESULT'};
	    last;
	}
        ($_peer_info, $_peer_vars) = $self->get_peer_info(role => $_role);
        diag("LATEST PEER TEST RUN PROGRESS: $_peer_vars->{'TEST_RUN_PROGRESS'} LATEST PEER TEST RUN RESULT: $_peer_vars->{'TEST_RUN_RESULT'}");
    }
    $_peer_test_run_result = 'FAILED' if (defined $_peer_vars->{'TEST_RUN_PROGRESS'} and $_peer_vars->{'TEST_RUN_PROGRESS'} =~ /post_fail_hook/i);
    return $_peer_test_run_result;
}

=head2 AUTOLOAD

AUTOLOAD will be executed if called subroutine does not exist.
=cut

sub AUTOLOAD {
    my $self = shift;   

    $self->set_test_run_progress;
    my $type = ref($self) || croak "$self is not an object";
    my $field = $AUTOLOAD;
    $field =~ s/.*://;
    unless (exists $self->{$field}) {
        croak "$field does not exist in object/class $type";
    }
    if (@_) {
        return $self->{funcname} = shift;
    }
    else {
        return $self->{domain_name};
    }
}

=head2 post_fail_hook

Set TEST_RUN_RESULT to FAILED, create junit log and collect logs.
=cut

sub post_fail_hook {
    my $self = shift;

    $self->set_test_run_progress;
    set_var('TEST_RUN_RESULT', 'FAILED');
    bmwqemu::save_vars();
    bmwqemu::load_vars();

    $self->{"stop_run"} = time();    
    $self->create_junit_log;
    collect_host_and_guest_logs('', '', '', "_post_fail_hook");
}

1;
