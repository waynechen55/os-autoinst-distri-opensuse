# VIRSH TEST MODULE BASE PACKAGE  
#
# Copyright © 2019 SUSE LLC
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved. This file is offered as-is,
# without any warranty.

# Summary: This is the base package for virsh test modules, for example,
# tests/virtualization/xen/hotplugging.pm
# tests/virt_autotest/virsh_internal_snapshot.pm
# tests/virt_autotest/virsh_external_snapshot.pm
# and etc.
# Maintainer: Wayne Chen <wchen@suse.com>

package virsh_autotest_base;

use base "consoletest";
use strict;
use warnings;
use POSIX 'strftime';
use File::Basename;
use Data::Dumper;
use XML::Writer;
use IO::File;
use testapi;
use utils;
use virt_utils;
use xen;

sub run_test {
    die('Please overwrite this subroutine in children modules to run actual tests.');
}

sub run {
    my ($self)    = @_;
    my $start_run = time();
    $self->run_test;
    my $stop_run  = time();
    return unless get_var("VIRT_AUTOTEST");
    my $runtime  = strftime("\%H:\%M:\%S", gmtime($stop_run - $start_run));;
    $self->junit_log_provision('PASSED', $runtime);
}

sub junit_log_provision {
    my ($self, $status, $runtime) = @_;
    my %data;
    my $tc_result = $self->analyzeResult($status, $runtime);
    $self->junit_log_params_provision($tc_result, ref($self), ref($self));
    $data{"pass_nums"}             = $self->{"pass_nums"};
    $data{"fail_nums"}             = $self->{"fail_nums"};    
    $data{"skip_nums"}             = $self->{"skip_nums"};
    @{$data{"success_guest_list"}} = @{$self->{"success_guest_list"}};
    $data{"product_name"}          = $self->{"product_name"};
    $data{"product_tested_on"}     = $self->{"product_tested_on"};
    $data{"package_name"}          = $self->{"package_name"};    
    print Dumper(\%data);
    my $xml_result = generateXML_from_data($tc_result, \%data);
    script_run "echo \'$xml_result\' > /tmp/output.xml";
    save_screenshot;
    parse_junit_log("/tmp/output.xml");
}

sub junit_log_params_provision {
    my ($self, $data, $product_name, $package_name) = @_;
    my %my_hash   = %$data;
    my $pass_nums = 0;
    my $fail_nums = 0;
    my $skip_nums = 0;

    $self->{"product_tested_on"} = script_output("cat /etc/issue | grep -io \"SUSE.*\$(arch))\"");
    $self->{"product_name"}      = $product_name;
    $self->{"package_name"}      = $package_name;

    foreach my $item (keys(%my_hash)) {
        if ($my_hash{$item}->{status} =~ m/PASSED/) {
            $pass_nums += 1;
            push @{$self->{success_guest_list}}, $item;
        }
        elsif ($my_hash{$item}->{status} =~ m/SKIPPED/ && $item =~ m/iso/) {
            $skip_nums += 1;
        }
        else {
            $fail_nums += 1;
        }
    }

    $self->{"pass_nums"} = $pass_nums;
    $self->{"skip_nums"} = $skip_nums;
    $self->{"fail_nums"} = $fail_nums;

    diag '@{$self->{success_guest_list}} content is: ' . Dumper(@{$self->{success_guest_list}});
}

sub analyzeResult {
    my ($self, $test_status, $test_time) = @_;
    my $result;
    foreach (keys %xen::guests) {
        $result->{$_}{status} = $test_status;
        $result->{$_}{time}   = $test_time;
    }
    return $result;
}

sub post_fail_hook {
    my ($self) = shift;
    $self->SUPER::post_fail_hook;
    $self->junit_log_provision('FAILED', 'inf');
}

1;
