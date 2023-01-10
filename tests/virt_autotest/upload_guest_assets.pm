# GUEST MIGRATION TEST SOURCE MODULE
#
# Copyright 2023 SUSE LLC
# SPDX-License-Identifier: FSFAP
#
# Maintainer: Wayne Chen <wchen@suse.com>, qe-virt <qe-virt@suse.de>
package upload_guest_assets;

use base "parallel_test_base";
use strict;
use warnings;
use POSIX 'strftime';
use File::Basename;
use testapi;
use Data::Dumper;
use XML::Writer;
use IO::File;
use Utils::Architectures;
use upload_system_log;
use virt_autotest::utils qw(is_kvm_host is_xen_host check_host_health check_guest_health is_fv_guest is_pv_guest);
use virt_utils qw(collect_host_and_guest_logs cleanup_host_and_guest_logs generate_guest_asset_name get_guest_disk_name_from_guest_xml compress_single_qcow2_disk); 

sub run_test {
    my $self = shift;

    my $guest = join(" ", split(/,/, get_required_var('GUEST_LIST')));
    $self->upload_guest_assets(guest => $guest); 
}

sub upload_guest_assets {
    my ($self, %args) = @_;
    $args{guest} //= '';
    $args{dir} //= '/var/lib/libvirt/images_backup_kvm';
    die "Guest to be uploaded must be given" if (!$args{guest});

    foreach my $guest (split(/ /, $args{guest})) {
        # Generate upload guest asset name
        my $guest_upload_asset_name = generate_guest_asset_name($guest);
        # Upload guest xml
        my $guest_xml_name = $guest_upload_asset_name . '.xml';
        # TODO: on host sle11sp4, the guest name has random string at the end of GUEST_PATTERN
        # eg sles-15-sp1-64-fv-def-net-77b-a43, so need to add special handle here for guest name
        assert_script_run("virsh dumpxml $guest > /tmp/$guest_xml_name");
        upload_asset("/tmp/$guest_xml_name", 1, 1);
        assert_script_run("rm /tmp/$guest_xml_name");
        record_info('Guest xml upload done', "Guest $guest xml uploaded as $guest_xml_name.");
        # Upload guest disk
        # Uploaded guest disk name is different from original disk name in guest xml.
        # This is to differentiate guest disk on different host, hypervisor and product build.
        # Need to recover the disk name when recovering guests from openqa assets.
        my $guest_disk_name_real = get_guest_disk_name_from_guest_xml($guest);
        my $guest_disk_name_to_upload = $guest_upload_asset_name . '.disk';
        if ($guest_disk_name_real =~ /qcow2/) {
            # Disk compression only for qcow2
            compress_single_qcow2_disk($guest_disk_name_real, $guest_disk_name_to_upload);
        }
        else {
            # Link real disk to uploaded disk name to be with needed name after upload
            assert_script_run("ln -s $guest_disk_name_real $guest_disk_name_to_upload");
        }
	#upload_asset("$guest_disk_name_to_upload", 1, 0);
	#assert_script_run("rm $guest_disk_name_to_upload");
	#record_info('Guest disk upload done', "Guest $guest disk uploaded as $guest_disk_name_to_upload.");
    }
}

1;
