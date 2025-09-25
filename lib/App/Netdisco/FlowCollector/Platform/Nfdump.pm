package App::Netdisco::FlowCollector::Platform::Nfdump;

=head1 NAME

App::Netdisco::FlowCollector::Platform::Nfdump

=head1 DESCRIPTION

Flow collector for nfdump-compatible flow files in nfsen directory structure

=cut

use strict;
use warnings;

use Dancer ':script';
use JSON::MaybeXS;
use IPC::Run3;
use File::Find;
use File::Spec;
use Moo;

=head1 PUBLIC METHODS

=over 4

=item B<collect_flows($label, $args)>

Retrieve flow entries from nfdump files. C<$label> is the configuration name.
C<$args> contains configuration parameters.

Returns a list of hashrefs in the format C<{ mac =E<gt> MACADDR, ip =E<gt> IPADDR }>.

=back

=cut

sub collect_flows {
    my ($self, $label, $args) = @_;

    debug "$label $$ collect_flows()";

    my $bin_path = $args->{bin_path} || '/usr/bin/nfdump';
    my $profiles_path = $args->{profiles_path};

    unless ($profiles_path) {
        warning "No profiles_path specified for $label";
        return ();
    }

    unless (-x $bin_path) {
        warning "nfdump binary not found or not executable: $bin_path";
        return ();
    }

    unless (-d $profiles_path) {
        warning "profiles_path does not exist: $profiles_path";
        return ();
    }

    # Find the latest flow files across all switches
    debug "Finding latest flow files in $profiles_path";
    my ($latest_timestamp, $latest_files) = $self->find_latest_flow_files($profiles_path);

    unless ($latest_timestamp && @$latest_files) {
        warning "No recent flow files found in $profiles_path";
        return ();
    }

    debug "Latest timestamp: $latest_timestamp, found " . scalar(@$latest_files) . " files";

    # Process the latest files
    my @flowentries;
    my @entries = $self->process_flow_files($bin_path, $profiles_path, $latest_timestamp, $latest_files);
    push @flowentries, @entries;

    debug "Total flow entries collected: " . scalar(@flowentries);
    return @flowentries;
}

sub find_latest_flow_files {
    my ($self, $profiles_path) = @_;

    my %switch_files;  # switch_name => [list of files with timestamps]
    my $live_path = File::Spec->catdir($profiles_path, 'live');

    unless (-d $live_path) {
        warning "Live directory does not exist: $live_path";
        return (undef, []);
    }

    # First, find all switches and their nfcapd files
    opendir(my $dh, $live_path) or return (undef, []);
    my @switches = grep { !/^\.\.?$/ && -d File::Spec->catdir($live_path, $_) } readdir($dh);
    closedir $dh;

    debug "Found " . scalar(@switches) . " switches: " . join(', ', @switches);

    # For each switch, find the latest nfcapd file
    foreach my $switch (@switches) {
        my $switch_path = File::Spec->catdir($live_path, $switch);
        my @files = $self->find_latest_nfcapd_files($switch_path);
        $switch_files{$switch} = \@files if @files;
    }

    # Find the globally latest timestamp
    my $latest_timestamp = undef;
    my @latest_files;

    foreach my $switch (keys %switch_files) {
        foreach my $file_info (@{$switch_files{$switch}}) {
            my $timestamp = $file_info->{timestamp};
            if (!$latest_timestamp || $timestamp gt $latest_timestamp) {
                $latest_timestamp = $timestamp;
                @latest_files = ($file_info);
            } elsif ($timestamp eq $latest_timestamp) {
                push @latest_files, $file_info;
            }
        }
    }

    # Filter to only include files with the latest timestamp
    my @final_files = grep { $_->{timestamp} eq $latest_timestamp } @latest_files;

    debug "Selected latest timestamp: $latest_timestamp with " . scalar(@final_files) . " files";
    return ($latest_timestamp, \@final_files);
}

sub find_latest_nfcapd_files {
    my ($self, $switch_path) = @_;

    my @files;

    # Traverse year/month/day directories
    return () unless -d $switch_path;

    opendir(my $year_dh, $switch_path) or return ();
    my @years = grep { /^\d{4}$/ && -d File::Spec->catdir($switch_path, $_) } readdir($year_dh);
    closedir $year_dh;

    foreach my $year (@years) {
        my $year_path = File::Spec->catdir($switch_path, $year);
        opendir(my $month_dh, $year_path) or next;
        my @months = grep { /^\d{2}$/ && -d File::Spec->catdir($year_path, $_) } readdir($month_dh);
        closedir $month_dh;

        foreach my $month (@months) {
            my $month_path = File::Spec->catdir($year_path, $month);
            opendir(my $day_dh, $month_path) or next;
            my @days = grep { /^\d{2}$/ && -d File::Spec->catdir($month_path, $_) } readdir($day_dh);
            closedir $day_dh;

            foreach my $day (@days) {
                my $day_path = File::Spec->catdir($month_path, $day);
                opendir(my $file_dh, $day_path) or next;
                my @nfcapd_files = grep { /^nfcapd\.\d+$/ && -f File::Spec->catfile($day_path, $_) } readdir($file_dh);
                closedir $file_dh;

                foreach my $file (@nfcapd_files) {
                    my $full_path = File::Spec->catfile($day_path, $file);
                    my @stat = stat($full_path);
                    my $mtime = $stat[9];

                    # Extract timestamp from filename
                    if ($file =~ /^nfcapd\.(\d+)$/) {
                        my $timestamp_str = $1;
                        # Convert to comparable format
                        if (length($timestamp_str) >= 12) {
                            # Format: YYYYMMDDHHMM
                            my $year = substr($timestamp_str, 0, 4);
                            my $month = substr($timestamp_str, 4, 2);
                            my $day = substr($timestamp_str, 6, 2);
                            my $hour = substr($timestamp_str, 8, 2);
                            my $minute = substr($timestamp_str, 10, 2);

                            my $timestamp = sprintf("%04d-%02d-%02d %02d:%02d", $year, $month, $day, $hour, $minute);

                            push @files, {
                                path => $full_path,
                                timestamp => $timestamp,
                                filename => $file,
                                relative_path => "$year/$month/$day/$file"
                            };
                        }
                    }
                }
            }
        }
    }

    # Sort by timestamp and return the latest
    @files = sort { $b->{timestamp} cmp $a->{timestamp} } @files;
    return @files ? ($files[0]) : ();  # Return only the latest file per switch
}

sub process_flow_files {
    my ($self, $bin_path, $profiles_path, $timestamp, $file_list) = @_;

    # Extract switch names and relative paths
    my @switches;
    my $relative_path;

    foreach my $file_info (@$file_list) {
        # Extract switch name from path: profiles-data/live/SWITCHNAME/...
        my ($vol, $dirs, $file) = File::Spec->splitpath($file_info->{path});
        my @path_parts = File::Spec->splitdir($dirs);

        # Find the switch name (directory after 'live')
        for (my $i = 0; $i < @path_parts; $i++) {
            if ($path_parts[$i] eq 'live' && $i + 1 < @path_parts) {
                push @switches, $path_parts[$i + 1];
                $relative_path = $file_info->{relative_path};
                last;
            }
        }
    }

    return () unless @switches && $relative_path;

    debug "Processing flow files for switches: " . join(', ', @switches) . " with relative path: $relative_path";

    # Create the -M argument with colon-separated switch names
    my $switch_list = join(':', @switches);
    my $live_path = File::Spec->catdir($profiles_path, 'live');

    # Run nfdump with -M and -T -r
    my $cmd = [
        $bin_path,
        '-M', $live_path . '/' . $switch_list,
        '-T',
        '-r', $relative_path,
        '-o', 'json',
        'flags S and not flags AFRPU'
    ];

    debug "Running command: " . join(' ', @$cmd);

    my ($stdout, $stderr);
    eval {
        run3($cmd, undef, \$stdout, \$stderr);
    };

    if ($@) {
        warning "Error running nfdump: $@";
        return ();
    }

    if ($stderr && $stderr !~ /Processed records|Summary|SysID|nfdump:/) {
        warning "nfdump stderr: $stderr";
    }

    # Handle empty output
    unless ($stdout && length($stdout) > 0) {
        warning "No output from nfdump command";
        return ();
    }

    debug "nfdump output length: " . length($stdout);

    # Parse JSON output
    my $json = JSON::MaybeXS->new;
    my $data;
    eval {
        $data = $json->decode($stdout);
    };

    if ($@) {
        warning "Error parsing JSON from nfdump output: $@";
        warning "JSON output snippet: " . substr($stdout, 0, 500) . "...";
        return ();
    }

    # Handle case where JSON is not an array
    unless (ref($data) eq 'ARRAY') {
        warning "nfdump JSON output is not an array";
        return ();
    }

    debug "Parsed " . scalar(@$data) . " flow records";

    # Collect valid MAC/IP pairs (only input or output pairs, not mixed)
    my %unique_pairs;

    # Process each flow record to extract valid MAC/IP pairs
    foreach my $record (@$data) {
        next unless ref($record) eq 'HASH';
        next unless $record->{type} eq 'FLOW';

        # Only use input pairs (in_src_mac with src4_addr)
        if ($record->{src4_addr} && $record->{in_src_mac} && 
            $record->{src4_addr} ne '0.0.0.0' && 
            $record->{in_src_mac} ne '00:00:00:00:00:00' &&
            $record->{in_src_mac} !~ /^ff:ff:ff:ff:ff:ff/i) {

            # Skip obviously invalid IPs
            next if $record->{src4_addr} =~ /^127\./;  # Loopback
            next if $record->{src4_addr} =~ /^224\./;  # Multicast
            next if $record->{src4_addr} =~ /^255\./;  # Broadcast

            my $key = $record->{in_src_mac} . '|' . $record->{src4_addr};
            $unique_pairs{$key} = {
                mac => $record->{in_src_mac},
                ip => $record->{src4_addr},
            };
        }

    }

    debug "Extracted " . scalar(keys %unique_pairs) . " valid MAC/IP pairs";

    # Convert hash to array of hashrefs
    my @flowentries;
    foreach my $key (keys %unique_pairs) {
        push @flowentries, $unique_pairs{$key};
    }

    return @flowentries;
}

1;
