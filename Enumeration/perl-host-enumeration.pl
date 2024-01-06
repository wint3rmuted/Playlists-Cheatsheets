#!/usr/bin/perl

use strict;
use warnings;
use Sys::Info;

# Create a Sys::Info object
my $info = Sys::Info->new;

# Get basic system information
my $os       = $info->os;
my $computer = $info->device('Computer');

# Display system information
print "System Information:\n";
print "-------------------\n";
print "Computer Name: " . $computer->host . "\n";
print "Operating System: " . $os->os() . "\n";
print "Version: " . $os->version() . "\n";
print "Architecture: " . $os->bitness() . "-bit\n";
print "\n";

# Get processor information
my $cpu = $info->device('CPU');

# Display processor information
print "Processor Information:\n";
print "----------------------\n";
print "Processor: " . $cpu->identify . "\n";
print "Cores: " . $cpu->count . "\n";
print "Frequency: " . $cpu->frequency . " MHz\n";
print "\n";

# Get memory (RAM) information
my $memory = $info->device('Memory');

# Display memory information
print "Memory Information:\n";
print "-------------------\n";
print "Total Memory: " . $memory->total . " MB\n";
print "\n";

# Get disk information
my $fs = $info->device('FileSystem');

# Display disk information
print "Disk Information:\n";
print "-----------------\n";

foreach my $partition ($fs->partitions) {
    print "Drive " . $partition->mount_point . ": " . $partition->total . " MB Free Space\n";
}
