#!/usr/bin/perl

#######################################################################
use File::Tail;
#######################################################################
sub unblock();
sub block($);
#######################################################################
# Global Persistent Variable #
# Use Arista ACL row numbers greater than this
my $ndel = 130;
# Use Arista ACL row numbers less than this
my $ndele = 1000;
# Timeout in seconds for inactive deny rules not already removed
my $expts = 300;
# Used to track interations of block loop before moving to unblock
my $c = 0;
#######################################################################
# Curl commands use .netrc file for auth
#######################################################################
my %recentb;
my $rb = \%recentb;
my %availnum;
my $avail = \%availnum;
my %timepax;
my $tpx = \%timepax;
#######################################################################
sub main();
sub block($);
#######################################################################
sub main () {
  my $ntoplog = '/var/log/ntopng.log';
# Create hash of row numbers
  for($i=++$ndel;$i < $ndele; $i++) {
    $avail->{$i} = 1;
  }
  my $ctime = time;
# Delete row numbers from hash created that are unavailable 
  my @nums = `/home/ntopng/arista-get.sh`;
  foreach (@nums) {
    next if $_ !~ /host/;
    next if $_ !~ /deny/;
    $_ =~ /(\d+)\s+deny/;
    next if $1 < $ndel or $1 >= $ndele;
    delete $avail->{$1};
# If rule has packets, populate the timeout tracking hash
    if($_ =~ /(\d+)\s+deny.*match\s+(\d+)\s+packets/) {
      $tpx->{$1} = $2 . '^'. $ctime;
    }
  }
  block($ntoplog);
}
#######################################################################
sub unblock() {
  my %unblock = ();
  my %keep;
  my @denies = `/home/ntopng/arista-get.sh`;
  my $logfile = '/tmp/elephant.log';
  my $elogfile = '/tmp/elephant-block-errors.log';
  # clean up stale info
  my $ctime = time;
  foreach my $key(keys %{$rb}) {
    if ($ctime - $rb->{$key} > 900) {
      delete $rb->{$key};
    }
  }
  open(WE,">>$logfile");
  open(WE2,">>$elogfile");
  foreach (@denies) {
    chomp $_;
    next if $_ !~ /host/;
    next if $_ !~ /deny/;
    my($row,$host,$host2,$packets,$time);
    my @ts;
    my $sec;
    if($_ =~ /match/) {
      if($_ =~ /(\d+)\s+deny\s+ip\s+host\s+([^\s]+)\s+host\s+([^\s]+)\s+\[match\s+(\d+)\s+packets\,([\w\d\s\,]+)?\s+([^\s]+)\s+ago\]/) {
        ($row,$host1,$host2,$packets,$time) = ($1,$2,$3,$4,$6);
        next if $row < $ndel or $row >= $ndele;
        @ts=split(':',$time);
        $sec=$ts[2];
        $sec+=$ts[1]*60;
        $sec+=$ts[0]*3600;
        my $days = $5 if $5;
        if($days and $days =~ /(\d+)\s+day/) {
          $sec+=($1 * 86400);
        }
        if(($sec or $sec eq '0') and $sec < $expts) {
          if(!$tpx->{$row}) {
             print WE2 "missing $tpx->{$row} for $row and trying to create it with $ctime and $packets\n";
             $tpx->{$row} = $packets . '^' . $ctime - 1;
          }
          my @thput = split('\^',$tpx->{$row});
          my $totpx = $packets - $thput[0];
          my $et = $ctime - $thput[1];
          if(($totpx / $et) < 25) {
            $avail->{$row} = 1  if !$keep{$row};
            $unblock{$row} = 'no ' . $_ if !$keep{$row};
          } else {
            $keep{$row} = 1;
            delete $unblock{$row} if $unblock{$row};
            delete $avail->{$row};
            $tpx->{$row} = $packets . '^' . $ctime;
          }
        } else {
          $avail->{$row} = 1  if !$keep{$row};
          $unblock{$row} = 'no ' . $_ if !$keep{$row};
        }
      } elsif($_ =~ /(\d+)\s+deny\s+ip\s+any\s+host\s+([^\s]+)\s+\[match\s+(\d+)\s+packets\,([\w\d\s\,]+)?\s+([^\s]+)\s+ago\]/) {
        ($row,$host1,$host2,$packets,$time) = ($1,'any',$2,$3,$5);
        next if $row < $ndel or $row >= $ndele;
        @ts=split(':',$time);
        $sec=$ts[2];
        $sec+=$ts[1]*60;
        $sec+=$ts[0]*3600;
        my $days = $4 if $4;
        if($days and $days =~ /(\d+)\s+day/) {
          $sec+=($1 * 86400);
        }
        if(($sec or $sec eq '0') and $sec < $expts) {
          if(!$tpx->{$row}) {
             $tpx->{$row} = $packets . '^' . $ctime - 1;
          }
          my @thput = split('\^',$tpx->{$row});
          my $totpx = $packets - $thput[0];
          my $et = $ctime - $thput[1];
          if(($totpx / $et) < 25) {
            $avail->{$row} = 1  if !$keep{$row};
            $unblock{$row} = 'no ' . $_ if !$keep{$row};
          } else {
            $keep{$row} = 1;
            delete $unblock{$row} if $unblock{$row};
            delete $avail->{$row};
            $tpx->{$row} = $packets . '^' . $ctime;
          }
        } else {
          $avail->{$row} = 1  if !$keep{$row};
          $unblock{$row}  = 'no ' . $_ if !$keep{$row};
        }
      } elsif($_ =~ /(\d+)\s+deny\s+ip\s+host\s+([^\s]+)\s+any\s+\[match\s+(\d+)\s+packets\,([\w\d\s\,]+)?\s+([^\s]+)\s+ago\]/) {
        ($row,$host1,$host2,$packets,$time) = ($1,$2,'any',$3,$5);
        next if $row < $ndel or $row >= $ndele;
        @ts=split(':',$time);
        $sec=$ts[2];
        $sec+=$ts[1]*60;
        $sec+=$ts[0]*3600;
        my $days = $4 if $4;
        if($days and $days =~ /(\d+)\s+day/) {
          $sec+=($1 * 86400);
        }
        if(($sec or $sec eq '0')  and $sec < $expts) {
          if(!$tpx->{$row}) {
             $tpx->{$row} = $packets . '^' . $ctime - 1;
          }
          my @thput = split('\^',$tpx->{$row});
          my $totpx = $packets - $thput[0];
          my $et = $ctime - $thput[1];
          if(($totpx / $et) < 25) {
            $avail->{$row} = 1  if !$keep{$row};
            $unblock{$row} = 'no ' . $_ if !$keep{$row};
          } else {
            $keep{$row} = 1;
            delete $unblock{$row} if $unblock{$row};
            delete $avail->{$row};
            $tpx->{$row} = $packets . '^' . $ctime;
         }
        } else {
          $unblock{$row} = 'no ' . $_ if !$keep{$row};
          $avail->{$row} = 1  if !$keep{$row};
        }
      }
    } elsif($_ !~ /match/) {
      if ($_ =~ /^\s+(\d+)\s+deny\s+ip\s+host\s+([^\s]+)\s+host\s+([^\s]+)$/) {
        $row = $1;
        $host1 = $2;
        $host2 = $3;
        next if $row < $ndel or $row >= $ndele;
        $unblock{$row} = 'no ' . $_;
        $avail->{$row} = 1;
      } elsif($_ =~ /^\s+(\d+)\s+deny\s+ip\s+any\s+host\s+([^\s]+)$/) {
        $row = $1;
        $host1 = 'any';
        $host2 = $2;
        next if $row < $ndel or $row >= $ndele;
        $unblock{$row} = 'no ' . $_;
        $avail->{$row} = 1;
      } elsif($_ =~ /^\s+(\d+)\s+deny\s+ip\s+host\s+([^\s]+)\s+any$/) {
        $row = $1;
        $host1 = $2;
        $host2 = 'any';
        next if $row < $ndel or $row >= $ndele;
        $unblock{$row} = 'no ' . $_;
        $avail->{$row} = 1;
      }
    } else {
      print WE2 "didn't match $_\n";
    }
  }
  my $basecmd = '/usr/bin/curl -s -k -n -H "Content-Type: application/json" -X POST -d '."'". '{"jsonrpc":"2.0", "method":"runCmds", "params":{ "version":1, "cmds":["enable", "configure", "ip access-list YourAccessListName" ';
  foreach my $key(sort keys %unblock) {
    $basecmd .= ',"' . "no $key" .'"';
    print WE $unblock{$key} . "\n";
    delete $tpx->{$key};
  }
  $basecmd .= '], "format":"json"}, "id":""}'."'". ' https://YourAristaSwitch/command-api';
  close(WE);
  close(WE2);
# Run unblock if there are deny lines to unblock
  `$basecmd` if scalar keys %unblock > 0;
  return;
}
#######################################################################
# Where all the action happens
#######################################################################
sub block($) {
  my ($ntoplog) = shift;
  my $file=File::Tail->new(name => $ntoplog, maxinterval => 1, adjustafter => 5, tail => 1, reset_tail => 1, ignore_nonexistant => 1);
# Log what we are doing
  my $logfile = '/tmp/elephant.log';
  my $elogfile = '/tmp/elephant-block-errors.log';
  my $ctime = time;
  while (defined($line=$file->read)) {
    my ($b1,$b2);
    next if $line !~ /\[Elephant Flow\]/;
    open(WE,">>$logfile");
    open(WE2,">>$elogfile");
    $line =~ /\[Elephant Flow\]\[Flow\]\[([^\:\s]+)(\:\d+)?\s+([^\:\s]+)(\:\d+)?\]/;
    print WE2 "Missing elephant flow data\n$line\n" if !$1 or !$3;
    my $interv1 = $1 . '^'. $3;
    my $interv2 = $3 . '^'. $1;
    my $dval = time;
    next if $rb->{$interv1} or $rb->{$interv2};
    $rb->{$interv1} = $dval;
    $rb->{$interv2} = $dval;
    foreach my $key(sort{$a <=> $b} keys %{$avail}) {
      if(!$b1) { $b1 = $key; } else { $b2 = $key; last; }
    }
    delete ($avail->{$b1});
    delete ($avail->{$b2});
    $tpx->{$b1} = '1' . '^'  . $ctime;
    $tpx->{$b2} = '1' . '^'  . $ctime;
    my $basecmd = '/usr/bin/curl -s -k -n -H "Content-Type: application/json" -X POST -d '."'". '{"jsonrpc":"2.0", "method":"runCmds", "params":{ "version":1, "cmds":["enable", "configure", "ip access-list YourAccessListName" ,';
    $basecmd .= '"' . "$b1 deny ip host $1 host $3" . '","' . "$b2 deny ip host $3 host $1" . '"';
    $basecmd .= '], "format":"json"}, "id":""}'."'". ' https://YourAristaSwitch/command-api';
    print WE $b1 . ' deny ip host ' . $1 . ' host ' . $3 . "\n";
    print WE $b2 . ' deny ip host ' . $3 . ' host ' . $1 . "\n";
    close(WE);
    close(WE2);
    $c++;
# If iteration track greater than 3 run unblock routine
# You may want to adjust this depending on how fast elephant
# Flows are detected in your environment
    if($c > 3) {
      $c = 0;
      unblock();
    }
# Run the current blocks if any
    `$basecmd`;
  }
}
#######################################################################
main();
