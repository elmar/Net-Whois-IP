package Net::Whois::IP;


########################################
#$Id: IP.pm,v 1.3 2003/02/14 16:19:25 ben Exp $
########################################

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use IO::Socket;
require Exporter;
use Carp;

@ISA = qw(Exporter AutoLoader);
@EXPORT = qw(
	     whoisip_query
	    );
$VERSION = '0.02';

my %whois_servers = ("RIPE"=>"whois.ripe.net","APNIC"=>"whois.apnic.net","KRNIC"=>"whois.krnic.net","LACNIC"=>"whois.lacnic.net","ARIN"=>"whois.arin.net");

######################################
# Public Subs
######################################

sub whoisip_query {
    my($ip) = @_;
    if($ip !~ /\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}/) {
	croak("$ip is not a valid ip address");
    }
#    DO_DEBUG("looking up $ip");
    my($response) = _do_lookup($ip,"ARIN");
    return($response);
}


######################################
#Private Subs
######################################
sub _do_lookup {
    my($ip,$registrar) = @_;
#    DO_DEBUG("do lookup $ip at $registrar");
#let's not beat up on them too much
    my $extraflag = "1";
    my $whois_response;
    my $whois_response_hash;
    LOOP: while($extraflag ne "") {
#	    DO_DEBUG("Entering loop $extraflag");
	my $lookup_host = $whois_servers{$registrar};
	($whois_response,$whois_response_hash) = _do_query($lookup_host,$ip);
	my($new_ip,$new_registrar) = _do_processing($whois_response,$registrar,$ip,$whois_response_hash);
	if(($new_ip ne $ip) || ($new_registrar ne $registrar) ) {
#	    DO_DEBUG("ip was $ip -- new ip is $new_ip");
#	    DO_DEBUG("registrar was $registrar -- new registrar is $new_registrar");
	    $ip = $new_ip;
	    $registrar = $new_registrar;
	    $extraflag++;
	    next LOOP;
	}else{
	    $extraflag="";
	    last LOOP;
	}
    }


    if(%{$whois_response_hash}) {
	foreach (sort keys(%{$whois_response_hash}) ) {
#	    DO_DEBUG("sub -- $_ -- $whois_response_hash->{$_}");
	}
        return($whois_response_hash);
    }else{
        return($whois_response);
    }
}

sub _do_query{
    my($registrar,$ip) = @_;
    my $sock = _get_connect($registrar);
    print $sock "$ip\n";
    my @response = <$sock>;
    close($sock);
#Prevent killing the whois.arin.net --- they will disable an ip if greater than 40 queries per minute
    sleep(1);
    my %hash_response;
    foreach my $line (@response) {
	if($line =~ /^(.+):\s+(.+)$/) {
	    $hash_response{$1} = $2;
	}
    }
    return(\@response,\%hash_response);
}

sub _do_processing {
    my($response,$registrar,$ip,$hash_response) = @_;
    LOOP:foreach (@{$response}) {
  	if (/Contact information can be found in the (\S+)\s+database/) {
	    $registrar = $1;
#	    DO_DEBUG("Contact -- registrar = $registrar -- trying again");
	    last LOOP;
	}elsif((/OrgID:\s+(\S+)/) || (/source:\s+(\S+)/) && (!defined($hash_response->{'TechPhone'})) ) {
	    my $val = $1;	
#	    DO_DEBUG("Orgname match: value was $val if not RIPE,APNIC,KRNIC,or LACNIC.. will skip");
	    if($val =~ /^RIPE|APNIC|KRNIC|LACNIC$/) {
		$registrar = $val;
#		DO_DEBUG(" RIPE - APNIC match --> $registrar --> trying again ");
		last LOOP;
	    }
	}elsif(/Parent:\s+(\S+)/) {
	    if(($1 ne "") && (!defined($hash_response->{'TechPhone'}))){
		$ip = $1;
#		DO_DEBUG(" Parent match ip will be $ip --> trying again");
		last LOOP;
	    }
	}elsif((/.+\((.+)\).+$/) && ($_ !~ /.+\:.+/)) {
	    $ip = $1;
	    $registrar = "ARIN";
#	    DO_DEBUG("parens match $ip $registrar --> trying again");
	}else{
	    $ip = $ip;
	    $registrar = $registrar;
	}
    }
    return($ip,$registrar);
}
	    
  

sub _get_connect {
    my($whois_registrar) = @_;
    my $sock = IO::Socket::INET->new(
				     PeerAddr=>$whois_registrar,
				     PeerPort=>'43',
				     Timeout=>'60',
				    );
    unless($sock) {
	carp("Failed to Connect to $whois_registrar at port print -$@");
	sleep(5);
	$sock = IO::Socket::INET->new(
				      PeerAddr=>$whois_registrar,
				      PeerPort=>'43',
				      Timeout=>'60',
				     );
	unless($sock) {
	    croak("Failed to Connect to $whois_registrar at port 43 for the second time - $@");
	}
    }
    return($sock);
}

sub DO_DEBUG {
    my(@stuff) = @_;
    my $date = scalar localtime;
    open(DEBUG,">>/tmp/Net.WhoisIP.log") or warn "Unable to open /tmp/$0.log";
    foreach my $item ( @stuff) {
        print DEBUG "$date|$item|\n";
    }
    close(DEBUG);
}


1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Net::Whois::IP - Perl extension for looking up the whois information for ip addresses

=head1 SYNOPSIS

  use Net::Whois::IP qw(whoisip_query);

  my $ip = "192.168.1.1";
#Response will be a reference to a hash containing all information
#provided by the whois registrar
  my $response = whoisip_query($ip);


=head1 DESCRIPTION

Perl module to allow whois lookup of ip addresses.  This module should recursively query the various
whois providers until it gets the more detailed information including either OrgName or CustName

=head1 AUTHOR

Ben Schmitz -- bschmitz@orbitz.com

Thanks to Orbitz for allowing the community access to this work

Please email me any suggestions, complaints, etc.

=head1 SEE ALSO

perl(1).
Net::Whois

=cut
